#define PACKAGE 1
#define PACKAGE_VERSION 1

#include<cstdlib>
#include<cstdint>
#include<cstdio>
#include<cstring>
#include<cerrno>

#include <string>
#include <vector>

#include <bfd.h>

#include "../include/loader.h"


using namespace std;

//使用文件名打开文件
//参数1：文件名
static bfd* open_bfd(string& fname)
{
    static int bfd_inited = 0;
    bfd* bfd_h;

    if (!bfd_inited)
    {
        bfd_init();
        bfd_inited = 1;
    }

    bfd_h = NULL;
    //open()的真正调用
    bfd_h = bfd_openr(fname.c_str(), NULL);
    if (!bfd_h)
    {
        fprintf(stderr, "failed to open binary '%s' (%s)\n", 
                fname.c_str(), bfd_errmsg(bfd_get_error()));
        return NULL;
    }

    //检查是否是可执行文件
    if (!bfd_check_format(bfd_h, bfd_object))
    {
        fprintf(stderr, "file '%s' does not look like an executable (%s)", 
                fname.c_str(), bfd_errmsg(bfd_get_error()));
        return NULL;
    }

    //清除bfd_error
    bfd_set_error(bfd_error_no_error);

    //检查是否是未知格式
    if (bfd_get_flavour(bfd_h) == bfd_target_unknown_flavour)
    {
        fprintf(stderr, "unrecognized format for file '%s' (%s)", 
                fname.c_str(), bfd_errmsg(bfd_get_error()));
        return NULL;
    }

    return bfd_h;
}

//解析静态符号，只添加函数符号到bin中
//参数1：bfd_openr()打开的对象，参数2：Binary类的对象
static int load_symbols_bfd(bfd* bfd_h, Binary* bin)
{
    int ret;
    long n, nsyms, i;
    asymbol** bfd_symtab;
    Symbol* sym;

    bfd_symtab = NULL;

    //获取符号表的大小并为其分配空间
    n = bfd_get_symtab_upper_bound(bfd_h);
    if (n < 0)
    {
        fprintf(stderr, "failed to read symtab (%s)\n",
                bfd_errmsg(bfd_get_error()));
        goto fail;
    }
    else if (n)
    {
        bfd_symtab = (asymbol**)malloc(n);
        if (!bfd_symtab)
        {
            fprintf(stderr, "out of memory\n");
            goto fail;
        }
    

        //把符号读入符号表并获取符号表中符号的个数
        nsyms = bfd_canonicalize_symtab(bfd_h, bfd_symtab);
        if (nsyms < 0)
        {
            fprintf(stderr, "failed to read symtab (%s)\n", 
                    bfd_errmsg(bfd_get_error()));
            goto fail;
        }

        //遍历符号表寻找函数符号并将其写入bin中
        for (i = 0; i < nsyms; ++i)
        {
            if (bfd_symtab[i]->flags & BSF_FUNCTION) //如果找到，就在bin中添加一个Symbol对象，并设置类型，名称， 地址
            {
                bin->symbols.push_back(Symbol());
                sym = &(bin->symbols.back());
                sym->type = Symbol::SYM_TYPE_FUNC;
                sym->name = string(bfd_symtab[i]->name);
                sym->addr = bfd_asymbol_value(bfd_symtab[i]);
            }
            if (bfd_symtab[i]->flags & BSF_OBJECT)//找到数据符号
            {
                //在bin中分配Symbol
                bin->symbols.push_back(Symbol());
                sym = &(bin->symbols.back());
                sym->type = Symbol::SYM_TYPE_OBJ;
                sym->name = string(bfd_symtab[i]->name);
                sym->addr = bfd_asymbol_value(bfd_symtab[i]);
            }
        }
    }

    ret = 0;
    goto cleanup;

    fail:
        ret = -1;
    
    cleanup:
        if (bfd_symtab)
        {
            free(bfd_symtab);
            bfd_symtab = NULL;
        }
    return ret;
}


static int load_dynsym_bfd(bfd* bfd_h, Binary* bin)
{
    int ret;
    long n, ndynsyms, i;
    asymbol** bfd_dynsymtab;
    Symbol* sym;

    bfd_dynsymtab = NULL;
    //获取动态符号表的大小并申请空间
    n = bfd_get_dynamic_symtab_upper_bound(bfd_h);
    if (n < 0)
    {
        fprintf(stderr, "failed to read dynamic symtab (%s)\n", 
                bfd_errmsg(bfd_get_error()));
        goto fail;
    }
    else if (n)
    {
        bfd_dynsymtab = (asymbol**)malloc(n);
        if (!bfd_dynsymtab)
        {
            fprintf(stderr, "out of memory\n");
            goto fail;
        }
        

        //将动态符号写入动态符号表并获取动态符号表中的大小
        ndynsyms = bfd_canonicalize_dynamic_symtab(bfd_h, bfd_dynsymtab);
        if (ndynsyms < 0)
        {
            fprintf(stderr, "failed to read dynamic symtab (%s)", 
                    bfd_errmsg(bfd_get_error()));
            goto fail;
        }

        //遍历动态符号表并将函数符号写入bin中
        for (i = 0; i < ndynsyms; ++i)
        {
            if (bfd_dynsymtab[i]->flags & BSF_FUNCTION)//found!!!
            {
                bin->symbols.push_back(Symbol());
                sym = &(bin->symbols.back());
                sym->type = Symbol::SYM_TYPE_FUNC;
                sym->name = string(bfd_dynsymtab[i]->name);
                sym->addr = bfd_asymbol_value(bfd_dynsymtab[i]);
            }
            if (bfd_dynsymtab[i]->flags & BSF_OBJECT)//找到数据符号
            {
                bin->symbols.push_back(Symbol());
                sym = &(bin->symbols.back());
                sym->type = Symbol::SYM_TYPE_OBJ;
                sym->name = string(bfd_dynsymtab[i]->name);
                sym->addr = bfd_asymbol_value(bfd_dynsymtab[i]);
            }
        }
    }

    ret = 0;
    goto cleanup;

    fail:
        ret = -1;
    
    cleanup:
        if (bfd_dynsymtab)
        {
            free(bfd_dynsymtab);
            bfd_dynsymtab = NULL;
        }

    return ret;
}

static int load_sections_bfd(bfd* bfd_h, Binary* bin)
{
    int bfd_flags;
    uint64_t vma, size;
    const char* secname;
    asection* bfd_sec;
    Section* sec;
    Section::SectionType sectype;

    //遍历bfd_h中的section，并将它们的信息记录到bin中
    for (bfd_sec = bfd_h->sections; bfd_sec; bfd_sec = bfd_sec->next)//获取单个section
    {
        //获取section的类型
        bfd_flags = bfd_get_section_flags(bfd_h, bfd_sec);

        //设置节类型
        sectype = Section::SEC_TYPE_NONE;
        if (bfd_flags & SEC_CODE)
        {
            sectype = Section::SEC_TYPE_CODE;
        }
        else if (bfd_flags & SEC_DATA)
        {
            sectype = Section::SEC_TYPE_DATA;
        }
        else
        {
            continue;
        }

        //获取起始地址、节大小、节名称
        vma = bfd_section_vma(bfd_h, bfd_sec);
        size = bfd_section_size(bfd_h, bfd_sec);
        secname = bfd_section_name(bfd_h, bfd_sec);
        //如果名称不存在
        if (!secname) secname = "<unname>";

        //在bin中分配Section对象
        bin->sections.push_back(Section());
        sec = &(bin->sections.back());

        //设置sec的内容
        sec->binary = bin;
        sec->name = string(secname);
        sec->size = size;
        sec->type = sectype;
        sec->vma = vma;
        //为bytes分配储存空间
        sec->bytes = (uint8_t*)malloc(size);
        if (!sec->bytes)
        {
            fprintf(stderr, "out of memory\n");
            return -1;
        }

        if (!bfd_get_section_contents(bfd_h, bfd_sec, sec->bytes, 0, size))//向bytes中填充字节
        {
            fprintf(stderr, "failed to read section '%s' (%s)", 
                    secname, bfd_errmsg(bfd_get_error()));
            return -1;
        }
    }

    return 0;
}

//参数1：文件名， 参数2：Binary对象， 参数3：Binary对象的type
int load_binary_bfd(string& fname, Binary* bin, Binary::BinaryType type)
{
    int ret;
    bfd* bfd_h;
    const bfd_arch_info_type* bfd_info;

    bfd_h = NULL;
    //获取bfd对象指针
    bfd_h = open_bfd(fname);
    if (!bfd_h)
    {
        goto fail;
    }

    //设置文件名和程序入口点
    bin->filename = fname.c_str();
    bin->entry = bfd_get_start_address(bfd_h);

    //确定可执行文件类型(PE/ELF)
    bin->type_str = string(bfd_h->xvec->name);
    switch (bfd_h->xvec->flavour)
    {
    case bfd_target_elf_flavour:
        bin->type = Binary::BIN_TYPE_ELF;
        break;
    case bfd_target_coff_flavour:
        bin->type = Binary::BIN_TYPE_PE;
        break;
    default:
        fprintf(stderr, "unsupported binary type (%s)\n", bfd_h->xvec->name);
        goto fail;
    }

    //确定可执行文件架构
    bfd_info = bfd_get_arch_info(bfd_h);
    bin->arch_str = string(bfd_info->printable_name);
    switch (bfd_info->mach)
    {
    case bfd_mach_i386_i386:
        bin-> arch = Binary::ARCH_X86;
        bin->bits = 32;
        break;
    case bfd_mach_x86_64:
        bin->arch = Binary::ARCH_X86;
        bin->bits = 64;
        break;
    default:
        fprintf(stderr, "unsupported architecture (%s)", bfd_info->printable_name);
        goto fail;
    }

    //符号处理
    load_symbols_bfd(bfd_h, bin);
    load_dynsym_bfd(bfd_h, bin);

    //解析节
    if (load_sections_bfd(bfd_h, bin) < 0) goto fail;

    ret = 0;
    goto cleanup;

    fail:
        ret = -1;

    cleanup:
        if (bfd_h) bfd_close(bfd_h);

    return ret;
}


//对load_binary_bfd()函数进行封装
//参数1：文件名， 参数2：Binary对象， 参数3：Binary对象的type
int load_binary(string& fname, Binary *bin, Binary::BinaryType type)
{
    return load_binary_bfd(fname, bin, type);
}


void unload_binary(Binary* bin)
{
    size_t i;
    Section* sec;

    //遍历bin中的sections容器，释放每个sec的bytes分配到的内存
    for (i = 0; i < bin->sections.size(); ++i)
    {
        sec = &(bin->sections[i]);
        if (sec->bytes)
        {
            free(sec->bytes);
            sec->bytes = NULL;
        }
    }
}


int main(int argc, char* argv[])
{
    size_t i;
    Binary bin;
    Section* sec;
    Symbol* sym;
    string fname;

    if (argc < 2)
    {
        printf("usage: %s <binary>\n", argv[0]);
        return 1;
    }

    fname.assign(argv[1]);
    //加载二进制文件
    if (load_binary(fname, &bin, Binary::BIN_TYPE_AUTO) < 0)
    {
        return 1;
    }

    printf("loaded binary '%s' %s/%s (%u bits) entry@0x%016jx\n", 
        bin.filename.c_str(),
        bin.type_str.c_str(), bin.arch_str.c_str(),
        bin.bits, bin.entry);

    //打印节信息
    for (i = 0; i < bin.sections.size(); i++)
    {
        sec = &bin.sections[i];
        printf("  0x%016jx %-8ju %-20s %s\n",
                sec->vma, sec->size, sec->name.c_str(), 
                sec->type == Section::SEC_TYPE_CODE ? "CODE" : "DATA");
    }

    //打印符号信息
    if (bin.symbols.size() > 0)
    {
        printf("Scanned symbol tables\n");
        for (i = 0; i < bin.symbols.size(); i++)
        {
            sym = &bin.symbols[i];
            printf("  %-40s 0x%016jx %s\n", 
                    sym->name.c_str(), sym->addr, 
                    (sym->type & Symbol::SYM_TYPE_FUNC) ? "FUNC" : "OBJ");
        }
    }

    //打印节的内容
    while (1)
    {
        printf("Do you want to show section's content? (Y/N)\n");
        char ans[10];
        int bytes_cnt;
        uint8_t* pcontent = NULL;
        char sec_name[100];
        scanf("%10s", ans);
        if (ans[0] == 'Y' || ans[0] == 'y')
        {
            //获取section的名称
            printf("Please input the section's name: \n");
            scanf("%100s", sec_name);
            //循环遍历sections寻找对应名称的section
            for (i = 0; i < bin.sections.size(); ++i)
            {
                sec = &(bin.sections[i]);
                if (!strcmp(sec_name, sec->name.c_str()))
                {
                    printf("0x%016jx %-8ju %-20s %s\n",
                    sec->vma, sec->size, sec->name.c_str(), 
                    sec->type == Section::SEC_TYPE_CODE ? "CODE" : "DATA");

                    for (bytes_cnt = 0; bytes_cnt < sec->size; bytes_cnt++)
                    {
                        printf("%02x ", sec->bytes[bytes_cnt]);
                        if ((bytes_cnt + 1) % 8 == 0)
                        {
                            printf(" ");
                        }
                        if((bytes_cnt + 1) % 16 == 0)
                        {
                            printf("\n");
                        }
                    }
                    printf("\n");
                }
                if (i == bin.sections.size())
                {
                    fprintf(stderr, "failed to find section '%s'\n", sec_name);
                }

            }
        }
        else if (ans[0] == 'N' || ans[0] == 'n')
        {
            break;
        }
        else
        {
            printf("invalid choice\n");
        }
    }

    //卸载二进制文件
    unload_binary(&bin);

    return 0;
}