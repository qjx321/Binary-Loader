#include<stdio.h>

void print(char * msg)
{
    printf("%s", msg);
}

int main()
{
    char* message = "Hello world!\n";
    print(message);
}