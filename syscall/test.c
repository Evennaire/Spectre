#include<stdio.h>
#include<unistd.h>

int main(){
    long pid = 0;
    long num = 500;
    
    pid = syscall(329, 0, 0x233);
    printf("num:0x%lx\n",pid);

    return 0;

}

