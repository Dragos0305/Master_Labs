#include <stdio.h>
#include <string.h>
#include <stdlib.h>
/* byte string shellcode */
int main()
{
    char shellcode[] = "\xeb\x16\x5b\x31\xc9\xb8\x05\x00\x00\x00\xcd\x80\xeb\x20\x5b\x31\xc9\xb8\x05\x00\x00\x00\xcd\x80\xe8\xe5\xff\xff\xff\x2e\x2e\x2f\x2e\x2e\x2f\x6a\x61\x69\x6c\x2f\x61\x2e\x74\x78\x74\x00\xe8\xdb\xff\xff\xff\x2e\x2e\x2f\x2e\x2e\x2f\x62\x2e\x74\x78\x74\x00";
    void (*func_ptr)(void) = (void (*)(void)) shellcode;
    /* Call shellcode. */
    func_ptr();
    while(1) {
	printf("PLM");
}
    return 0;
}
