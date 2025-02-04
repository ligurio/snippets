#include <stdlib.h>

size_t b_cpuid(void *dummy) {
  asm volatile("push %%"
               "bx; cpuid; pop %%"
               "bx"
               :
               :
               : "eax", "ecx", "edx");
  return 0;
}

/*

https://github.com/autotest/tp-qemu/blob/master/qemu/deps/cpuid/src/test.c#L63

size_t b_cpuid(unsigned int leaf, unsigned int idx)
{
    unsigned int eax, ebx, ecx, edx;
    asm("cpuid"
        : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx)
        : "a" (leaf), "c" (idx));
    printf("   0x%08x 0x%02x: eax=0x%08x ebx=0x%08x"
           " ecx=0x%08x edx=0x%08x\n", leaf, idx,
           eax, ebx, ecx, edx);
    return eax;
}
*/
