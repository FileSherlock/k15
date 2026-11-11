/* Host timing of the asm crypto (src/os.asm built with -DHOST): `make bench`. */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/mman.h>
#include <x86intrin.h>
typedef unsigned char u8;
#define SCRATCH "memory", "cc", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", \
                "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7"
#define ASMCALL(fn, ...) __asm__ volatile("call " #fn : __VA_ARGS__ : : SCRATCH)
extern u8 E[], K[], REGS[];
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}
#define TIME(name, n, ...) do { double t = now(); unsigned long long c = __rdtsc(); \
    for (i = 0; i < (n); i++) { __VA_ARGS__; } \
    c = __rdtsc() - c; \
    printf("%-34s %8.1f us  %9llu cycles\n", name, (now() - t) / (n) * 1e6, c / (n)); } while (0)
int main(void){
    mmap((void *)0x200000, 0x200000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    __asm__ volatile("call shaconst" ::: SCRATCH);
    static u8 u[32]={9}, pub[32], z[32], m[4096], h[32]; int i;
    TIME("tables (boot)", 1, __asm__ volatile("call echost" ::: SCRATCH));
    for(i=0;i<32;i++) E[i]=i*7+1, K[i]=i*13+5, z[i]=i*3;
    TIME("x25519: our share and the secret", 2000, { u8 *p = pub; const u8 *q = u; ASMCALL(xdh, "+D"(p), "+S"(q)); });
    TIME("ecdsa: sign", 2000, { const u8 *q = z; ASMCALL(sign, "+S"(q)); });
    TIME("sha256 of 64 bytes (2 blocks)", 20000, { u8 *o = h, *mm = m; unsigned n = 64; ASMCALL(sha256, "+D"(o), "+S"(mm), "+c"(n)); });
    TIME("sha256 of 3000 bytes", 2000, { u8 *o = h, *mm = m; unsigned n = 3000; ASMCALL(sha256, "+D"(o), "+S"(mm), "+c"(n)); });
    return 0;
}
