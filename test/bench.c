/* Host timing of the asm crypto (src/os.asm built with -DHOST): `make bench`. */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/mman.h>
typedef unsigned char u8;
#define ASMCALL(fn, ...) __asm__ volatile("call " #fn : __VA_ARGS__ : : "memory", "cc")
extern u8 E[], K[], REGS[];
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}
int main(void){
    mmap((void *)0x200000, 0x100000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    __asm__ volatile("call shaconst" ::: "memory","cc");
    static u8 u[32]={9}; int i;
    for(i=0;i<32;i++) E[i]=i*7+1, K[i]=i*13+5;
    double t=now();
    for(i=0;i<20;i++){ const u8*p=u; ASMCALL(x25519, "+S"(p)); }
    printf("x25519: %.2f ms each\n",(now()-t)/20*1e3);
    t=now();
    for(i=0;i<20;i++){ __asm__ volatile("call sigr" ::: "memory","cc"); }
    printf("sigr (r with retries + 1/k): %.2f ms each\n",(now()-t)/20*1e3);
    static u8 m[4096], h[32]; u8*o=h,*mm=m; unsigned n=3000;
    t=now();
    for(i=0;i<200;i++){ o=h; mm=m; n=3000; ASMCALL(sha256, "+D"(o), "+S"(mm), "+c"(n)); }
    printf("sha256 of 3000 bytes: %.1f us each\n",(now()-t)/200*1e6);
    return 0;
}
