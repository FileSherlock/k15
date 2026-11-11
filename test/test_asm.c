/* Host harness for the asm crypto (src/os.asm built with -DHOST): prints the same lines as
 * test_crypto.c so test/test_crypto.py can check them. Build: see the Makefile. */
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

typedef unsigned char u8;
typedef unsigned int u32;

/* The asm keeps the eight old registers (or says what it returns in them); r8-r15 and the
 * SSE registers are scratch. */
#define SCRATCH "memory", "cc", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", \
                "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7"
#define ASMCALL(fn, ...) __asm__ volatile("call " #fn : __VA_ARGS__ : : SCRATCH)

static void sha(u8 *out, u8 *m, u32 n) { ASMCALL(sha256, "+D"(out), "+S"(m), "+c"(n)); }
static void hm(u8 *out, const u8 *k, const u8 *m, u32 n) { ASMCALL(hmac, "+D"(out), "+b"(k), "+S"(m), "+c"(n)); }
static void ex(u8 *out, const u8 *sec, const char *lab, const u8 *ctx) { ASMCALL(expand, "+D"(out), "+b"(sec), "+S"(lab), "+d"(ctx)); }
static u32 sl(u8 *o, const u8 *m, u32 n, const u8 *kiv, u32 seq)
{
    u8 *e = o;
    __asm__ volatile("clc\n\tcall seal" : "+D"(e), "+S"(m), "+c"(n), "+b"(kiv), "+d"(seq) : : SCRATCH); /* CF = 0: encrypt */
    return e - o;
}

extern u8 E[], K[], REGS[];
enum { R_X = 3 * 32, R_Y = 4 * 32 }; /* as in tools/ec.py */
/* our key share for the secret E to pub, the secret shared with the owner of u to shared */
static void xdh_(u8 *pub, u8 *shared, const u8 *u)
{
    ASMCALL(xdh, "+D"(pub), "+S"(u));
    memcpy(shared, REGS + R_X, 32);
}

static void hex(const char *tag, const u8 *p, u32 n)
{
    printf("%s ", tag);
    while (n--) printf("%02x", *p++);
    printf("\n");
}

int main(void)
{
    static u8 m[2000], out[4096], tmp[2100], h[32], kiv[68];
    setbuf(stdout, NULL);
    u32 i, lens[] = {0, 3, 55, 56, 63, 64, 119, 1000, 1999};
    if (mmap((void *)0x200000, 0x200000, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0) != (void *)0x200000) {
        perror("mmap");
        return 1;
    }
    __asm__ volatile("call shaconst\n\tcall echost" ::: SCRATCH);
    for (i = 0; i < sizeof m; i++) m[i] = i * 7 + 3;
    for (i = 0; i < sizeof lens / sizeof *lens; i++) {
        char t[32];
        memcpy(tmp, m, lens[i]);
        sha(h, tmp, lens[i]);
        sprintf(t, "sha%u", lens[i]);
        hex(t, h, 32);
    }
    hm(h, m, m + 32, 50);
    hex("hmac", h, 32);
    ex(h, m, "\x20\x07" "derived", m + 100);
    hex("expand", h, 32);
    for (i = 0; i < 32; i++) kiv[i] = m[300 + i], kiv[36 + i] = m[400 + i];
    for (i = 0; i < 12; i++) {       /* ChaCha20-Poly1305, then AES-128-GCM (the key block says) */
        u32 n = (u32[]){1, 100, 1500, 15, 16, 17}[i % 6], L;
        char t[32];
        kiv[32] = i >= 6;
        L = sl(out, m, n, kiv, i * 77);
        sprintf(t, "%s%u_%u", i >= 6 ? "gcm" : "seal", n, i * 77);
        hex(t, out, L);
    }
    /* X25519 with our scalar e (unclamped): key share, and the secret with the public key
     * of the all-zero private key; then with scalars of all ones and all zeros, and with a
     * client's u that has its top bit set (which is to be ignored) */
    {
        static u8 peer[32] = {0x2f,0xe5,0x7d,0xa3,0x47,0xcd,0x62,0x43,0x15,0x28,0xda,0xac,0x5f,0xbb,0x29,0x07,
                              0x30,0xff,0xf6,0x84,0xaf,0xc4,0xcf,0xc2,0xed,0x90,0x99,0x5f,0x58,0xcb,0x3b,0x74};
        static u8 pub[32], shared[32];
        for (i = 0; i < 4; i++) {
            u32 j;
            char t[32];
            for (j = 0; j < 32; j++) E[j] = i == 1 ? 0xff : i == 2 ? 0 : m[500 + 40 * i + j];
            peer[31] = i == 3 ? peer[31] | 0x80 : peer[31] & 0x7f;
            xdh_(pub, shared, peer);
            sprintf(t, "xpub%u", i);
            hex(t, pub, 32);
            sprintf(t, "xshared%u", i);
            hex(t, shared, 32);
        }
    }
    /* ECDSA: (r, s) for a hash and the nonce K */
    for (i = 0; i < 6; i++) {
        u32 j;
        char t[32];
        static u8 z[32];
        const u8 *zp = z;
        for (j = 0; j < 32; j++) K[j] = m[600 + 40 * i + j], z[j] = m[900 + 40 * i + j];
        if (i == 2) memset(K, 0xff, 32), memset(z, 0xff, 32);
        if (i == 3) memset(K, 0, 32), K[0] = 1, memset(z, 0, 32);
        ASMCALL(sign, "+S"(zp));
        sprintf(t, "sig%u", i);
        memcpy(tmp, z, 32), memcpy(tmp + 32, REGS + R_X, 32), memcpy(tmp + 64, REGS + R_Y, 32);
        hex(t, tmp, 96); /* hash (big-endian) | r | s (little-endian) */
    }
    return 0;
}
