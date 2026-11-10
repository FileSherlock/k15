#!/usr/bin/env python3
"""The elliptic-curve side of the image, as data plus a bit-exact Python model of it.

The asm has one 256-bit modular multiplication (Montgomery, R = 2^288: 9 limbs of 32 bits)
and a tiny register machine on top: 16 registers of 9 limbs, three operations. The curve
formulas are programs for that machine, assembled here (2 bytes per operation) and included
in the image by gen.py. This file also runs them in Python, so `python3 tools/ec.py` checks
the formulas, the constants and the size bounds below against pyca/cryptography.

Lazy reduction: nothing is ever reduced or compared. With R = 2^288 and m < 2^256,
  mul(a, b) = a b / R mod m, and is < 2m    whenever a, b < 4096 m
  add(a, b) = a + b                         (plain 9-limb addition)
  sub(a, b) = a - b + 256 m                 (needs b <= 256 m; 256 m is the modulus read one
                                             byte early: a zero byte sits in front of it)
so there are no data-dependent branches or lengths anywhere. Canonical values only appear
where a result leaves the machine, through mul(x, 1), which is <= m.

Montgomery form: a stored value s stands for s / R. Products of stored values are then
stored values again; constants are baked in already multiplied by R. Inputs that arrive raw
(the client's key share, the hash to sign) are used raw where the formulas are homogeneous
enough not to care, see the programs.
"""
import os
import sys

R = 1 << 288
P25519 = (1 << 255) - 19
P256 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
N256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
B256 = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX256 = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY256 = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

# registers: GX to ONE are constants copied from the image at boot, the next two are set by
# boot code (near ONE: short addresses), the rest starts as zero. U, X2 and Z2 come first:
# the asm reaches r and s with short offsets from pointers it has anyway (the nonce sits
# right in front of the registers), and register 0 must not be squared (see asm()): U never is.
REGS = "U X2 Z2 X3 Z3 GX B4 D ONE A24 NINE ZERO T0 T1 T2 T3".split()
REG = {n: i for i, n in enumerate(REGS)}
ADD, SUB, MUL = 1, 2, 3


def asm(text):
    """'DST = A op B' lines -> bytes: a << 4 | b, then op << 4 | dst; a zero byte ends the
    program (no operation has register 0 as both operands)."""
    out = bytearray()
    for line in text.strip().splitlines():
        line = line.split("#")[0].strip()
        if not line:
            continue
        dst, _, a, op, b = line.split()
        out += bytes([REG[a] << 4 | REG[b], {"+": ADD, "-": SUB, "*": MUL}[op] << 4 | REG[dst]])
    assert all(out[::2])
    return bytes(out) + b"\0"


# Both ladders keep two points (X2 : Z2) and (X3 : Z3) whose difference is the base point, and
# start from infinity = (1 : 0) and the base point = (x : 1).
#
# X25519 (RFC 7748). U is the raw u coordinate; A24 is 121665 R. Multiplying by the raw U
# puts a factor 1/R on Z3, so X3 gets one too (times ONE): a ratio doesn't mind.
INIT25519 = asm("""
    X2 = ONE + ZERO
    Z2 = ZERO + ZERO
    X3 = U + ZERO
    Z3 = ONE + ZERO
""")
STEP25519 = asm("""
    T0 = X2 + Z2        # A
    T1 = X2 - Z2        # B
    T2 = X3 + Z3        # C
    T3 = X3 - Z3        # D
    T3 = T3 * T0        # DA
    T2 = T2 * T1        # CB
    X3 = T3 + T2
    X3 = X3 * X3
    X3 = X3 * ONE
    Z3 = T3 - T2
    Z3 = Z3 * Z3
    Z3 = Z3 * U
    T0 = T0 * T0        # AA
    T1 = T1 * T1        # BB
    X2 = T0 * T1
    T1 = T0 - T1        # E
    Z2 = A24 * T1
    Z2 = Z2 + T0
    Z2 = Z2 * T1
""")
# P-256, x only (Brier and Joye 2002, a = -3). GX is x(G) R, B4 is 4 b R.
#   add:    X = (X2 X3 + 3 Z2 Z3)^2 - 4b Z2 Z3 (X2 Z3 + X3 Z2),  Z = x(G) (X2 Z3 - X3 Z2)^2
#   double: X = (X^2 + 3 Z^2)^2 - 8b X Z^3,  Z = 4 Z (X (X^2 - 3 Z^2) + b Z^3)
INIT256 = asm("""
    X2 = ONE + ZERO
    Z2 = ZERO + ZERO
    X3 = GX * ONE
    Z3 = ONE + ZERO
""")
STEP256 = asm("""
    T0 = X2 * X3
    T1 = Z2 * Z3
    T2 = X2 * Z3
    T3 = X3 * Z2
    Z3 = T2 - T3
    Z3 = Z3 * Z3
    Z3 = Z3 * GX
    T2 = T2 + T3
    T2 = T2 * T1
    T2 = T2 * B4
    T3 = T1 + T1
    T3 = T3 + T1
    T3 = T3 + T0
    X3 = T3 * T3
    X3 = X3 - T2
    T0 = X2 * X2        # XX
    T1 = Z2 * Z2        # ZZ
    T2 = T1 + T1
    T2 = T2 + T1        # 3 ZZ
    T3 = T0 + T2
    T3 = T3 * T3        # (XX + 3 ZZ)^2
    T0 = T0 - T2
    T0 = T0 * X2        # w = X (XX - 3 ZZ)
    T1 = T1 * Z2
    T1 = T1 * B4        # 4b Z^3
    T2 = T1 * X2
    T2 = T2 + T2        # 8b X Z^3
    X2 = T3 - T2
    T0 = T0 + T0
    T0 = T0 + T0
    T0 = T0 + T1        # 4w + 4b Z^3
    Z2 = T0 * Z2
""")
# After a ladder and inv(Z2) -> T1 (which is R^2 / Z2): X2 = X2 / Z2, canonical.
FIN = asm("""
    T0 = T1 * X2
    X2 = T0 * ONE
""")
# ECDSA, mod n: X2 = r (raw), U = hash (raw), D = d R, T1 = inv(k) = R^2 / k.
# Z2 = s = (hash + r d) / k, canonical.
SIGN = asm("""
    T0 = X2 * D
    T0 = T0 + U
    T0 = T0 * T1
    Z2 = T0 * ONE
""")

PROGRAMS = {"INIT25519": INIT25519, "STEP25519": STEP25519, "INIT256": INIT256,
            "STEP256": STEP256, "FIN": FIN, "SIGN": SIGN}


def mprime(m):
    return (-pow(m, -1, 1 << 32)) % (1 << 32)


class Machine:
    """The register machine, with the asm's exact arithmetic and its preconditions asserted."""

    def __init__(self):
        self.r = [0] * 16
        self.r[REG["ONE"]] = 1
        self.r[REG["NINE"]] = 9
        self.r[REG["A24"]] = 121665 * R % P25519
        assert self.r[REG["A24"]] == 4623270 << 32
        self.r[REG["GX"]] = GX256 * R % P256
        self.r[REG["B4"]] = 4 * B256 * R % P256
        self.m = None

    def mul(self, a, b):
        m = self.m
        assert a < 4096 * m and b < 4096 * m
        t = a * b
        for _ in range(9):
            t = (t + (t * mprime(m) % (1 << 32)) * m) >> 32
        assert t < 2 * m and t == a * b * pow(R, -1, m) % m + (m if t >= m else 0)
        return t

    def run(self, prog):
        r = self.r
        for i in range(0, len(prog) - 1, 2):
            b, a, dst, op = prog[i] & 15, prog[i] >> 4, prog[i + 1] & 15, prog[i + 1] >> 4
            if op == ADD:
                v = r[a] + r[b]
            elif op == SUB:
                assert r[b] <= 256 * self.m
                v = r[a] - r[b] + 256 * self.m
            else:
                v = self.mul(r[a], r[b])
            assert 0 <= v < R
            r[dst] = v

    def ladder(self, k, step):
        r, x2 = self.r, REG["X2"]
        for i in reversed(range(256)):
            bit = k >> i & 1
            if bit:
                r[x2:x2 + 4] = r[x2 + 2:x2 + 4] + r[x2:x2 + 2]
            self.run(step)
            if bit:
                r[x2:x2 + 4] = r[x2 + 2:x2 + 4] + r[x2:x2 + 2]

    def inv(self, x):
        """T1 = x^(m-2) by right-to-left square and multiply (bit 0 of m - 2 is always 1)."""
        r, e = self.r, self.m - 2
        r[REG["T0"]] = r[REG["T1"]] = x
        for i in range(1, 256):
            r[REG["T0"]] = self.mul(r[REG["T0"]], r[REG["T0"]])
            if e >> i & 1:
                r[REG["T1"]] = self.mul(r[REG["T1"]], r[REG["T0"]])

    def x25519(self, k, u):
        self.m = P25519
        self.r[REG["U"]] = u
        self.run(INIT25519)
        self.ladder(k, STEP25519)
        self.inv(self.r[REG["Z2"]])
        self.run(FIN)
        return self.r[REG["X2"]]

    def sign(self, d, k, z):
        """(r, s) for hash z and nonce k; r is x(kG) without the reduction mod n."""
        self.m = P256
        self.run(INIT256)
        self.ladder(k, STEP256)
        self.inv(self.r[REG["Z2"]])
        self.run(FIN)
        self.m = N256
        self.r[REG["D"]] = d * R % N256
        self.r[REG["U"]] = z
        self.inv(k)
        self.run(SIGN)
        return self.r[REG["X2"]], self.r[REG["Z2"]]


def selftest():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    mach = Machine()
    for t in range(6):
        # X25519: our scalar is unclamped, so compare shared secrets, both ways round
        peer = X25519PrivateKey.generate()
        e = int.from_bytes(os.urandom(32), "little") if t else (1 << 256) - 1
        pub = mach.x25519(e, 9)
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        theirs = peer.exchange(X25519PublicKey.from_public_bytes(pub.to_bytes(32, "little")))
        u = int.from_bytes(peer.public_key().public_bytes_raw(), "little")
        if t == 1:
            u |= 1 << 255  # a client may set the unused top bit; we take u mod p (as curve25519 does not)
        ours = mach.x25519(e, u)
        if t != 1:
            assert ours.to_bytes(32, "little") == theirs, "x25519"
        # ECDSA
        key = ec.generate_private_key(ec.SECP256R1())
        d = key.private_numbers().private_value
        k = int.from_bytes(os.urandom(32), "little") if t else (1 << 256) - 1
        z = int.from_bytes(os.urandom(32), "big") if t else (1 << 256) - 1
        r, s = mach.sign(d, k, z)
        if 0 < r < N256 and 0 < s < N256:
            key.public_key().verify(utils.encode_dss_signature(r, s), z.to_bytes(32, "big"),
                                    ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    print("ec.py: programs ok;", ", ".join(f"{n} {len(p)}" for n, p in PROGRAMS.items()), "bytes")


if __name__ == "__main__":
    selftest()
