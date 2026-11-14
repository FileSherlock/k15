#!/usr/bin/env python3
"""The Bitcoin address that a certificate's private key also is the key of, and a
zero-knowledge proof (without revealing the key) that the two public keys share it.

    tools/bounty.py CERT/server.key                       the bc1q... address (public)
    tools/bounty.py CERT/server.key --wif                 the key as a wallet imports it
    tools/bounty.py --gen CERT [-n NAME] [--san NAME]...  24 BIP-39 words + key + CSR + proof
    tools/bounty.py --restore [--wif] [--out KEYFILE]     check/restore from the 24 words
    tools/bounty.py --prove CERT/server.key [PROOF]       write Cross-Curve DLEQ proof
    tools/bounty.py --verify [HOST[:PORT]|CERT.pem] [PROOF]  verify live server or PEM (stdlib)
    tools/bounty.py --test                                known answers and soundness checks

A P-256 private key is an integer d in [1, n_r1 - 1], and n_r1 < n_k1: so the same integer d
is a valid secp256k1 private key. `--prove` decomposes d (or n_r1 - 1 - d when d >= 2^255)
into 128 base-4 digits (< 2^255 < n_r1 < n_k1, so neither group reduces the sum) under
Pedersen commitments on both curves, linked by a 128-bit Borromean ring signature (MRL-0010).
`--verify` uses Python's standard library alone.
"""
import base64
import getpass
import hashlib
import hmac
import os
import socket
import ssl
import sys

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BIP39_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
BIP39_PATHS = (
    "/usr/lib/python3/dist-packages/passlib/_data/wordsets/bip39.txt",
    "/usr/share/dict/bip39.txt",
)


class Curve:
    def __init__(self, name, p, a, b, n, gx, gy):
        self.name, self.p, self.a, self.b, self.n = name, p, a, b, n
        self.G = (gx, gy)
        self.H = self._nums(f"k15-bounty-nums-{name}".encode())
        self._htab = None

    def on(self, P):
        return P is not None and 0 <= P[0] < self.p and 0 <= P[1] < self.p and (
            P[1] * P[1] - (P[0] * P[0] + self.a) * P[0] - self.b) % self.p == 0

    def _nums(self, tag):
        p = self.p
        for ctr in range(256):
            x = int.from_bytes(hashlib.sha256(tag + bytes([ctr])).digest(), "big")
            if x < p:
                rhs = ((x * x + self.a) * x + self.b) % p
                y = pow(rhs, (p + 1) >> 2, p)
                if y * y % p == rhs:
                    return (x, y if y & 1 == 0 else p - y)
        raise RuntimeError("NUMS")

    def encode(self, P):
        if P is None:
            raise ValueError("infinity")
        return bytes([2 | (P[1] & 1)]) + P[0].to_bytes(32, "big")

    def decode(self, buf):
        if len(buf) != 33 or buf[0] not in (2, 3):
            raise ValueError("bad point encoding")
        p, x = self.p, int.from_bytes(buf[1:], "big")
        if x >= p:
            raise ValueError("x >= p")
        rhs = ((x * x + self.a) * x + self.b) % p
        y = pow(rhs, (p + 1) >> 2, p)
        if y * y % p != rhs:
            raise ValueError("point not on curve")
        if (y & 1) != (buf[0] & 1):
            y = p - y
        return (x, y)

    def neg(self, P):
        return None if P is None else (P[0], (-P[1]) % self.p)

    def j_dbl(self, J):
        if J is None:
            return None
        X1, Y1, Z1 = J
        if Y1 == 0:
            return None
        p = self.p
        Y1sq = Y1 * Y1 % p
        S = 4 * X1 * Y1sq % p
        Z2 = Z1 * Z1 % p
        M = 3 * (X1 - Z2) * (X1 + Z2) % p if self.a == p - 3 else (3 * X1 * X1 + self.a * Z2 * Z2) % p
        X3 = (M * M - 2 * S) % p
        Y3 = (M * (S - X3) - 8 * Y1sq * Y1sq) % p
        Z3 = 2 * Y1 * Z1 % p
        return (X3, Y3, Z3)

    def j_add_aff(self, J, Q):
        if Q is None:
            return J
        if J is None:
            return (Q[0], Q[1], 1)
        X1, Y1, Z1 = J
        x2, y2 = Q
        p = self.p
        Z2 = Z1 * Z1 % p
        U2 = x2 * Z2 % p
        S2 = y2 * Z2 * Z1 % p
        H = (U2 - X1) % p
        R = (S2 - Y1) % p
        if H == 0:
            return self.j_dbl(J) if R == 0 else None
        H2 = H * H % p
        H3 = H * H2 % p
        V = X1 * H2 % p
        X3 = (R * R - H3 - 2 * V) % p
        Y3 = (R * (V - X3) - Y1 * H3) % p
        Z3 = Z1 * H % p
        return (X3, Y3, Z3)

    def j_add(self, J1, J2):
        if J1 is None or J2 is None:
            return J1 or J2
        X1, Y1, Z1 = J1
        X2, Y2, Z2 = J2
        if Z2 == 1:
            return self.j_add_aff(J1, (X2, Y2))
        p = self.p
        Z1s, Z2s = Z1 * Z1 % p, Z2 * Z2 % p
        U1, U2 = X1 * Z2s % p, X2 * Z1s % p
        S1, S2 = Y1 * Z2s * Z2 % p, Y2 * Z1s * Z1 % p
        H, R = (U2 - U1) % p, (S2 - S1) % p
        if H == 0:
            return self.j_dbl(J1) if R == 0 else None
        H2 = H * H % p
        H3 = H * H2 % p
        V = U1 * H2 % p
        X3 = (R * R - H3 - 2 * V) % p
        Y3 = (R * (V - X3) - S1 * H3) % p
        return (X3, Y3, Z1 * Z2 % p * H % p)

    def to_aff(self, J):
        if J is None:
            return None
        p = self.p
        iz = pow(J[2], -1, p)
        iz2 = iz * iz % p
        return (J[0] * iz2 % p, J[1] * iz2 * iz % p)

    def batch_aff(self, Js):
        p = self.p
        idx = [i for i, J in enumerate(Js) if J is not None]
        if not idx:
            return [None] * len(Js)
        acc, pre = 1, []
        for i in idx:
            pre.append(acc)
            acc = acc * Js[i][2] % p
        inv = pow(acc, -1, p)
        out = [None] * len(Js)
        for i, pr in zip(reversed(idx), reversed(pre)):
            X, Y, Z = Js[i]
            iz = inv * pr % p
            inv = inv * Z % p
            iz2 = iz * iz % p
            out[i] = (X * iz2 % p, Y * iz2 * iz % p)
        return out

    def add(self, P, Q):
        return self.to_aff(self.j_add_aff(None if P is None else (P[0], P[1], 1), Q))

    def mul(self, k, P):
        k %= self.n
        if k == 0 or P is None:
            return None
        acc = None
        J = (P[0], P[1], 1)
        while k:
            if k & 1:
                acc = self.j_add(acc, J)
            k >>= 1
            if k:
                J = self.j_dbl(J)
        return self.to_aff(acc)

    def _ensure_htab(self):
        if self._htab is not None:
            return
        rows_j = []
        base = (self.H[0], self.H[1], 1)
        for _ in range(64):
            row = [None, base]
            for u in range(2, 16):
                row.append(self.j_add(row[-1], base))
            rows_j.extend(row[1:])
            for _ in range(4):
                base = self.j_dbl(base)
        affs = self.batch_aff(rows_j)
        self._htab = [[None] + affs[i * 15:(i + 1) * 15] for i in range(64)]

    def mul_H_j(self, s):
        self._ensure_htab()
        s %= self.n
        acc = None
        for t in range(64):
            u = s & 15
            if u:
                acc = self.j_add_aff(acc, self._htab[t][u])
            s >>= 4
            if not s:
                break
        return acc

    def lin_step(self, s, neg_e, Q):
        """Return affine s * H - e * Q, where 0 <= neg_e < 2^128 and Q is affine."""
        acc = None
        if neg_e and Q is not None:
            nQ = (Q[0], (-Q[1]) % self.p)
            win = [None, (nQ[0], nQ[1], 1)]
            for _ in range(2, 16):
                win.append(self.j_add_aff(win[-1], nQ))
            for shift in range(124, -1, -4):
                if acc is not None:
                    acc = self.j_dbl(self.j_dbl(self.j_dbl(self.j_dbl(acc))))
                u = (neg_e >> shift) & 15
                if u:
                    acc = self.j_add(acc, win[u])
        return self.to_aff(self.j_add(acc, self.mul_H_j(s)))


R1 = Curve(
    "secp256r1",
    0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
    0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)
K1 = Curve(
    "secp256k1",
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    0,
    7,
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
N_R1, N_K1 = R1.n, K1.n


def pubkey(d):
    """The compressed secp256k1 public key of d, 33 bytes."""
    return K1.encode(K1.mul(d, K1.G))


def polymod(values):
    c = 1
    for v in values:
        top = c >> 25
        c = (c & 0x1FFFFFF) << 5 ^ v
        for i, g in enumerate((0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)):
            if top >> i & 1:
                c ^= g
    return c


def address_from_pubkey(pk_bytes, hrp="bc"):
    """bech32 of witness version 0 and hash160 of a 33-byte compressed secp256k1 public key."""
    h = hashlib.new("ripemd160", hashlib.sha256(pk_bytes).digest()).digest()
    bits = "".join(f"{b:08b}" for b in h) + "0000"
    data = [0] + [int(bits[i:i + 5], 2) for i in range(0, 160, 5)]
    exp = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    check = polymod(exp + data + [0] * 6) ^ 1
    data += [check >> 5 * (5 - i) & 31 for i in range(6)]
    return hrp + "1" + "".join(B32[v] for v in data)


def address(d, hrp="bc"):
    return address_from_pubkey(pubkey(d), hrp)


def wif(d):
    """The key for import: base58check of 0x80, the key, 0x01 (compressed public key)."""
    raw = b"\x80" + d.to_bytes(32, "big") + b"\x01"
    n = int.from_bytes(raw + hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4], "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    return s


# --- BIP-39 + BIP-84 (m/84'/0'/0'/0/0) ---

def load_wordlist():
    env = os.environ.get("BIP39_WORDS")
    paths = ([env] if env else []) + list(BIP39_PATHS)
    for path in paths:
        if path and os.path.exists(path):
            words = [w.strip() for w in open(path, encoding="utf-8").read().splitlines() if w.strip()][:2048]
            raw = ("\n".join(words) + "\n").encode()
            if hashlib.sha256(raw).hexdigest() == BIP39_SHA256:
                return words
    sys.exit("bounty.py: BIP-39 wordlist not found (install python3-passlib or set BIP39_WORDS)")


def entropy_to_words(ent):
    assert len(ent) in (16, 32)
    words = load_wordlist()
    cs_bits = len(ent) * 8 // 32
    cs = hashlib.sha256(ent).digest()[0] >> (8 - cs_bits)
    val = (int.from_bytes(ent, "big") << cs_bits) | cs
    n = (len(ent) * 8 + cs_bits) // 11
    return [words[(val >> (11 * (n - 1 - i))) & 0x7FF] for i in range(n)]


def words_to_entropy(phrase):
    words = load_wordlist()
    idx_map = {w: i for i, w in enumerate(words)}
    toks = phrase.strip().lower().split()
    if len(toks) not in (12, 24):
        raise ValueError(f"expected 12 or 24 BIP-39 words, got {len(toks)}")
    val = 0
    for w in toks:
        if w not in idx_map:
            raise ValueError(f"not a BIP-39 word: '{w}'")
        val = (val << 11) | idx_map[w]
    cs_bits = len(toks) // 3
    ent_bytes = (len(toks) * 11 - cs_bits) // 8
    ent = (val >> cs_bits).to_bytes(ent_bytes, "big")
    cs = hashlib.sha256(ent).digest()[0] >> (8 - cs_bits)
    if (val & ((1 << cs_bits) - 1)) != cs:
        raise ValueError("BIP-39 checksum mismatch (check your written words for a typo)")
    return ent, toks


def bip84_scalar(words_list):
    seed = hashlib.pbkdf2_hmac("sha512", " ".join(words_list).encode(), b"mnemonic", 2048, 64)
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k, c = int.from_bytes(I[:32], "big"), I[32:]
    if not 0 < k < N_K1:
        raise ValueError("invalid master key")
    for idx in (84 | 0x80000000, 0x80000000, 0x80000000, 0, 0):
        data = (b"\x00" + k.to_bytes(32, "big") if idx & 0x80000000 else pubkey(k)) + idx.to_bytes(4, "big")
        I = hmac.new(c, data, hashlib.sha512).digest()
        il = int.from_bytes(I[:32], "big")
        k = (il + k) % N_K1
        if il >= N_K1 or k == 0:
            raise ValueError("invalid child key")
        c = I[32:]
    return k


# --- Cross-Curve Zero-Knowledge Proof (Borromean Pedersen DLEQ, 128-bit challenge) ---

def _rand_mod(n):
    while True:
        v = int.from_bytes(os.urandom(32), "big")
        if 1 <= v < n:
            return v


def _h128(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return int.from_bytes(h.digest()[:16], "big")


def prove_xcurve(d):
    """Prove knowledge of d in [1, N_R1 - 1] with Q1 = d * G_R1 and Q2 = d * G_K1."""
    if not 0 < d < N_R1:
        raise ValueError("d out of P-256 range")
    Q1, Q2 = R1.mul(d, R1.G), K1.mul(d, K1.G)
    flip = 1 if d >= (1 << 255) else 0
    dp = (N_R1 - 1 - d) if flip else d
    assert 0 <= dp < (1 << 255)
    digits = [(dp >> (2 * i)) & 3 for i in range(128)]
    assert digits[127] in (0, 1)

    r1 = [_rand_mod(N_R1) for _ in range(127)]
    r2 = [_rand_mod(N_K1) for _ in range(127)]
    r1.append((-sum(r1[i] << (2 * i) for i in range(127)) * pow(1 << 254, -1, N_R1)) % N_R1)
    r2.append((-sum(r2[i] << (2 * i) for i in range(127)) * pow(1 << 254, -1, N_K1)) % N_K1)

    G1s = [None, R1.G, R1.mul(2, R1.G), R1.mul(3, R1.G)]
    G2s = [None, K1.G, K1.mul(2, K1.G), K1.mul(3, K1.G)]
    C1 = [R1.to_aff(R1.j_add_aff(R1.mul_H_j(r1[i]), G1s[digits[i]])) for i in range(128)]
    C2 = [K1.to_aff(K1.j_add_aff(K1.mul_H_j(r2[i]), G2s[digits[i]])) for i in range(128)]

    ctx_h = hashlib.sha256(b"k15-xcurve-dleq-v1" + bytes([flip]) + R1.encode(Q1) + K1.encode(Q2))
    for i in range(128):
        ctx_h.update(R1.encode(C1[i]))
        ctx_h.update(K1.encode(C2[i]))
    ctx = ctx_h.digest()

    s1 = [[0] * (2 if i == 127 else 4) for i in range(128)]
    s2 = [[0] * (2 if i == 127 else 4) for i in range(128)]
    k1 = [_rand_mod(N_R1) for _ in range(128)]
    k2 = [_rand_mod(N_K1) for _ in range(128)]
    tops = []
    for i in range(128):
        m = 2 if i == 127 else 4
        di = digits[i]
        R1_cur = R1.to_aff(R1.mul_H_j(k1[i]))
        R2_cur = K1.to_aff(K1.mul_H_j(k2[i]))
        for j in range(di + 1, m):
            ej = _h128(ctx, bytes([i, j]), R1.encode(R1_cur), K1.encode(R2_cur))
            s1[i][j] = _rand_mod(N_R1)
            s2[i][j] = _rand_mod(N_K1)
            P1 = C1[i] if j == 0 else R1.add(C1[i], R1.neg(G1s[j]))
            P2 = C2[i] if j == 0 else K1.add(C2[i], K1.neg(G2s[j]))
            R1_cur = R1.lin_step(s1[i][j], ej, P1)
            R2_cur = K1.lin_step(s2[i][j], ej, P2)
        tops.append(R1.encode(R1_cur) + K1.encode(R2_cur))

    e0 = _h128(ctx, *tops)
    for i in range(128):
        di = digits[i]
        ej = _h128(ctx, e0.to_bytes(16, "big"), bytes([i, 0]))
        for j in range(di):
            s1[i][j] = _rand_mod(N_R1)
            s2[i][j] = _rand_mod(N_K1)
            P1 = C1[i] if j == 0 else R1.add(C1[i], R1.neg(G1s[j]))
            P2 = C2[i] if j == 0 else K1.add(C2[i], K1.neg(G2s[j]))
            R1_cur = R1.lin_step(s1[i][j], ej, P1)
            R2_cur = K1.lin_step(s2[i][j], ej, P2)
            ej = _h128(ctx, bytes([i, j + 1]), R1.encode(R1_cur), K1.encode(R2_cur))
        s1[i][di] = (k1[i] + ej * r1[i]) % N_R1
        s2[i][di] = (k2[i] + ej * r2[i]) % N_K1

    out = bytearray([1, flip])
    out += R1.encode(Q1) + K1.encode(Q2)
    for i in range(128):
        out += R1.encode(C1[i]) + K1.encode(C2[i])
    out += e0.to_bytes(16, "big")
    for i in range(128):
        for j in range(2 if i == 127 else 4):
            out += s1[i][j].to_bytes(32, "big") + s2[i][j].to_bytes(32, "big")
    return bytes(out)


def verify_xcurve(proof_bytes, expected_q1=None):
    """Verify binary Cross-Curve DLEQ proof; return (Q1_bytes, Q2_bytes, bc1q_addr) or raise ValueError."""
    if len(proof_bytes) != 2 + 66 + 128 * 66 + 16 + 510 * 64:
        raise ValueError("wrong proof length")
    ver, flip = proof_bytes[0], proof_bytes[1]
    if ver != 1 or flip not in (0, 1):
        raise ValueError("bad proof header")
    Q1 = R1.decode(proof_bytes[2:35])
    Q2 = K1.decode(proof_bytes[35:68])
    if expected_q1 is not None and Q1 != expected_q1:
        raise ValueError("certificate P-256 public key does not match proof")
    off = 68
    C1, C2 = [], []
    for _ in range(128):
        C1.append(R1.decode(proof_bytes[off:off + 33]))
        C2.append(K1.decode(proof_bytes[off + 33:off + 66]))
        off += 66
    e0 = int.from_bytes(proof_bytes[off:off + 16], "big")
    off += 16

    T1 = R1.add(R1.mul(N_R1 - 1, R1.G), R1.neg(Q1)) if flip else Q1
    T2 = K1.add(K1.mul(N_R1 - 1, K1.G), K1.neg(Q2)) if flip else Q2
    acc1 = acc2 = None
    for i in range(127, -1, -1):
        if acc1 is not None:
            acc1 = R1.j_dbl(R1.j_dbl(acc1))
        if acc2 is not None:
            acc2 = K1.j_dbl(K1.j_dbl(acc2))
        acc1 = R1.j_add_aff(acc1, C1[i])
        acc2 = K1.j_add_aff(acc2, C2[i])
    if R1.to_aff(acc1) != T1 or K1.to_aff(acc2) != T2:
        raise ValueError("commitment sum mismatch")

    ctx_h = hashlib.sha256(b"k15-xcurve-dleq-v1" + bytes([flip]) + R1.encode(Q1) + K1.encode(Q2))
    for i in range(128):
        ctx_h.update(R1.encode(C1[i]))
        ctx_h.update(K1.encode(C2[i]))
    ctx = ctx_h.digest()

    nG1 = [None, R1.neg(R1.G), R1.neg(R1.mul(2, R1.G)), R1.neg(R1.mul(3, R1.G))]
    nG2 = [None, K1.neg(K1.G), K1.neg(K1.mul(2, K1.G)), K1.neg(K1.mul(3, K1.G))]
    tops = []
    for i in range(128):
        m = 2 if i == 127 else 4
        ej = _h128(ctx, e0.to_bytes(16, "big"), bytes([i, 0]))
        for j in range(m):
            s1_ij = int.from_bytes(proof_bytes[off:off + 32], "big")
            s2_ij = int.from_bytes(proof_bytes[off + 32:off + 64], "big")
            off += 64
            if s1_ij >= N_R1 or s2_ij >= N_K1:
                raise ValueError("scalar out of range")
            P1 = C1[i] if j == 0 else R1.add(C1[i], nG1[j])
            P2 = C2[i] if j == 0 else K1.add(C2[i], nG2[j])
            R1_cur = R1.lin_step(s1_ij, ej, P1)
            R2_cur = K1.lin_step(s2_ij, ej, P2)
            if R1_cur is None or R2_cur is None:
                raise ValueError("infinity in ring")
            if j + 1 < m:
                ej = _h128(ctx, bytes([i, j + 1]), R1.encode(R1_cur), K1.encode(R2_cur))
        tops.append(R1.encode(R1_cur) + K1.encode(R2_cur))
    if _h128(ctx, *tops) != e0:
        raise ValueError("Borromean ring check failed")
    q2_enc = K1.encode(Q2)
    return R1.encode(Q1), q2_enc, address_from_pubkey(q2_enc)


def format_proof(raw, addr):
    b64 = base64.b64encode(raw).decode()
    lines = [f"# k15 cross-curve DLEQ proof (secp256r1 <-> secp256k1) for {addr}"]
    lines += [b64[i:i + 76] for i in range(0, len(b64), 76)]
    return "\n".join(lines) + "\n"


def parse_proof(text):
    b64 = "".join(ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("#"))
    return base64.b64decode(b64, validate=True)


# --- X.509 DER P-256 SubjectPublicKeyInfo parser (stdlib only, for --verify) ---

def _der_tlv(buf, pos):
    tag = buf[pos]
    pos += 1
    b = buf[pos]
    pos += 1
    if b < 128:
        ln = b
    else:
        n = b & 0x7F
        ln = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
    return tag, buf[pos:pos + ln], pos + ln


def extract_p256_from_der_cert(der):
    """Extract (X, Y) from an X.509 DER certificate's SubjectPublicKeyInfo."""
    tag, cert_body, _ = _der_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("not DER SEQUENCE")
    tag, tbs, _ = _der_tlv(cert_body, 0)
    if tag != 0x30:
        raise ValueError("bad TBSCertificate")
    pos = 0
    tag, _, next_pos = _der_tlv(tbs, pos)
    if tag == 0xA0:  # explicit [0] version
        pos = next_pos
    for _ in range(5):  # serial, sigAlg, issuer, validity, subject
        _, _, pos = _der_tlv(tbs, pos)
    tag, spki, _ = _der_tlv(tbs, pos)
    p256_alg = bytes.fromhex("301306072a8648ce3d020106082a8648ce3d030107")
    if tag != 0x30 or not spki.startswith(p256_alg + b"\x03\x42\x00\x04") or len(spki) != 89:
        raise ValueError("certificate SubjectPublicKeyInfo is not uncompressed ECDSA P-256")
    pt = spki[-64:]
    Q = (int.from_bytes(pt[:32], "big"), int.from_bytes(pt[32:], "big"))
    if not R1.on(Q):
        raise ValueError("certificate key not on P-256")
    return Q


def fetch_cert_der(target):
    if os.path.exists(target):
        pem = open(target, encoding="utf-8").read()
        lines = []
        in_cert = False
        for ln in pem.splitlines():
            if "BEGIN CERTIFICATE" in ln:
                in_cert = True
            elif "END CERTIFICATE" in ln:
                break
            elif in_cert:
                lines.append(ln.strip())
        return base64.b64decode("".join(lines)), None
    host, _, port_s = target.partition(":")
    port = int(port_s) if port_s else 443
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            info = tls.getpeercert()
            return tls.getpeercert(binary_form=True), info.get("notAfter") if info else None


# --- Key writing (uses cryptography, only for --gen / --restore --out / reading PEM keys) ---

def write_secret(path, data):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def save_p256_key_and_csr(d, cert_dir, name=None, sans=()):
    import ipaddress
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.derive_private_key(d, ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    os.makedirs(cert_dir, exist_ok=True)
    os.chmod(cert_dir, 0o700)
    write_secret(os.path.join(cert_dir, "server.key"), pem)
    if name:
        all_names = [name] + [s for s in sans if s != name]
        gns = []
        for n in all_names:
            try:
                gns.append(x509.IPAddress(ipaddress.ip_address(n)))
            except ValueError:
                gns.append(x509.DNSName(n))
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, name)]))
            .add_extension(x509.SubjectAlternativeName(gns), critical=False)
            .sign(key, hashes.SHA256())
        )
        with open(os.path.join(cert_dir, "csr.pem"), "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))


def read_pem_scalar(path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    with open(path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        sys.exit("bounty.py: not an elliptic-curve key")
    d = key.private_numbers().private_value
    if not 0 < d < N_R1:
        sys.exit("bounty.py: this key is not below P-256's order")
    return d


def run_tests():
    assert pubkey(1).hex() == "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    assert address(1) == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    assert wif(1) == "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"

    # Official BIP-84 vector (m/84'/0'/0'/0/0)
    ent, w12 = words_to_entropy("abandon " * 11 + "about")
    assert entropy_to_words(ent) == w12
    d84 = bip84_scalar(w12)
    assert pubkey(d84).hex() == "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"
    assert address(d84) == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
    assert wif(d84) == "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d"

    # Cross-curve proof: both flip=0 (< 2^255) and flip=1 (>= 2^255), plus soundness rejection
    for d_test in (d84 & ((1 << 255) - 1), N_R1 - 42):
        prf = prove_xcurve(d_test)
        q1_b, q2_b, addr = verify_xcurve(prf, R1.mul(d_test, R1.G))
        assert addr == address(d_test) and q2_b == pubkey(d_test)
        bad = bytearray(prf)
        bad[300] ^= 1
        try:
            verify_xcurve(bytes(bad))
            raise AssertionError("accepted corrupted proof")
        except ValueError:
            pass
        try:
            verify_xcurve(prf, R1.mul(d_test - 1, R1.G))
            raise AssertionError("accepted mismatched certificate key")
        except ValueError:
            pass
    print("bounty.py: ok")


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        sys.exit(__doc__)
    if args == ["--test"]:
        run_tests()
        return

    if args[0] == "--gen":
        if len(args) < 2:
            sys.exit("usage: tools/bounty.py --gen CERT [-n NAME] [--san NAME]...")
        cert_dir = args[1]
        name, sans, i = None, [], 2
        while i < len(args):
            if args[i] == "-n" and i + 1 < len(args):
                name = args[i + 1]
                i += 2
            elif args[i] == "--san" and i + 1 < len(args):
                sans.append(args[i + 1])
                i += 2
            else:
                sys.exit(f"bounty.py --gen: unknown arg '{args[i]}'")
        while True:
            words = entropy_to_words(os.urandom(32))
            d = bip84_scalar(words)
            if 0 < d < (1 << 255):
                break
        save_p256_key_and_csr(d, cert_dir, name, sans)
        addr = address(d)
        raw_proof = prove_xcurve(d)
        with open(os.path.join(cert_dir, "bounty.proof"), "w", encoding="utf-8") as f:
            f.write(format_proof(raw_proof, addr))
        print("Write down these 24 BIP-39 words on paper (never stored on disk):")
        for row in range(6):
            cols = [f"{row + 1 + 6 * c:2d}. {words[row + 6 * c]:<10s}" for c in range(4)]
            print("  " + "  ".join(cols).rstrip())
        print(f"\nBitcoin address (m/84'/0'/0'/0/0): {addr}")
        print(f"Wrote {cert_dir}/server.key, {cert_dir}/bounty.proof" + (f", {cert_dir}/csr.pem" if name else ""))
        return

    if args[0] == "--restore":
        want_wif = "--wif" in args
        out_key = None
        i = 1
        while i < len(args):
            if args[i] == "--wif":
                i += 1
            elif args[i] == "--out" and i + 1 < len(args):
                out_key = args[i + 1]
                i += 2
            else:
                sys.exit(f"bounty.py --restore: unknown arg '{args[i]}'")
        phrase = getpass.getpass("Enter 24 BIP-39 words: ") if sys.stdin.isatty() else sys.stdin.read()
        _, toks = words_to_entropy(phrase)
        d = bip84_scalar(toks)
        if not 0 < d < N_R1:
            sys.exit("bounty.py: derived key is not below P-256's order")
        if out_key:
            save_p256_key_and_csr(d, os.path.dirname(os.path.abspath(out_key)) or ".")
            if os.path.basename(out_key) != "server.key":
                os.replace(os.path.join(os.path.dirname(os.path.abspath(out_key)) or ".", "server.key"), out_key)
        print(wif(d) if want_wif else address(d))
        return

    if args[0] == "--prove":
        if len(args) not in (2, 3):
            sys.exit("usage: tools/bounty.py --prove CERT/server.key [OUT_PROOF]")
        d = read_pem_scalar(args[1])
        out_path = args[2] if len(args) == 3 else "bounty.proof"
        addr = address(d)
        raw_proof = prove_xcurve(d)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(format_proof(raw_proof, addr))
        print(f"{addr} -> {out_path}")
        return

    if args[0] == "--verify":
        target = args[1] if len(args) >= 2 else "15kb.org"
        default_proof = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bounty.proof")
        proof_path = args[2] if len(args) >= 3 else default_proof
        if os.path.exists(proof_path):
            proof_text = open(proof_path, encoding="utf-8").read()
        elif len(args) < 3:
            import urllib.request
            with urllib.request.urlopen("https://raw.githubusercontent.com/FileSherlock/k15/bounty/bounty.proof", timeout=10) as resp:
                proof_text = resp.read().decode("utf-8")
        else:
            sys.exit(f"bounty.py: proof file not found: {proof_path}")
        der, not_after = fetch_cert_der(target)
        cert_q1 = extract_p256_from_der_cert(der)
        q1_b, q2_b, addr = verify_xcurve(parse_proof(proof_text), cert_q1)
        print(f"target:      {target}" + (f" (expires {not_after})" if not_after else ""))
        print(f"P-256 key:   {q1_b.hex()}")
        print(f"secp256k1:   {q2_b.hex()}")
        print(f"BTC address: {addr}")
        print("verified: the TLS certificate's P-256 private key is the private key of this Bitcoin wallet.")
        return

    want_wif = "--wif" in args
    paths = [a for a in args if a != "--wif"]
    if len(paths) != 1 or paths[0].startswith("-"):
        sys.exit(__doc__)
    d = read_pem_scalar(paths[0])
    print(wif(d) if want_wif else address(d))


if __name__ == "__main__":
    main()
