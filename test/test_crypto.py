#!/usr/bin/env python3
"""Check the asm crypto (run via build/test_asm) against pyca/cryptography."""
import hashlib
import os
import hmac
import subprocess
import sys

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

m = bytes((i * 7 + 3) & 255 for i in range(2000))
exp = {}
for n in (0, 3, 55, 56, 63, 64, 119, 1000, 1999):
    exp[f"sha{n}"] = hashlib.sha256(m[:n]).digest()
exp["hmac"] = hmac.new(m[:32], m[32:82], hashlib.sha256).digest()
info = b"\x00\x20" + b"\x0dtls13 derived" + b"\x20" + m[100:132] + b"\x01"
exp["expand"] = hmac.new(m[:32], info, hashlib.sha256).digest()
sk = X25519PrivateKey.from_private_bytes(bytes(32))
key, iv = m[300:332], m[400:412]
for i, n in enumerate((1, 100, 1500)):
    seq = i * 77
    nonce = iv[:4] + bytes(a ^ b for a, b in zip(iv[4:], seq.to_bytes(8, "big")))
    hdr = bytes([0x17, 3, 3]) + (n + 16).to_bytes(2, "big")
    exp[f"seal{n}_{seq}"] = hdr + ChaCha20Poly1305(key).encrypt(nonce, m[:n], hdr)

got = {}
for line in subprocess.run([sys.argv[1]], capture_output=True, text=True, check=True).stdout.splitlines():
    tag, val = line.split()
    got[tag] = bytes.fromhex(val)

bad = 0
for tag, want in exp.items():
    ok = got.get(tag) == want
    bad += not ok
    print(("ok  " if ok else "FAIL"), tag)

# X25519: our scalar is unclamped, so check that the peer (whose private key is all zeros,
# clamped) derives the same secret from our share
for i in range(4):
    pub, shared = got[f"xpub{i}"], got[f"xshared{i}"]
    if i == 2:      # our scalar 0: nothing times anything (u of the neutral point is 0 here)
        ok = pub == bytes(32) and shared == bytes(32)
    else:
        ok = sk.exchange(X25519PublicKey.from_public_bytes(pub)) == shared
    bad += not ok
    print(("ok  " if ok else "FAIL"), f"x25519_{i}")

# ECDSA: (r, s) must verify under the certificate's key
pub = x509.load_pem_x509_certificates(open(os.path.join(os.environ.get("CERT", "cert"), "server.pem"), "rb").read())[0].public_key()
for i in range(6):
    sig = got[f"sig{i}"]
    z, r, s = sig[:32], int.from_bytes(sig[32:64], "little"), int.from_bytes(sig[64:], "little")
    try:
        pub.verify(utils.encode_dss_signature(r, s), z, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        ok = True
    except (InvalidSignature, ValueError):
        ok = False
    bad += not ok
    print(("ok  " if ok else "FAIL"), f"ecdsa{i}")
sys.exit(1 if bad else 0)
