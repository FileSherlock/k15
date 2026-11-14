#!/usr/bin/env python3
"""The Bitcoin address that a certificate's private key also is the key of.

    tools/bounty.py CERT/server.key          the address (public: this is what gets paid)
    tools/bounty.py CERT/server.key --wif    the key as a wallet imports it (secret)
    tools/bounty.py --test                   the known answers for the key 1

A P-256 private key is a number below P-256's order, which is below secp256k1's: so it
is a Bitcoin private key as well. Money on its address belongs to whoever has the
certificate's key, and taking it proves having had it. Nothing here touches a network.
The address is native SegWit (P2WPKH, bc1q...) of the compressed public key.

`k15 renew` makes a new key each time: the address changes with the certificate, and
what is on the old one has to be moved (the old key stays in CERT/old until the next).
"""
import hashlib
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

N_K1 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def pubkey(d):
    """The compressed secp256k1 public key of d, 33 bytes."""
    return ec.derive_private_key(d, ec.SECP256K1()).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)


def polymod(values):
    c = 1
    for v in values:
        top = c >> 25
        c = (c & 0x1FFFFFF) << 5 ^ v
        for i, g in enumerate((0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)):
            if top >> i & 1:
                c ^= g
    return c


def address(d, hrp="bc"):
    """bech32 of witness version 0 and hash160 of the public key (BIP 173)."""
    h = hashlib.new("ripemd160", hashlib.sha256(pubkey(d)).digest()).digest()
    bits = "".join(f"{b:08b}" for b in h) + "0000"      # 160 bits, padded to 5 x 32
    data = [0] + [int(bits[i:i + 5], 2) for i in range(0, 160, 5)]
    exp = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    check = polymod(exp + data + [0] * 6) ^ 1
    data += [check >> 5 * (5 - i) & 31 for i in range(6)]
    return hrp + "1" + "".join(B32[v] for v in data)


def wif(d):
    """The key for import: base58check of 0x80, the key, 0x01 (compressed public key)."""
    raw = b"\x80" + d.to_bytes(32, "big") + b"\x01"
    n = int.from_bytes(raw + hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4], "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    return s


def main():
    args = sys.argv[1:]
    if args == ["--test"]:
        assert pubkey(1).hex() == "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        assert address(1) == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"       # BIP 173's example
        assert wif(1) == "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
        print("bounty.py: ok")
        return
    want_wif = "--wif" in args
    paths = [a for a in args if a != "--wif"]
    if len(paths) != 1 or paths[0].startswith("-"):
        sys.exit(__doc__)
    with open(paths[0], "rb") as f:
        key = serialization.load_pem_private_key(f.read(), None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        sys.exit("bounty.py: not an elliptic-curve key")
    d = key.private_numbers().private_value
    if not 0 < d < N_K1:
        sys.exit("bounty.py: this key is not below secp256k1's order")
    print(wif(d) if want_wif else address(d))


if __name__ == "__main__":
    main()
