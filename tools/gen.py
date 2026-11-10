#!/usr/bin/env python3
"""Build-time generator: certificate chain, signing key, curve programs, HTTP response.

Usage: gen.py www/index.html build/

The server's identity comes from cert/ (or the directory $CERT names):
  cert/server.key   its private key (PEM, must be ECDSA P-256)
  cert/server.pem   its certificate, followed by any intermediates (PEM)
  cert/ca.pem       the root to trust in tests, if it is not a public one
If they are missing, a private CA (cert/ca.pem: there is no CA key, see make_identity) and
the smallest leaf we found that curl, Chrome and Firefox accept are made, for NAME (default
127.0.0.1; an IP address or a DNS name). To serve with a real certificate instead, drop its two files into cert/.
Nothing here ever renews: the certificate is baked into the image.

Outputs: build/gen.inc (TLS blobs), build/ec.inc (curve programs), build/regs.inc
(curve constants and the private key: the image is a secret), build/ca.pem (what clients must trust; empty if the
chain is a real one) and build/name (the host name to test with).
"""
import ipaddress
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ec as curve  # noqa: E402

CERT = os.environ.get("CERT", "cert")


def tlv(tag, body):
    n = len(body)
    ln = bytes([n]) if n < 128 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + ln + body


def put(path, data):
    with open(path, "wb") as f:
        f.write(data)


def private_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def ec_add(P, Q):
    """P-256 points in affine coordinates (None = infinity)."""
    p = curve.P256
    if P is None or Q is None:
        return P or Q
    if P[0] == Q[0]:
        if (P[1] + Q[1]) % p == 0:
            return None
        lam = (3 * P[0] * P[0] - 3) * pow(2 * P[1], -1, p) % p
    else:
        lam = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, p) % p
    x = (lam * lam - P[0] - Q[0]) % p
    return x, (lam * (P[0] - x) - P[1]) % p


def ec_mul(k, P):
    acc = None
    while k:
        if k & 1:
            acc = ec_add(acc, P)
        P, k = ec_add(P, P), k >> 1
    return acc


ECDSA_SHA256 = tlv(0x30, tlv(0x06, bytes.fromhex("2a8648ce3d040302")))
EC_P256 = tlv(0x30, tlv(0x06, bytes.fromhex("2a8648ce3d0201")) + tlv(0x06, bytes.fromhex("2a8648ce3d030107")))
VALIDITY = tlv(0x30, tlv(0x17, b"260101000000Z") + tlv(0x17, b"491231000000Z"))


def make_identity(name):
    """A leaf certificate for `name` and the CA that signed it: cert/server.key, .pem, ca.pem.

    The leaf is the smallest X.509 we found that curl, Chrome and Firefox accept under a
    trusted CA: v3 (the subjectAltName needs it), empty subject, one extension, and an 8-byte
    signature. The last works because the CA signs nothing else, so we may pick the signature
    first and the CA's key second: take the curve point R with the smallest x coordinate as
    the nonce point, so r = x(R) is tiny, set s = 1, and solve the verification equation
    R = (z G + r Q) / s for the CA's public key Q = (R - z G) / r. That is a perfectly valid
    ECDSA signature under Q. Nobody knows log R, so nobody (us included) knows Q's private
    key: this CA can never sign a second certificate, which makes it harmless to trust.
    (Its own self-signature is a dummy for the same reason; no client checks a trust
    anchor's.) LEAF=option,... tries variants of the leaf.
    """
    opt = os.environ.get("LEAF", "").split(",")
    key = ec.generate_private_key(ec.SECP256R1())
    # (a compressed point would save 32 bytes: curl takes it, Firefox says
    # SEC_ERROR_UNSUPPORTED_EC_POINT_FORM once the chain is trusted)
    point = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
                                          if "compressed" in opt else serialization.PublicFormat.UncompressedPoint)
    spki = tlv(0x30, EC_P256 + tlv(0x03, b"\x00" + point))
    try:
        gn = tlv(0x87, ipaddress.ip_address(name).packed)
    except ValueError:
        gn = tlv(0x82, name.encode())
    # critical, as RFC 5280 wants with an empty subject (Chrome: INVALID otherwise)
    san = tlv(0x30, tlv(0x06, b"\x55\x1d\x11") + (b"" if "noncritical" in opt else tlv(0x01, b"\xff"))
              + tlv(0x04, tlv(0x30, gn)))
    subject = tlv(0x30, tlv(0x31, tlv(0x30, tlv(0x06, b"\x55\x04\x03") + tlv(0x0c, b"x")))) if "subject" in opt else tlv(0x30, b"")
    # The CA's name: one attribute, OID 2.5.4 = "". (An empty name: curl and Firefox refuse,
    # MOZILLA_PKIX_ERROR_EMPTY_ISSUER_NAME. Firefox calls a 1-byte OID bad DER.)
    ca_name = tlv(0x30, tlv(0x31, tlv(0x30, tlv(0x06, b"\x55\x04") + tlv(0x13, b""))))
    tbs = tlv(0x30, tlv(0xa0, tlv(0x02, b"\x02")) + tlv(0x02, b"\x01") + ECDSA_SHA256
              + ca_name + VALIDITY + subject + spki + tlv(0xa3, tlv(0x30, san)))

    p, n = curve.P256, curve.N256
    h = hashes.Hash(hashes.SHA256())
    h.update(tbs)
    z = int.from_bytes(h.finalize(), "big")
    r = 1
    while pow((r ** 3 - 3 * r + curve.B256) % p, (p - 1) // 2, p) != 1:
        r += 1
    R = (r, pow((r ** 3 - 3 * r + curve.B256) % p, (p + 1) // 4, p))
    Q = ec_mul(pow(r, -1, n), ec_add(R, ec_mul(n - z % n, (curve.GX256, curve.GY256))))
    sig = tlv(0x30, tlv(0x02, bytes([r])) + tlv(0x02, b"\x01"))
    ca_pub = ec.EllipticCurvePublicNumbers(Q[0], Q[1], ec.SECP256R1()).public_key()
    ca_pub.verify(sig, tbs, ec.ECDSA(hashes.SHA256()))  # raises if the trick went wrong
    leaf = tlv(0x30, tbs + ECDSA_SHA256 + tlv(0x03, b"\x00" + sig))

    # the CA: an ordinary root certificate around Q
    ca_spki = tlv(0x30, EC_P256 + tlv(0x03, b"\x00" + ca_pub.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)))
    ca_ext = (tlv(0x30, tlv(0x06, b"\x55\x1d\x13") + tlv(0x01, b"\xff") + tlv(0x04, tlv(0x30, tlv(0x01, b"\xff"))))
              + tlv(0x30, tlv(0x06, b"\x55\x1d\x0f") + tlv(0x01, b"\xff") + tlv(0x04, tlv(0x03, b"\x01\x06"))))
    ca_tbs = tlv(0x30, tlv(0xa0, tlv(0x02, b"\x02")) + tlv(0x02, os.urandom(8).hex().encode()[:8]) + ECDSA_SHA256
                 + ca_name + VALIDITY + ca_name + ca_spki + tlv(0xa3, tlv(0x30, ca_ext)))
    ca = tlv(0x30, ca_tbs + ECDSA_SHA256 + tlv(0x03, b"\x00" + tlv(0x30, tlv(0x02, b"\x01") + tlv(0x02, b"\x01"))))

    os.makedirs(CERT, exist_ok=True)
    put(f"{CERT}/server.key", private_pem(key))
    for path, der in ((f"{CERT}/server.pem", leaf), (f"{CERT}/ca.pem", ca)):
        put(path, x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM))


def db(name, data):
    return f"{name}: db {','.join(str(b) for b in data)}\n{name}_LEN equ $ - {name}\n"


def le(v, n=32):
    return v.to_bytes(n, "little")


def main(html_path, out):
    if not (os.path.exists(f"{CERT}/server.key") and os.path.exists(f"{CERT}/server.pem")):
        make_identity(os.environ.get("NAME", "127.0.0.1"))
    key = serialization.load_pem_private_key(open(f"{CERT}/server.key", "rb").read(), None)
    chain = x509.load_pem_x509_certificates(open(f"{CERT}/server.pem", "rb").read())
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
        sys.exit("gen.py: cert/server.key must be an ECDSA P-256 key")
    if key.public_key().public_numbers() != chain[0].public_key().public_numbers():
        sys.exit("gen.py: cert/server.key does not match the first certificate in cert/server.pem")
    d = key.private_numbers().private_value

    # what to trust and what to call the server when testing
    private = os.path.exists(f"{CERT}/ca.pem") and chain[-1].issuer == x509.load_pem_x509_certificate(
        open(f"{CERT}/ca.pem", "rb").read()).subject
    put(f"{out}/ca.pem", open(f"{CERT}/ca.pem", "rb").read() if private else b"")
    san = chain[0].extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    names = [str(n.value) for n in san]
    put(f"{out}/name", (names[0] if names else "").encode())

    # EncryptedExtensions (empty) + Certificate message, as one constant blob
    ee = bytes([8, 0, 0, 2, 0, 0])
    entries = b""
    for c in chain:
        der = c.public_bytes(serialization.Encoding.DER)
        entries += len(der).to_bytes(3, "big") + der + b"\0\0"
    body = b"\0" + len(entries).to_bytes(3, "big") + entries
    certmsg = bytes([11]) + len(body).to_bytes(3, "big") + body

    html = open(html_path, "rb").read()
    resp = b"HTTP/1.1 200\nContent-Length:%d\n\n" % len(html) + html  # bare LFs: all clients cope
    resp += b"\x17"  # TLS inner content type (application_data)

    # CertificateVerify up to r: r and s are always plain 32-byte INTEGERs (the server grinds)
    cvt = bytes([0x0f, 0, 0, 74, 4, 3, 0, 70, 0x30, 68, 2, 32])
    with open(f"{out}/conf.inc", "w") as f:  # what the code needs to know before it is assembled
        f.write(f"; generated by tools/gen.py\n%assign CHAIN_LEN {len(ee + certmsg)}\n")
    with open(f"{out}/gen.inc", "w") as f:
        f.write("; generated by tools/gen.py\n")
        for name, data in (("EECERT", ee + certmsg), ("CVT", cvt), ("RESP", resp)):
            f.write(db(name, data))

    R = curve.R
    with open(f"{out}/ec.inc", "w") as f:
        f.write("; generated by tools/gen.py from tools/ec.py: SECRET (holds the private key)\n")
        for name in ("INIT25519", "STEP25519", "INIT256", "STEP256", "FIN", "SIGN"):
            f.write(db(name, curve.PROGRAMS[name]))  # (each STEP must follow its INIT)
    # the constant registers GX, B4, D and ONE (9 limbs each; ONE's zeros are not stored),
    # copied to the register file at boot
    regs = b"".join(le(v, 36) for v in (curve.GX256 * R % curve.P256, 4 * curve.B256 * R % curve.P256,
                                        d * R % curve.N256)) + b"\x01"
    # then what boot can't compute of the group order n: its low half and -1/n mod 2^32
    with open(f"{out}/regs.inc", "w") as f:
        f.write("; generated by tools/gen.py: SECRET (holds the private key)\n" + db("REGC", regs)
                + db("NLOW", le(curve.N256 % (1 << 128), 16) + le(curve.mprime(curve.N256), 4)))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
