#!/usr/bin/env python3
"""Build-time generator: certificate chain, signing key, curve programs, HTTP response.

Usage: gen.py www/index.html build/

The server's identity comes from cert/:
  cert/server.key   its private key (PEM, must be ECDSA P-256)
  cert/server.pem   its certificate, followed by any intermediates (PEM)
If they are missing, a private CA (cert/ca.key, cert/ca.pem) and the smallest leaf we found
that curl, Chrome and Firefox accept are made, for NAME (default 127.0.0.1; an IP address or
a DNS name). To serve with a real certificate instead, drop its two files into cert/.
Nothing here ever renews: the certificate is baked into the image.

Outputs: build/gen.inc (TLS blobs), build/ec.inc (curve programs and constants, including
the private key: the image is a secret), build/ca.pem (what clients must trust; empty if the
chain is a real one) and build/name (the host name to test with).
"""
import datetime
import ipaddress
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ec as curve  # noqa: E402

CERT = "cert"


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


def make_ca():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "k2")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(datetime.datetime(2026, 1, 1))
            .not_valid_after(datetime.datetime(2049, 12, 31))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False),
                           critical=True)
            .sign(key, hashes.SHA256()))
    os.makedirs(CERT, exist_ok=True)
    put(f"{CERT}/ca.key", private_pem(key))
    put(f"{CERT}/ca.pem", cert.public_bytes(serialization.Encoding.PEM))
    return key, cert


def make_leaf(ca_key, ca_cert, name):
    """Smallest X.509 we found that all three clients accept under a trusted CA: v3 (the
    subjectAltName needs it), empty subject, compressed EC point, one extension."""
    key = ec.generate_private_key(ec.SECP256R1())
    sigalg = tlv(0x30, tlv(0x06, bytes.fromhex("2a8648ce3d040302")))  # ecdsa-with-SHA256
    algid = tlv(0x30, tlv(0x06, bytes.fromhex("2a8648ce3d0201")) + tlv(0x06, bytes.fromhex("2a8648ce3d030107")))
    point = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    spki = tlv(0x30, algid + tlv(0x03, b"\x00" + point))
    try:
        gn = tlv(0x87, ipaddress.ip_address(name).packed)
    except ValueError:
        gn = tlv(0x82, name.encode())
    # critical, as RFC 5280 wants with an empty subject
    san = tlv(0x30, tlv(0x06, b"\x55\x1d\x11") + tlv(0x01, b"\xff") + tlv(0x04, tlv(0x30, gn)))
    validity = tlv(0x30, tlv(0x17, b"260101000000Z") + tlv(0x17, b"491231000000Z"))
    tbs = tlv(0x30, tlv(0xa0, tlv(0x02, b"\x02")) + tlv(0x02, b"\x01") + sigalg
              + ca_cert.subject.public_bytes() + validity + tlv(0x30, b"") + spki
              + tlv(0xa3, tlv(0x30, san)))
    # ECDSA signatures vary in length: take a short one (r and s without padding bytes)
    while True:
        sig = ca_key.sign(tbs, ec.ECDSA(hashes.SHA256()))
        if len(sig) <= 70 - int(os.environ.get("GRIND", "1")):
            break
    der = tlv(0x30, tbs + sigalg + tlv(0x03, b"\x00" + sig))
    cert = x509.load_der_x509_certificate(der)
    put(f"{CERT}/server.key", private_pem(key))
    put(f"{CERT}/server.pem", cert.public_bytes(serialization.Encoding.PEM))


def db(name, data):
    return f"{name}: db {','.join(str(b) for b in data)}\n{name}_LEN equ $ - {name}\n"


def le(v, n=32):
    return v.to_bytes(n, "little")


def main(html_path, out):
    if not (os.path.exists(f"{CERT}/server.key") and os.path.exists(f"{CERT}/server.pem")):
        if os.path.exists(f"{CERT}/ca.key"):
            ca_key = serialization.load_pem_private_key(open(f"{CERT}/ca.key", "rb").read(), None)
            ca_cert = x509.load_pem_x509_certificate(open(f"{CERT}/ca.pem", "rb").read())
        else:
            ca_key, ca_cert = make_ca()
        make_leaf(ca_key, ca_cert, os.environ.get("NAME", "127.0.0.1"))
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
    with open(f"{out}/gen.inc", "w") as f:
        f.write("; generated by tools/gen.py\n")
        for name, data in (("EECERT", ee + certmsg), ("CVT", cvt), ("RESP", resp)):
            f.write(db(name, data))

    R = curve.R
    with open(f"{out}/ec.inc", "w") as f:
        f.write("; generated by tools/gen.py from tools/ec.py: SECRET (holds the private key)\n")
        for name in ("INIT25519", "STEP25519", "INIT256", "STEP256", "FIN", "SIGN"):
            f.write(db(name, curve.PROGRAMS[name]))  # (each STEP must follow its INIT)
        # moduli: m | 0 | -1/m mod 2^32, each with a zero byte in front
        for name, m in (("M25519", curve.P25519), ("MN", curve.N256), ("MP256", curve.P256)):
            f.write("        db 0\n" + db(name, le(m) + le(0, 4) + le(curve.mprime(m), 4)))
        regs = b"".join(le(v, 36) for v in (curve.GX256 * R % curve.P256, 4 * curve.B256 * R % curve.P256,
                                            d * R % curve.N256)) + b"\x01"
        f.write(db("REGS", regs))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
