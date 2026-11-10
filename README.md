# k2

k2 is a 3,364-byte bootable x86 "operating system" that serves a static web page over HTTPS
(TLS 1.3), securely. It boots in QEMU, drives an NE2000 network card, speaks just enough TCP,
and does the whole TLS 1.3 handshake itself: X25519, ECDSA P-256, ChaCha20-Poly1305,
SHA-256 / HKDF, all hand-written in assembly. curl, Chrome and Firefox load the page with no
certificate warning once they trust its CA, or with none at all if you bake in a real
certificate.

It is the secure sibling of k1 (2,332 bytes), which got that small by having no security at
all. The goal is the same, connections per KiB: `./score.sh` opens TLS connections until the
client runs out of ports, keeps them all open, and checks that every one serves the page.

## What is secure, and what is not there

- Every handshake uses a fresh X25519 secret and a fresh ECDSA nonce from `rdrand`, and a
  real ECDSA P-256 signature. Sessions have forward secrecy.
- Clients verify a real chain and the server's name. The tests never bypass a certificate
  error.
- A client record is answered only if its authentication tag verifies.
- The curve arithmetic has no secret-dependent branches or memory accesses.
- The certificate never renews: it is baked in when the image is built. The image contains
  the server's private key, so the image is a secret.

It still takes shortcuts that a general-purpose TLS stack must not: one cipher suite, one
key-exchange group, no alerts, no session resumption, requests must fit one TCP segment, and
the HTTP response is a constant. `CLAUDE.md` lists them all.

## Try it

Needs `nasm`, `python3` with `cryptography`, `qemu-system-x86_64` and `curl`.

```bash
make                 # -> build/os.bin, and on the first run cert/ (a private CA and a leaf)
./measure.sh         # boot it, fetch the page with curl (verifying), print the size
./browsers.sh        # Firefox and Chrome, trusting the CA in throwaway profiles
./score.sh           # hold as many connections as the client has ports
```

Or by hand:

```bash
qemu-system-x86_64 -nodefaults -display none -cpu max -m 16 -kernel build/os.bin \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:8443-:443 -device ne2k_isa,netdev=n0
curl --cacert build/ca.pem https://127.0.0.1:8443/
```

Change `www/index.html` to serve something else, `NAME=example.org make` (after deleting
`cert/server.*`) to make the certificate for another name.

## The certificate

By default the build makes its own CA and a 210-byte leaf for 127.0.0.1. That CA has no
private key: the leaf's signature was picked first (8 bytes) and the CA's public key was
computed to fit it. Trusting `cert/ca.pem` is therefore harmless: it can never sign another
certificate.

To serve with a real certificate, put `server.key` (ECDSA P-256) and `server.pem` (leaf, then
intermediates) into `cert/`, or into another directory:

```bash
python3 tools/mkchain.py cert-real          # a realistic test chain; or use your own files
make B=build-real CERT=cert-real            # 4,833 bytes with that 1.6 KB chain
B=build-real CERT=cert-real ./measure.sh
```

## How it stays small

- One 256-bit Montgomery multiplication serves X25519, P-256 and the arithmetic mod the group
  order. Values are never reduced or compared: the bounds are proved in `tools/ec.py`.
- The curve formulas are not code but 2-byte operations for a 16-register machine: the
  X25519 step is 39 bytes, the P-256 step 65.
- Both ladders, all inversions and the signature share one driver, one exponentiation and one
  set of temporaries. The moduli are built at boot.
- Signatures are retried until they have a fixed-size encoding, so the handshake message is a
  template.
- Everything k1 did that did not cost security: SHA-256 constants computed at boot, the
  table-driven Poly1305, replies built in place in the received frame, one 128-byte slot per
  connection.

## Tests

- `make test` checks the asm crypto against pyca/cryptography (needs 32-bit gcc support) and
  runs the Python model of the curve code.
- `./browsers.sh` loads the page in headless Firefox and Chrome.
- `tools/load.py` has `burst K` (K clients connecting at the same moment), `seq N` and `ka N`.
