# Goal: most simultaneous *secure* HTTPS connections per KiB of bootable x86 image

Maximize the score from `./score.sh`: connections / (size of `build/os.bin` / 1024), where
connections = the most TLS connections that were open at the same time and all served the page,
every one of them verifying the certificate. `./measure.sh` must keep passing.

This is k1 (`../sizecodeing-os`, 2,332 bytes, deliberately insecure) with security as a
requirement. Correctness for real clients (curl, Chrome, Firefox) matters as before, but now
without any certificate bypass: they must accept the chain and the name.

## What "secure" means here
A standard validating client gets server authentication, confidentiality, integrity and
forward secrecy against a network attacker, and no packet makes the server leak its key:
- a fresh X25519 secret and a fresh ECDSA nonce per handshake, from `rdrand`
- a real ECDSA P-256 signature under a key that only exists in the image
- a certificate chain clients verify (private CA by default, or a real chain dropped in)
- a client record gets an answer only if its AEAD tag verifies (next sequence number)
- the curve arithmetic has no secret-dependent branches or memory accesses
- attacker-controlled lengths are bounded (ClientHello size, record sizes)
The image contains the private key: `build/` and `cert/` are secrets and are not in git.

## Commands
- `make` assembles `src/os.asm` into `build/os.bin` (flat multiboot image for `qemu -kernel`)
  and a listing `build/os.lst`; `python3 tools/sizes.py build/os.lst` = bytes per routine.
  The first build makes `cert/` (see below). `make B=dir CERT=dir` builds a second image from
  another identity; the scripts take the same `B` and `CERT` from the environment.
- `./measure.sh` builds, boots it in QEMU (TCG, no KVM here), fetches it with curl (chain and
  name verified, fresh connections + keep-alive, and a check that curl refuses without our
  CA), prints PASS + size + largest routines
- `./browsers.sh` checks Firefox and Chrome with our CA as a trusted root in throwaway
  profiles (no exceptions, no `--ignore-certificate-errors`; Chrome's net-log must show no
  certificate error flags) and that Chrome refuses without the CA. Run after any
  TLS/cert/TCP/HTTP change.
- `./score.sh [image] [max]` boots the image and runs `tools/load.py hold` (same test as k1:
  every unprivileged client port, 4 handshakes in flight, fetches over every connection at
  64, 128, 256, ...). `PORTS=auto` keeps to the ephemeral range (28,232 connections).
  `tools/load.py` also has `burst K`, `seq N` (handshake rate) and `ka N` (keep-alive).
- `make test` checks the asm crypto (`src/os.asm` built with `-DHOST`, driven by
  `test/test_asm.c` in a 32-bit process) against pyca/cryptography, X25519 and ECDSA
  included, and runs `tools/ec.py`, the Python model of the curve code.
- `tools/tbcheck.py build/os.lst` (run by measure.sh): TCG jump-cache collisions, as in k1.

## Machine contract (what measure.sh boots; `tools/vm.sh`)
`qemu-system-x86_64 -nodefaults -cpu max -m 16 -kernel build/os.bin -netdev user,hostfwd=tcp::8443-:443 -device ne2k_isa,netdev=n0`
`-cpu max` because of `rdrand` (qemu64 has none). Otherwise as k1: ISA NE2000 at 0x300,
polled, guest IP 10.0.2.15, MAC 0, promiscuous.

## The certificate (`tools/gen.py`, `cert/`)
- `cert/server.key` (ECDSA P-256) and `cert/server.pem` (leaf, then intermediates) are the
  identity that gets baked in. Nothing renews. To use a real certificate, put those two files
  there (and no `ca.pem`); `tools/mkchain.py DIR` makes a realistic test chain.
- If they are missing, gen.py makes a 210-byte leaf for `NAME` (default 127.0.0.1) and its
  CA, `cert/ca.pem`. There is no CA key: the leaf's signature is chosen first (r = 5, the
  smallest x on the curve, s = 1: 8 bytes of DER instead of ~70) and the CA's public key is
  solved from the verification equation. Nobody knows that key's private half, so trusting
  this CA is harmless: it can never sign anything else.
- gen.py also writes `build/ca.pem` (what tests trust; empty for a real chain) and
  `build/name` (the name tests connect to; a DNS name is resolved to 127.0.0.1 by the tests).
- A chain over ~1.1 KB makes the handshake reply longer than one TCP segment; only then is
  the segment loop in `tcp` assembled (`CHAIN_LEN` in `build/conf.inc`).

## Layout
- `src/os.asm`: everything. Buffers at fixed addresses from 2 MiB; 128-byte connection slots
  at 8 MiB, one per client port (server key|iv, client key|iv); ClientHello buckets at 4 MiB.
- `tools/ec.py`: the curve code's other half. The asm has one Montgomery multiplication
  (R = 2^288, 9 limbs), plain 9-limb add/subtract, and a 16-register machine that runs
  2-byte operations; the X25519 ladder, the P-256 x-only ladder and the ECDSA formula are
  programs for it, written and assembled in ec.py, which also models the machine exactly and
  asserts the bounds that make lazy reduction safe. Read its docstring before touching either.
- `tools/gen.py`: certificate, CertificateVerify template, HTTP response, curve constants
  (x(G) R, 4b R, the private key as d R mod n, the low half of n) -> `build/*.inc`
- `tools/vm.sh`: QEMU command line and curl options, sourced by the three test scripts
- `tools/ffcheck.py` (Firefox via Marionette), `tools/nssdb.py` (an NSS database trusting
  our CA, for both browsers, without certutil), `tools/certerr.py` (Chrome net-log flags)

## How the curve code stays small
- No reduction, no comparison, anywhere: mul gives a b / R mod m below 2m for inputs below
  4096m; add is a plain add; sub adds 256m, which is the modulus read one byte early (a zero
  byte sits in front of each modulus). Canonical values come out of mul(x, 1).
- One ladder driver for both curves; the step is a program. One inversion (x^(m-2),
  right to left) for both fields and for mod n. Constants are stored times R.
- The three moduli are built at boot (only the low half of n is data).
- r and s are forced into plain 32-byte DER INTEGERs by retrying: r by stepping the nonce
  (about 2 ladders per handshake), s by nudging the server random as k1 did. Only the one
  signature that is sent ever leaves the machine.
- Our X25519 scalar is used unclamped (the peer only needs our share and the secret to agree).

## Shortcuts that remain (do not "fix" these without asking)
- TLS 1.3 only, one suite: TLS_CHACHA20_POLY1305_SHA256, X25519, ecdsa_secp256r1_sha256.
  A ClientHello without an x25519 share gets a useless answer (no HelloRetryRequest).
- The client's Finished is not checked as such: it carries handshake keys, fails the tag
  check like any forgery, and is skipped. The first request proves the same thing (the
  application keys depend on the whole transcript and the shared secret).
- Client data is authenticated but never decrypted: every authentic record gets one HTTP
  response, a close_notify included. A bad record is skipped, not answered with an alert.
- The tag comparison is `repe cmpsb` (not constant-time): a forged request would only fetch
  the public page for someone else's connection.
- A client record must arrive whole in one TCP segment to count (requests up to ~1.4 KB).
- The server random is the client's, nudged. Freshness comes from our key share.
- No check for an all-zero X25519 result (a client can only weaken its own connection).
- No alerts, no close_notify, no KeyUpdate, no session tickets.
- TCP, NE2000, ARP, HTTP and SHA-256 constants exactly as in k1 (see its CLAUDE.md): our
  seq = their ack, in-order segments only, one slot per client port, bare-LF HTTP response.
- `keys` still writes 20 junk bytes after an IV: the client key block goes last in the slot.

## Tried and rejected
- Compressed EC point in the leaf (-32 bytes): Firefox, once the chain is trusted, says
  SEC_ERROR_UNSUPPORTED_EC_POINT_FORM. (k1 got away with it behind a certificate exception.)
- subjectAltName not critical with the empty subject (-3 bytes): Chrome says INVALID.
- Empty issuer name: curl and Firefox refuse (MOZILLA_PKIX_ERROR_EMPTY_ISSUER_NAME).
- CA and leaf with the same serial number: NSS refuses (Firefox sends bad_certificate).
- Curve registers at the end of the image (their zeros would be free): every write to a page
  that holds translated code takes a slow path in TCG; handshakes took 0.85 s instead of 30 ms.
- Python's `VERIFY_X509_STRICT` (default from 3.13) wants an authority key identifier in the
  leaf; none of the three clients does, so `tools/load.py` clears that one flag.
- Reusing HKDF's info block for "c ap traffic" by patching one byte: `hmac` overwrites it.

## Workflow
Measure after every change; any protocol/cert/HTTP change also needs `./browsers.sh`.
After changing a program in ec.py run `make test` (model and asm must both pass).
Snap Firefox cannot start through its launcher from Claude's shells (no-new-privileges), so
`tools/ffcheck.py` runs the binary inside the snap directly; it quits Firefox through
Marionette. Deleting `cert/server.*` makes the next build generate a new identity and CA
(browsers.sh and measure.sh pick the new CA up from `build/ca.pem`).
Image compression has not been tried: ask the user before going there.
