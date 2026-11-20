# k15

**https://15kb.org/ is served by a 14 KB x86-64 HTTPS operating system written in assembly, with a $200 Bitcoin bounty on its TLS key until 2027-02-12.**

The live server's TLS certificate private key (ECDSA P-256) is the exact same 255-bit integer as the private key of Bitcoin wallet [`bc1q00000000000000000000000000000000000000`](https://mempool.space/address/bc1q00000000000000000000000000000000000000). Break into `15kb.org`, extract the key from RAM or TLS, and sweep the wallet. Moving the coins is the proof.

```bash
python3 tools/bounty.py --verify 15kb.org   # stdlib-only zero-knowledge proof against the live TLS cert
```

**The server stays on this version.** 15kb.org runs the image packed from this branch (`bounty`) until 2027-02-12. Work goes on in [`main`](https://github.com/FileSherlock/k15/tree/main); nothing merged there, and no pull request, is deployed to the server before the deadline.

## What it is

k15 packs a folder of static files into a bootable x86-64 HTTPS disk image: boot sector, long mode, virtio-net, ARP, TCP, TLS 1.3 and HTTP in one assembly file (13,859 bytes of system + your files).

- **Nothing underneath.** On `15kb.org` the raw disk holds only the boot sector and image: no Linux, no kernel, no shell, no file system, no user accounts, no SSH, no outgoing connections. Writable memory is non-executable (`W^X`), interrupt tables are empty (any CPU fault resets straight back into k15), and curve/cipher code has no secret-dependent branches or memory accesses (checked under Valgrind with secrets marked undefined, Wycheproof, and tlsfuzzer).
- **TLS 1.3 only.** X25519, ECDSA P-256, AES-128-GCM, fresh `rdrand` keys and nonces per handshake, forward secrecy on every connection (SSL Labs: A).
- **Clunky on purpose.** GET and HEAD only, IPv4 only, gzip/brotli pre-packed, ETag/304, port 80 redirect. Content and certificate are baked into the image; changing either is a 4-second reboot.

| on a 2-vCPU Hetzner server ([bench/README.md](bench/README.md)) | k15 | nginx + OpenSSL |
|---|---:|---:|
| new TLS 1.3 connections / s (full handshake) | 7,500 – 9,000 | 2,100 – 2,200 |
| small pages / s, connections kept | 105,000 – 125,000 | 30,000 – 34,000 |
| 14 KB files / s | 30,000 – 35,000 | 24,000 – 27,000 |
| 1.5 MiB file throughput | 1.2 GB/s | 0.90 – 0.98 GB/s |
| RAM per held TLS connection | 128 B | 25.8 KiB |

## Usage

```bash
./k15 pack site/ -n example.org -i 203.0.113.7    # -> build-example.org/os.bin and disk.img
./k15 run build-example.org                       # try in QEMU: https://127.0.0.1:8443/
./k15 deploy 203.0.113.7 build-example.org        # boot via GRUB on a Linux server
```

Requires x86-64 with `rdrand`, AES-NI, PCLMULQDQ, SSE4.1, BMI2 and ADX (Intel Broadwell+, AMD Zen+), BIOS or GRUB, and `virtio-net` (cloud VM or QEMU).

## Testing & Docs

```bash
make && ./measure.sh     # build and test in QEMU (curl verified + hostile-packet abuse)
make test                # assembly crypto vs pyca/cryptography and tools/ec.py
tools/suite.sh           # all 59 regression runs (loss, reorder, fuzzing, browsers, scale)
```

Details live in [`docs/`](docs/internals.md) (`commands.md`, `internals.md`, `server.md`, `pitfalls.md`). `build*/` and `cert*/` hold private keys and stay out of git.
