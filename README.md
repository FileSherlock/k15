# k3

k3 turns a folder of static files into a bootable x86-64 HTTPS server: 13 KB of system
with the files behind it, in one image. There is no operating system underneath, because
it is one: its own boot sector, long mode, a virtio-net driver, ARP, TCP, TLS 1.3 and as
much of HTTP as a static site needs, in one assembly file.

```bash
./k3 pack site/ -n example.org -i 203.0.113.7    # -> build-example.org/os.bin and disk.img
./k3 run build-example.org                       # try it in QEMU: https://127.0.0.1:8443/
./k3 deploy 203.0.113.7 build-example.org        # onto a server that runs Linux with GRUB
```

What you get, and what you don't:

- **Small.** The system is 13,371 bytes. The image is that plus your files, each stored
  as the response it is sent as.
- **Nothing to break into.** No kernel, no shell, no file system, no user accounts, no
  way to log in, no outgoing connections, no parser but the ones for a TLS record and a
  request line. Only the code is executed, and nothing that is written (not a packet,
  not the stack) can be: the page tables say so, and a test makes sure. There are no
  fault handlers: a fault resets the machine.
- **Secure where it counts.** TLS 1.3 only (older clients are told so), X25519, ECDSA
  P-256, ChaCha20-Poly1305 and
  AES-128-GCM, a fresh key and a fresh nonce for every handshake, forward secrecy for
  every connection, and curve arithmetic and ciphers that neither branch on nor index
  with anything secret. Port 80 only says where the site is.
- **Cheap to hold open.** A TLS connection costs 128 bytes, however large the file it is
  fetching: what was sent is never stored, it is made again from the image if it gets
  lost. A SYN from an address that does not answer costs nothing.
- **Fast at what a site is made of.** On a cloud server with two shared virtual
  processors (a Hetzner cx23): 7,500 to 9,000 new TLS 1.3 connections a second,
  depending on the hour, each with a full handshake: twice what nginx with BoringSSL
  did there in the same night and four times nginx with OpenSSL; 105,000 to 114,000
  small pages a second on connections that stay, against nginx's 30,000. [bench/README.md](bench/README.md) has the comparison, how it
  was made, and what it does not say.
- **Slow at large files**, for now: 165 MB/s where nginx does 750, because it sends one
  frame per segment. And 64 KB per round trip at most (no window scaling).
- **Clunky on purpose.** Content and certificate are part of the image: a change is a new
  image and a reboot of a few seconds. Nothing renews by itself: `./k3 renew` is there to
  be run from cron, does nothing until the certificate has a month left, and then makes
  the new key on your machine (its part on the server has not met Let's Encrypt yet).
  One site per server, one address
  baked in, GET and HEAD and nothing else, requests of up to 4 KB, no compression, no
  conditional requests, TLS 1.3 clients only.

It needs a 64-bit processor with rdrand, AES-NI, PCLMULQDQ, SSE4.1, BMI2 and ADX (Intel
since Broadwell, AMD since Zen), a BIOS or GRUB to start it, and a virtio-net card: a
cloud server, or QEMU.

It is work in progress. `CLAUDE.md` has the state, the plan, how everything works and
everything measured so far.

## Working on it

```bash
make                 # -> build/os.bin and build/disk.img with the site of www/ (the first build makes cert/)
./measure.sh         # boot it in QEMU, fetch with curl (certificate verified), play the hostile client
make test            # the crypto against pyca/cryptography and the model in tools/ec.py
tools/suite.sh       # all 52 regression runs: loss, reordering, scale, browsers, a site of 80 files
tools/sitetest.sh    # that site alone: every path, every kind of client
unshare -Urn ./tap.sh ./taprunc.sh 2000 1024 4   # 8,000 connections from 4 source IPs
gcc -O2 -o build/rawc tools/rawc.c
unshare -Urn ./tap.sh build/rawc 1000000         # a million plain connections, raw packets
gcc -O2 -o build/bench tools/bench.c -lssl -lcrypto   # the rate client of bench/README.md
```

By hand:

```bash
qemu-system-x86_64 -machine q35 -accel kvm -cpu host -smp 2 -m 256 -nodefaults -display none \
  -drive file=build/disk.img,format=raw,if=none,id=d0 \
  -device virtio-scsi-pci -device scsi-hd,drive=d0 \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:8443-:443,hostfwd=tcp:127.0.0.1:8080-:80 -device virtio-net-pci,netdev=n0
curl --cacert build/ca.pem https://127.0.0.1:8443/
curl http://127.0.0.1:8080/
```

`build*/` and `cert*/` hold the server's private key and are not in git.
