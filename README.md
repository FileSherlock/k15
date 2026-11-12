# k3

k3 is a bootable x86-64 "operating system" of about 11 KB that serves one static web page
over HTTPS (TLS 1.3, a certificate that clients verify) and plain HTTP, and does nothing
else. It is the secure sibling [k2](../k2) taken out of the emulator and put on a cloud
server: long mode, a virtio-net driver, its own boot sector, ARP, a TCP that copes with
lost and reordered packets and hostile clients, all the processors and memory the machine
has, and an address on the internet.

The aim is to hold and to open as many connections as a small cloud server can, per byte
of image, without giving up any security. A connection to port 80 costs it 20 bytes, a
TLS connection 128. On a cloud server with two virtual processors it opens 9,000 TLS 1.3
connections a second, each with a full handshake, a fresh X25519 key and a fresh ECDSA
signature: twice what nginx with BoringSSL does on the same server and four times nginx
with OpenSSL. Requests on connections that stay, and plain HTTP, go as fast as that
server's network lets them (130,000 requests a second), with its processors four fifths
idle. [bench/README.md](bench/README.md) has the comparison, how it was made and what it
does not say. On the machine it is developed on (QEMU with KVM, one tap interface) it
held 84 million plain connections in 2 GiB. It is work in progress: `CLAUDE.md` has the
state, the plan and everything measured so far.

```bash
make                 # -> build/os.bin and build/disk.img (the first build makes cert/)
./measure.sh         # boot it in QEMU and fetch the page with curl, certificate verified
make test            # the crypto against pyca/cryptography and the model in tools/ec.py
tools/suite.sh       # all the regression runs: loss, reordering, scale, browsers
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

It needs a 64-bit processor with rdrand, AES-NI, PCLMULQDQ, SSE4.1, BMI2 and ADX (Intel
since Broadwell, AMD since Zen), and a virtio-net card.

`build*/` and `cert*/` hold the server's private key and are not in git.
