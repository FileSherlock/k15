# k3

k3 is a bootable x86 "operating system" of about 6 KB that serves one static web page over
HTTPS (TLS 1.3, a certificate that clients verify) and plain HTTP, and does nothing else. It is the secure
sibling [k2](../k2) taken out of the emulator and put on a cloud server: a virtio-net driver
instead of an ISA NE2000, its own boot sector, ARP, a TCP that copes with lost packets and
hostile clients, and an address on the internet.

The aim is to hold as many connections as a small cloud server can, first over plain HTTP
and then over HTTPS. It is work in progress: `CLAUDE.md` has the state, the plan and
everything measured so far.

```bash
make                 # -> build/os.bin and build/disk.img (the first build makes cert/)
./measure.sh         # boot it in QEMU and fetch the page with curl, certificate verified
unshare -Urn ./tap.sh ./taprunc.sh 2000 1024 4   # 8,000 connections from 4 source IPs
```

By hand:

```bash
qemu-system-x86_64 -machine q35 -accel kvm -cpu host -m 256 -nodefaults -display none \
  -drive file=build/disk.img,format=raw,if=none,id=d0 \
  -device virtio-scsi-pci -device scsi-hd,drive=d0 \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:8443-:443,hostfwd=tcp:127.0.0.1:8080-:80 -device virtio-net-pci,netdev=n0
curl --cacert build/ca.pem https://127.0.0.1:8443/
curl http://127.0.0.1:8080/
```

`build*/` and `cert*/` hold the server's private key and are not in git.
