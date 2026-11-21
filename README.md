# k15

**https://15kb.org/ is served by it** (SSL Labs: A with no warnings, where letsencrypt.org
gets an A+ without post-quantum key exchange either. What letsencrypt.org has and
15kb.org does not is TLS 1.2, guarded against downgrades: k15 speaks TLS 1.3 alone.)

k15 turns a folder of static files into a bootable x86-64 HTTPS server: 14 KB of system
with the files behind it, in one image. There is no operating system underneath, because
it is one: its own boot sector, long mode, a virtio-net driver, ARP, TCP, TLS 1.3 and as
much of HTTP as a static site needs, in one assembly file.

```bash
./k15 pack site/ -n example.org -i 203.0.113.7    # -> build-example.org/os.bin and disk.img
./k15 run build-example.org                       # try it in QEMU: https://127.0.0.1:8443/
./k15 deploy 203.0.113.7 build-example.org        # onto a server that runs Linux with GRUB
```

For a site that is meant to stay (`--reset`: how the server gets back into its Linux):

```bash
./k15 pack site/ -n example.org --san www.example.org --hsts 31536000 -i 203.0.113.7
./k15 renew 203.0.113.7 build-example.org --force --reset 'hcloud server reset NAME'   # Let's Encrypt
./k15 deploy 203.0.113.7 build-example.org --persist --reset 'hcloud server reset NAME'
```

What you get, and what you don't:

- **Small.** The system is 13,891 bytes. The image is that plus your files, each stored
  as the response it is sent as (and, where that makes it shorter, once more compressed
  with gzip and with brotli, for clients that take that).
- **Nothing to break into.** No kernel, no shell, no file system, no user accounts, no
  way to log in, no outgoing connections, no parser but the ones for a TLS record and a
  request line. Only the code is executed, and nothing that is written (not a packet,
  not the stack) can be: the page tables say so, and a test makes sure. There are no
  fault handlers, and every processor is told so: a fault resets the machine.
- **Secure where it counts.** TLS 1.3 only (older clients are told so), X25519, ECDSA
  P-256, AES-128-GCM (the one cipher every TLS 1.3 client has), a fresh key and a
  fresh nonce for every handshake, forward secrecy for every connection, and curve
  arithmetic and ciphers that neither branch on nor index
  with anything secret: checked, not only read, by running them under Valgrind with
  every secret marked as undefined. The arithmetic is also asked what Project
  Wycheproof asks every implementation, and the running image what tlsfuzzer does
  (1,300 conversations, most of them wrong in one place). What is random comes from the processor's generator, and each
  draw is compared with the one before: a generator that repeats itself (some have)
  stops the machine before it signs anything. Port 80 only says where the site is.
- **Cheap to hold open.** A TLS connection costs 128 bytes, however large the file it is
  fetching: what was sent is never stored, it is made again from the image if it gets
  lost. A SYN from an address that does not answer costs nothing, and a client that
  vanishes in the middle of a file is given up after a minute or two.
- **Fast at what a site is made of.** On a cloud server with two shared virtual
  processors (a Hetzner cx23): 7,500 to 9,000 new TLS 1.3 connections a second,
  depending on the hour, each with a full handshake: twice what nginx with BoringSSL
  did there in the same night and four times nginx with OpenSSL; 105,000 to 125,000
  small pages a second on connections that stay, against nginx's 34,000; files of 14 KB
  at 30,000 to 35,000 a second, against 24,000 to 27,000. [bench/README.md](bench/README.md)
  has the comparison, how it was made, and what it does not say.
- **Large files a quarter faster than nginx**: 1.2 GB/s where nginx did 0.90 to 0.98 two
  nights before, under AES-128-GCM. (It was 0.17 GB/s until the card was given 45
  records to a frame to cut up, and 1.0 until a record was sealed four blocks at a
  time.) Over a distance a
  window may grow past 64 KB, but only slowly: without SACK, what is lost in a large
  window comes back a segment a round trip.
- **Clunky on purpose.** Content and certificate are part of the image: a change is a new
  image and a reboot of a few seconds. Nothing renews by itself: `./k15 renew` is there to
  be run from cron, does nothing until the certificate has a month left, and then makes
  the new key on your machine: only a request for a certificate travels to the server.
  One site per server, one address
  baked in (IPv4: there is no IPv6), GET and HEAD and nothing else, requests of up to
  4 KB, nothing compressed
  that was not packed that way, no ranges, TLS 1.3 clients only. Of a request's
  headers two are read: Accept-Encoding and If-None-Match (a client that has a file is
  told so).

It needs a 64-bit processor with rdrand, AES-NI, PCLMULQDQ, SSE4.1, BMI2 and ADX (Intel
since Broadwell, AMD since Zen), a BIOS or GRUB to start it, and a virtio-net card: a
cloud server, or QEMU.

It is work in progress. `CLAUDE.md` has the rules and the state, `docs/` how everything
works, the commands, the server, and what went wrong before.

## Working on it

```bash
make                 # -> build/os.bin and build/disk.img with the site of www/ (the first build makes cert/)
./measure.sh         # boot it in QEMU, fetch with curl (certificate verified), play the hostile client
make test            # the crypto against pyca/cryptography and the model in tools/ec.py
tools/outside.sh fetch   # what the next three need, into ext/ (Wycheproof, Valgrind, tlsfuzzer)
make outside         # the crypto against Wycheproof's vectors and RFC 6979's
make ct              # the crypto under Valgrind: no jump and no address is made of a secret
unshare -Urn tools/tlsfuzz.sh   # tlsfuzzer against the image
tools/suite.sh       # all 65 regression runs: loss, reordering, scale, browsers, a site of 80 files
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
