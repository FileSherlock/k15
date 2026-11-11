# Goal: a tiny secure HTTPS server on bare metal that stands comparison

k3 is k2 (`../k2`: 3,231 bytes, QEMU with an ISA NE2000, scored in connections per KiB)
taken off its machine contract and put on a Hetzner cloud server. Decided with the user:
- (2026-11-10) the load is k6-style: ramp to N users in 60 s, hold, under 1% errors
- plain HTTP on port 80 (for the connection count) and HTTPS on 443 (as fast as it will go).
  Port 80 has none of the security below: it serves the same public page to anyone.
- (2026-11-11) it is to be useful and competitive: the user named nginx, BoringSSL,
  Unikraft and F-Stack, and four gaps: handshakes per second per core, record speed (and
  AES-GCM), all the cores and all the RAM, and timers for the tail. **Security can never
  be lowered, only raised.** The measure is still something like connections divided by
  the size of the binary, so a feature has to pay for its bytes. The image is one assembly
  file (10,561 bytes): don't golf it, don't bloat it.
- security as in k2 (below) still holds for everything behind TLS

## Where it stands
Works, locally and on the server: boot from GRUB or a BIOS boot sector into 64-bit long
mode, all the RAM the machine has (also above 4 GiB), all its
processors (up to 4), modern virtio-net, ARP, a TCP that copes with loss, reordering, small
segments and made-up clients, two hashed connection tables sized from the machine's memory
(20 bytes per connection on port 80, 128 per TLS connection), TLS 1.3 with a verified
certificate on 443 (ChaCha20-Poly1305 and AES-128-GCM), the same page over plain HTTP on
80, keep-alive requests on both.

On the server (2026-11-11, late, from the user's machine, RTT 11 ms; a `DEBUG=1 LIFE=8`
image): both processors answer (the debug page says which); a handshake costs 375,000 to
383,000 cycles there when the nonces were made while idle, which at 2.1 GHz is 5,500 a
second and processor, about 4,500 under full load; a verified HTTPS fetch with curl takes
35 ms (49 before), a keep-alive request 10 ms (one round trip), both ciphers; 600 TLS
connections opened with 8 in flight in 1.8 s, all held and fetched; the knock resets it.
What it does under real load is still to be measured, from a load generator.

| measured here (Ryzen 7 3800X, KVM) | |
|---|---|
| full handshakes/s over tap (`NOMARK=1 ... taprunc.sh 8000 1024 8`: 64,000, all verified) | 7,300 on one processor, 13,300 on two (140 before the night of 2026-11-11) |
| a handshake's crypto natively (`make bench`) | 300,000 cycles: X25519, both halves, 211,000; an ECDSA signature 89,000, or 2,000 when the nonces were made while idle (16 million before) |
| guest cycles for one whole TLS connection (`DEBUG=1`) | 430,000 |
| guest cycles per frame, TLS keep-alive requests | 3,900 (27,000 before) |
| TLS connections held over tap, 256 MiB VM | 144,000 of 144,000, each verified and fetched |
| plain connections held over tap, 2 GiB VM (32-bit image) | 83,983,904 of 84,000,000 tried, each fetched twice |
| connections opened and fetched per second over tap | ~80,000-100,000 (QEMU's packet path is the limit, not the guest) |
| guest cycles per frame, plain HTTP (`DEBUG=1`, counter 1) | 1,880 (32-bit image; under 2,800 on the server) |
| with loss over tap (`tools/suite.sh`) | 3%, MTU 300, reordering, both ciphers, a two-segment flight, 1, 2 and 4 processors: all served, also over 12 to 24 runs of each (see "Learned the hard way" for the two bugs this found) |
| at 5% loss, 12 runs of each | 2 fetches of 240,000 ran past tapc's 60 s: a lost SYN-ACK leaves a Linux client with a retransmission timeout of 3 s, then 6 s, and two more losses on that connection are a minute (captured). No fault of ours, but ours to shorten: the timer in the plan |
| emulated (KVM=0) | boots in 7 s (the tables for the curves), `measure.sh` passes |

Before that, the 32-bit image on the server (2026-11-11, early): HTTPS and HTTP fetched
with curl, Chrome and Firefox; 400 TLS connections held and fetched; 10 x 1,000 plain
connections; 60 of 60 single fetches in 49 ms (HTTPS) and 24 ms (HTTP) each. The browsers
have not been pointed at the 64-bit image on the server yet (locally they have).

## Plan
Done of the user's four gaps: (1) the handshake but for session tickets, (2) records,
(3) processors and RAM but for the offloads. Not done: (4) timers.

**Next, in the order of what they are worth:**
- **Measure it on the server under load.** It runs there (above); the numbers that count
  (a ramp of handshakes, held connections in 4 GiB, plain connections a second) need a
  load generator next to it (the user's; `tools/rawc.c` can use a real interface), not
  a home connection.
- **A retransmission timer** (gap 4). We still never send anything unasked: a lost SYN-ACK
  costs the client its SYN timeout (1 s) and after that a retransmission timeout of 3 s
  for the rest of the connection (it has no round-trip time to go by), everything else its
  retransmission timeout (200 ms and up, or its tail loss probe). A queue of what was sent with a fixed timeout
  is in time order by itself (no wheel needed); when an entry comes due and its connection
  still lacks an ack, treat it as if the client had asked (`.resend`). For a SYN-ACK the
  entry has to carry the SYN (there is no slot yet).
- **Session tickets** (gap 1c). A ticket sealed under a key made at boot, psk_dhe_ke only
  (so forward secrecy stays), saves the signature and the certificate on a return visit,
  not X25519: about a third of a handshake. Needs a real ClientHello parser (today: a
  search for the key share, `handshake`), the binder check, the PSK key schedule and the
  resumption secret (which needs the client's Finished: computable, it is a function of
  the transcript).
- **Checksum offload** (gap 3, the rest): the card offers CSUM and GUEST_CSUM (TSO too:
  no use for a page of one segment). Or a 64-bit `csum` first: it is still 16 bits at a
  time.
- **The handshake further.** Where its 430,000 cycles go: the ladder for the client's
  share 142,000 (256 steps of 529: ten multiplications of 30, eight additions of 4, and
  what the register machine costs around them), k G for the signature 86,000, our own
  share 31,000, the inversion 20,000, SHA-256 about 60,000 (75 blocks of 840), the rest
  records and TCP. A squaring of its own, a short multiplication for a24, HMAC pads kept
  between calls and X25519 key pairs made while idle are each a few percent.

**Later.** A real certificate (needs a name; then no `--cacert`), DHCP instead of a
baked-in address, HelloRetryRequest, taking out the reset knock, size.

## What "secure" means here
A standard validating client gets server authentication, confidentiality, integrity and
forward secrecy against a network attacker, and no packet makes the server leak its key:
- a fresh X25519 secret and a fresh ECDSA nonce per handshake, from `rdrand`; a fresh
  server random too (k2 reused the client's)
- a real ECDSA P-256 signature under a key that only exists in the image
- a certificate chain clients verify (private CA by default, or a real chain dropped in)
- a client record gets an answer only if its AEAD tag verifies (next sequence number); the
  comparison looks at all 16 bytes whatever they are
- nothing in the curve arithmetic, the table lookups (`select`) or the two ciphers
  branches on, or indexes memory with, anything secret
- attacker-controlled lengths and indices are bounded (ClientHello size, cipher suite
  list, record sizes, the slot a packet selects, what the NIC reports)
- ECDSA nonces are made 64 at a time and kept until used (`stock`): each is used once,
  each processor has its own stock (its own memory: see "Processors"), and nothing is
  made before the processors are started. A nonce used twice gives the key away: keep it
  that way.
The image contains the private key: `build*/` and `cert*/` are secrets and are not in git.
Unlike k2 this one faces the internet: anything a packet can make it do is in scope.

## Commands
- `make` assembles `src/os.asm` into `build/os.bin` (loaded at 1 MiB) and `build/disk.img`
  (`src/boot.asm` + the image; what the tests boot). `python3 tools/sizes.py build/os.lst`
  = bytes per routine. (Of 10,549: boot, driver and the other processors 1,900, network
  2,700, TLS handshake and key schedule 1,000, SHA-256 540, curves 2,800 with their
  programs and constants, the two ciphers 1,160, certificate, response and tables 450. A
  flat binary: no padding anywhere.) `make B=dir CERT=dir NAME=n IP=a.b.c.d KNOCK=a,b`
  builds another image: its identity, the name in a generated certificate, the address it
  answers on, and (development only) the two ports that reset it. The scripts take `B`
  from the environment.
- `tools/suite.sh [JOBS] [name...]`: everything below, a few at a time, one line each
  (27 runs, under two minutes). `SMP=1` or `SMP=4` in front for other machines than the
  default of 2 processors. Its verdict is strict: one failed connection is a FAIL. Under
  a loaded host a run that overflows rings on purpose (`raw1m_20k`) can time out a few of
  a million: run it alone before believing it.
- `./measure.sh` builds, boots the disk image in QEMU, fetches with curl (chain and name
  verified, fresh connections + keep-alive, each of the two ciphers by name, plain HTTP on
  port 80, and a check that curl refuses without our CA) and runs `tools/abuse.py`
  (forged, replayed, truncated records and bad ClientHellos must be ignored and leave real
  connections working; requests in pieces and pipelined on port 80). About a second with
  KVM. Through slirp the guest's 443 is 127.0.0.1:`PORT` (8443) and its 80 is `HPORT`
  (PORT + 1000).
- `./browsers.sh` checks Firefox and Chrome with our CA as a trusted root in throwaway
  profiles (no exceptions; Chrome's net-log must show no certificate error flags) and that
  Chrome refuses without the CA. Both take AES-128-GCM. Run after any TLS/cert/TCP/HTTP
  change.
- `unshare -Urn ./tap.sh ./taprunc.sh [PER] [BASE_PORT] [W]`: the load test. A tap
  interface in a throwaway user + network namespace (no root, none of the host's ports),
  `tools/tapc.c` (k1's epoll + OpenSSL client, verifying chain and name) from W source IPs
  (10.0.2.32-47) x PER connections, all open at once, all fetched over at the end. A real
  Ethernet segment: ARP, a Linux TCP as the peer, random ISNs. In front of `unshare`:
  `LOSS=1` drops 1% of the packets in each direction, `MTU=n` sets the tap's MTU,
  `TIMEOUT=10` makes a hung connection fail fast instead of after 60 s, `SUITES=
  TLS_AES_128_GCM_SHA256` picks the cipher (OpenSSL's own order gets ChaCha20-Poly1305),
  `NOMARK=1` leaves out the fetches on the way (then `open_s` is the handshakes alone:
  the rate), `PLAIN=1 INFLIGHT=64` runs the same over plain HTTP to port 80, `SMP=n` and
  `MEM=n` shape the VM (default 2 processors, 256 MiB). W can be up to 32 (10.0.2.32-63:
  the second 16 share their low nibble with the first).
- `REORDER=25` in front of tap.sh lets a quarter of the packets to the guest overtake the
  rest (held 5 ms). Timing single fetches with curl under it shows whether early segments
  are used: 9 of 60 stalled before `oohold`, none after.
- `make B=build-dbg DEBUG=1` builds an image that counts things (`count n` in the source)
  and shows six counters, four hex digits each, in place of the end of the page on port
  80: frames with a bad length or checksum, cycles per frame handled (an average since
  boot), connections refused for lack of room, early segments, resends, RSTs sent (those
  of the processor that answers). This is how the reordering was found on the server and
  how the cost of a frame was taken apart. Not for images that are measured or kept
  running (and rawc and tapc don't know its page).
- `unshare -Urn ./tap.sh build/rawc N [W]` (`gcc -O2 -o build/rawc tools/rawc.c`): the
  scale test. N plain connections made of raw packets on the tap, from as many source
  addresses as it takes (12 bytes each in the client, no sockets): each is opened and
  fetched over, then all are fetched over again. W in flight (default 512; thousands
  overflow the guest's receive ring on purpose: lost packets are sent again). `MEM=4096`
  in front for the server's memory. It prints how many were reset (refused, or replaced)
  and how many timed out; 80,000-100,000 connections a second. Run twice in one VM, the
  same clients come again with the same sequence numbers: each must be taken as new.
- `make B=build-small CAP=1024` builds an image with at most 1,024 slots in each table, then
  `B=build-small unshare -Urn ./tap.sh python3 tools/churn.py [HELD] [LOOPS]` checks that
  connections that end (five ways) give their slots back, and with `FLOOD=n` in front that
  SYNs, acks and data from clients that don't exist (`tools/flood.py`) take none. With
  `IDLE=0` as well, a connection quiet for a minute or two may be replaced (default: about
  an hour): the way to test that rule. `TSHARE=n` gives the TLS table 1/2^n of the memory.
- `tools/load.py` (through slirp, `PORT=`): `hold N`, `burst K`, `seq N` (handshake rate),
  `ka N` (keep-alive rate). Start a VM first: `source tools/vm.sh; boot` with `B`, `PORT`
  and `IMG=$B/os.bin` set.
- `make test` checks the asm crypto (`src/os.asm` built with `-DHOST`, driven by
  `test/test_asm.c`) against pyca/cryptography (hashes, both ciphers, X25519 with edge
  scalars, 70 signatures) and against the model (every pair of 22 edge numbers through
  add, subtract and multiply in each of the three fields), and runs `tools/ec.py`, the
  Python model of the curve code. `make bench` times the same object natively, down to
  one multiplication.
- KVM is used when /dev/kvm is there; `KVM=0` emulates. `tools/vm.sh` reads `KVM` when it
  is sourced, not when `boot` runs.

## The test machine and the server
`tools/vm.sh` and `tap.sh` boot the server's shape: `-machine q35`, 2 processors, a
modern-only virtio-net (`disable-legacy=on`) behind a PCIe root port, the disk on virtio
SCSI, 256 MiB (`MEM=4096` in front of tap.sh for the server's 4 GiB: RAM above 4 GiB, and
SeaBIOS then puts the card's registers far above 4 GiB too; both are tested that way).

The server (seen over ssh): "Hetzner vServer/Standard PC (Q35 + ICH9)", SeaBIOS (no UEFI),
2 vCPUs, 4 GB, "Intel Xeon Processor (Skylake, IBRS, no TSX)" at 2,100 MHz with rdrand,
aes, pclmulqdq, ssse3, sse4.1, adx, bmi2 (all needed), pdpe1gb, x2apic, avx512f/bw/vl, no
sha_ni, no avx512ifma. RAM: 1 MiB to 0x7ffdc000 below 4 GiB, the other 2 GiB above.
Network: 1af4:1041 at 01:00.0, BAR 4 at 0xfd000000 (64-bit, but below 4 GiB),
common/ISR/device/notify structures at +0/+0x1000/+0x2000/+0x3000, notify multiplier 4,
rings of 256, **one queue pair** (no multiqueue on offer; it offers CSUM, GUEST_CSUM, TSO,
MRG_RXBUF, CTRL_VQ, EVENT_IDX, INDIRECT_DESC), MAC 92:00:0a:76:c2:50. Address
2.28.113.14/32, everything through the gateway 172.31.1.1 (d2:74:7f:6e:37:e3). Disk: 38 GB
on virtio SCSI (1af4:1048), Ubuntu 26.04 with GRUB 2.14.

SeaBIOS won't boot a disk of a few KiB: `disk.img` is 8 MiB, sparse.

## Running it on the server
`ssh root@2.28.113.14` works from the user's machine while the server runs Linux.
- `make B=build-hz CERT=cert-hz NAME=2.28.113.14 IP=2.28.113.14 KNOCK=$(tr ' ' , < build-hz/knock)`
  (`-B` after changing KNOCK or IP: only the address is tracked as a dependency)
- `B=build-hz tools/deploy.sh root@2.28.113.14` copies the image to /boot/k3.bin and
  reboots into it ONCE through a GRUB entry ("k3" in /etc/grub.d/40_custom, loaded with
  `multiboot`). Ubuntu stays installed and is what any later reset boots. Up after ~4 s
  (more now: all 4 GiB are zeroed, and the curve tables take 25 ms).
- `curl --cacert build-hz/ca.pem https://2.28.113.14/` and `curl http://2.28.113.14/`
- For a first look at anything new, add `DEBUG=1 LIFE=8` to that `make`: the page on
  port 80 then starts with how many processors take frames (less 1) and which one
  answered, and the machine resets itself after about 8 minutes whatever happens (a
  `LIFE` image is for nothing else). Without `LIFE`, an image whose network side does not
  work stays up until the user presses reset.
- A connection that fails at once from here is ours, not the server's: tapc prints
  `bind/connect port N: Address already in use` when another program on this machine has
  the port. Ten runs of 1,000 from base port 32000 each lost port 32770 that way (a
  browser's connection had it); ten from 20000 lost none. That was the "1 in 1,000" of
  the first night on the server.
- `B=build-hz tools/knock.sh 2.28.113.14` resets it: a TCP packet to port a, then one to
  port b (build-hz/knock). Linux and ssh are back ~25 s later ("connection refused" on
  port 22 means Linux is booting; a timeout means the image is still there). This is a backdoor for
  development (two port scans in a row could trigger it); it is only assembled with KNOCK
  set and must be left out of anything that gets benchmarked or kept running.
- The image never answers ping; the user's reset button in the Hetzner console is the
  fallback if a build doesn't come up or the knock doesn't work. A fault resets the
  machine by itself (there is no IDT), which boots Linux again; a hang does not.
- Be modest with load from the user's home connection; the user is setting up a separate
  load generator. From here: `B=build-hz DST=2.28.113.14:443 build/tapc 0.0.0.0 20000 400
  www/index.html`, and with `PLAIN=1 INFLIGHT=32` and `DST=...:80` for port 80. Base ports
  below 32768.
- A browser against the server: `tools/nssdb.py DIR/.pki/nssdb build-hz/ca.pem`, then
  `HOME=DIR google-chrome --headless=new --no-sandbox --user-data-dir=DIR/c --dump-dom
  https://2.28.113.14/`; `tools/ffcheck.py https://2.28.113.14/ build-hz/ca.pem "Hello"`.

## The certificate (`tools/gen.py`, `cert/`)
- `cert/server.key` (ECDSA P-256) and `cert/server.pem` (leaf, then intermediates) are the
  identity that gets baked in. Nothing renews. To use a real certificate, put those two files
  there (and no `ca.pem`); `tools/mkchain.py DIR` makes a realistic test chain.
- If they are missing, gen.py makes a 210-byte leaf for `NAME` (default 127.0.0.1; an IP
  address or a DNS name) and its CA, `cert/ca.pem`. There is no CA key: the leaf's signature
  is chosen first (r = 5, s = 1) and the CA's public key is solved from the verification
  equation. Nobody knows that key's private half, so trusting this CA is harmless.
- gen.py also writes `build/ca.pem` (what tests trust; empty for a real chain) and
  `build/name` (the name tests ask for; they always connect to 127.0.0.1 or the tap).
- A chain over ~1.1 KB makes the handshake reply longer than one TCP segment
  (`tools/mkchain.py cert-real`, `make B=build-real CERT=cert-real`: a flight of 1,909
  bytes; run the loss and reorder tests with it after touching `.resend` or `tcp_send`).
  A handshake buffer is 4 KiB, or the next power of two that holds the chain.

## Layout
- `src/os.asm`: everything after the loader. 64-bit long mode, interrupts off, no IDT (a
  fault resets the machine), one polling loop per processor. Start-up, in 32-bit code as
  the loader leaves us: page tables for the first 16 MiB, long mode. Then: the memory map
  into page tables (below), zero from 2 MiB to the end of it, the table space divided,
  SHA-256 constants, `ecinit` (fields, constants and tables for the curves, the programs
  unpacked), the start of the key schedule, virtio-net, the key for `prf`, the other
  processors.
  Code is 32-bit in style where it came from k2 (`pushad` is a macro for the eight old
  registers; r8-r15 belong to the crypto and are nobody's to keep). Addresses below 4 GiB
  live in 32-bit registers; a connection's slot does not (`rbp`).
- `src/boot.asm`: BIOS boot sector: reads 64 sectors, asks the BIOS for its memory map
  (int 15h, E820), protected mode, copies the image to 1 MiB, enters it like a multiboot
  loader (the map in a multiboot information structure at ebx, as GRUB passes it).
- virtio-net: `pcird` reads PCI configuration; the driver finds 1af4:1041 or :1000 on any
  bus, walks its capabilities for the common, notify and device structures (a BAR may be
  64-bit and anywhere: each structure is mapped at a place of ours), negotiates only
  VERSION_1, and polls the used ring. Frames to send are built in the transmit buffers
  (`txbuf` gives the next one and waits if the device holds all N, `txgo` queues it; the
  two bracket a lock, the transmit ring being all processors'); the device is told
  (`txkick`, if it hasn't set NO_NOTIFY) when the polling loop has handled everything
  that came in, or every 32 frames: telling it leaves the virtual machine and costs more
  than everything else done for a frame.
- `tcp`: ARP requests for OURIP get a reply; then only IPv4 without options, unfragmented,
  TCP, to OURIP, with the TCP checksum right and a length that fits the frame, port 443 or
  80 gets further. `tcp_send` cuts an answer into segments, `tcp_seg` builds and sends one.
- `handshake`, `thash` (the transcript's hash, continued, not restarted), `keys`, `hmac`,
  `expand`; `sha256`/`shablk`; `seal` with `chacha`, Poly1305, `aeskey`, `aesblk`, GHASH.
- `xdh`, `sign`, `stock`, `binv`, `comb`, `select`, `vm`, `fas`, `fmul`, `inv`, `ecinit`:
  the curves, see below.
- `tools/ec.py`: the curve code's other half: the programs, and a model of the arithmetic
  that the asm must match number for number. Read its docstring before touching either.
- `tools/gen.py`: certificate, HTTP response, curve programs and constants ->
  `build/*.inc`. `tools/ip.py`, `tools/mkdisk.py`: the baked-in address, the disk image.
- `tools/vm.sh`: QEMU command line and curl options, sourced by the test scripts
- `tools/ffcheck.py`, `tools/nssdb.py`, `tools/certerr.py`: the browser checks' helpers

## Memory
What the page tables say (2 MiB pages; `start`):
- The first 16 MiB as they are: the frame being handled at address 0 (`FR`: it stays as
  it came, so its fields are the packet's variables, `P_SEQ` and so on, a byte away from
  ebx = 0); the image at 1 MiB; page tables from 0x110000; buffers and variables from
  2 MiB (`BSS`; `OB` is our answer to one packet; the stack comes down from 4 MiB); virtio
  rings at 4 MiB (`VQ`), receive and transmit buffers at 5 and 7 MiB (`RXB`, `TXB`: 2 KiB
  each, descriptor i is buffer i, a 12-byte virtio header in front); the other processors'
  page tables at 9 MiB and their memory from 10 MiB.
- Behind that, from 16 MiB up, **the table space**: every 2 MiB of RAM that the loader's
  memory map calls available, one after the other, wherever it is. On the server that is
  the rest of the 2 GiB below 4 GiB and then the 2 GiB above. Boot divides it: n
  handshake buffers and n places of 2 KiB for early segments (n a power of two: about
  1/32 and 1/64 of it; one mask, `HSMASK`), then the table for TLS (an eighth of the
  rest: `TSHARE`), then the table for port 80. In a 4 GiB machine: 16,384 buffers, 3.9
  million TLS slots, 174 million for port 80.
- The card's structures (and the local APIC), each in 4 MiB of its own in GiB 505.
Variables in BSS are reached relative to the instruction pointer (`BSS equ mb + ...`:
nasm won't do that for a plain number). Needs 64 MiB or more.

## Processors
The server's card has one receive queue, so the others are fed in software. The first
processor (the one that booted) takes every frame off the ring; a frame of a connection
that is another's (`prf` of its addresses and ports, the low bits of the word that also
picks the place of an early segment) is copied into that processor's ring (256 frames),
which is all that one polls. Everything else it does itself, with the same code:
- Each of the others has page tables of its own that differ from the first one's in two
  places: BSS and page 0 are memory of its own (BSS a copy of the first one's as it was
  when everything was set up). So all that is at a fixed address there (the frame, the
  transcript, the curve registers, the stock of nonces, counters) is per processor, and
  nothing in the code says so.
- Shared, and how: the transmit ring (`TXLOCK`, from `txbuf` to `txgo`); the connection
  tables (a connection is one processor's, but a bucket is not: a new connection takes
  its slot with one `lock cmpxchg` on the slot's first 8 bytes, against what `find` saw
  there; if another processor was quicker, the packet is as good as lost and comes
  again); handshake buffers (each processor has every n-th: `hsnew`); the places for
  early segments (a place's low bits are its processor).
- They are started with INIT and SIPI to "all but self" (`tramp`, copied to 0x8000: from
  real mode straight to long mode); each takes a number with `lock xadd`. Frames go to
  the largest power of two of them (`NCPUM`). With one processor nothing changes but the
  uncontended lock.
- Not closed: a slot given up for being idle (full table, an hour of silence) is taken by
  another processor's `cmpxchg` while a packet of the idle connection could be arriving
  on its own processor in the same microsecond.

## How TCP works here
No timer and no copy of what was sent, except the handshake flight. Our side of a connection
is a function of its keys: the flight, then one record of `RL` bytes per request answered. A
connection knows the next byte it expects (`C_NXT`), our next byte (`C_SND`) and the
client's last ack (`C_ACK`); a TLS connection also how many requests it has answered
(`C_ST`), from which follows where its records start.
- In-order data is taken (a segment that overlaps what we have is trimmed), data from
  further on is kept (see below) and gets an ack of what we expect, a keep-alive probe
  gets an ack.
- Loss shows in two ways, and both lead to `.resend`, which builds the end of what we sent
  again, from the client's ack on (the last records by sealing the response again under
  the same sequence numbers, and before them the end of the flight from the handshake
  buffer): old data arriving again with an ack below `C_SND` (the client's request is
  unacknowledged because our answer carried the ack), or the same ack below `C_SND` twice
  without data (the client got something behind a hole).
- An answer of several segments does not acknowledge the last byte the client sent
  (`tcp_send`, `F_DEFER`); that is done when the client's ack shows it has the whole
  answer. Until then the client keeps retransmitting that byte, whichever of our segments
  were lost, so a flight of several segments needs no timer either. A client that then has
  nothing to say acknowledges late (Linux: 40 ms), and gets our ack after that: one more
  small packet, no delay for the next request.
  (Two earlier rules were not enough. Acknowledging with the last segment: a hole in the
  middle plus the loss of the client's one duplicate ack left it with nothing outstanding,
  4 in 2,000 at 3% loss. Not acknowledging what the packet at hand brought: an answer sent
  again for a duplicate ack is sent for a packet that brought nothing, so it acknowledged
  everything, and if the segment that filled the hole was lost again and the next
  duplicate ack too, nobody had anything left to send: 1 handshake in 8,000 at 3% loss
  with a flight of two segments, found by running the test 16 times.)
- A retransmitted ClientHello must get the same flight, not a new handshake: the client may
  have the first one already (its retransmission was only early), and would then hold keys
  we no longer have.
- Handshake buffers (`HSP`: n of 4 KiB, see "Memory"): a connection takes one with its
  first ClientHello byte (`hsnew`: the next in a circle that is not in use; if 16 in a
  row are, the 16th all the same). It holds the ClientHello while that arrives (any number
  of segments) and then, in its place, the flight. In use means: its owner's slot still
  names it. The slot lets go when the client's ack says it has the flight, so a buffer is
  busy for a round trip, not until 1,024 others have come. A connection whose buffer went
  to another and that needs it (the rest of its ClientHello arrives, or its flight has to
  go out again) is reset.
- A segment from further on than we expect is kept (`oohold`) and used as soon as what
  comes before it has arrived (`.reply`). There are n places of 2 KiB for such segments; a
  client's place is picked by its hash and holds one segment, the earliest; two clients
  that share a place overwrite each other, and the loser's client retransmits. This
  matters on a real network: between the user's machine and the server, two segments sent
  back to back (a ClientHello in two parts; Finished and the request) arrive swapped 5-25%
  of the time. Dropping the early one cost a client timeout (+220 ms) on a quarter of all
  fetches; Linux on the same server counts the same swaps (TCPOFOQueue) and hides them the
  same way.
- Port 80 is the same machine without keys: its "records" are the bare response, all the
  same, and its requests are found by counting line ends (`.plain`: two in a row, CRs
  ignored, end a request; a request body would be read as more request lines).
- A record header split over segments is carried in the slot (`C_HDRN` bytes of it, in
  `C_LEN`); a record split over segments is still skipped, not read (see Shortcuts).

## The connection tables
- Two tables, one per port, so that a connection to port 80 costs 20 bytes (address, port,
  a byte of flags, a byte of time, `C_NXT`, `C_SND`, `C_ACK`) and a TLS connection 128 (the
  same, then `C_ST`, `C_LEN`, its handshake buffer, and 96 bytes of keys). They fill the
  table space behind the buffers: the TLS table gets an eighth (`TSHARE`), port 80 the
  rest.
- A connection is in one of two buckets of 16 slots, picked by two words of `prf(addresses,
  ports)`; a new one goes into the bucket with more free slots (`find`). A slot is free
  when its address is 0. With two buckets to choose from the table fills to 85% before
  anyone finds both full, and at 92% one in a thousand does; one run of 16 slots from one
  hash, as it was, lost 0.8% of the held connections at 70% (`tools/rawc.c` measures it;
  both match a simulation).
- `prf` is eleven AES rounds (the processor's `aesenc`) over the frame's addresses and
  ports under round keys from rdrand at boot: about 50 cycles, and clients can't aim at
  each other's buckets. Its four words pick the two buckets, make the cookie's secret
  (`W`), and the last one the place of an early segment and the processor. (It was a
  ChaCha20 block: 3,200 cycles, half of what a frame then cost.)
- A SYN gets a SYN-ACK and no slot. Our initial sequence number is a cookie: `W` with the
  low bits of the client's initial sequence number xored into bits 10-31; bits 2-9 are
  `W`'s own (`HINT`), bits 0-1 say which of the four segment sizes the client takes. The
  first packet that acknowledges it (the bare ack, or the first data if that ack got
  lost) makes the slot (`ckx`, `.make`). A SYN flood from made-up addresses therefore
  takes no slots at all.
- A packet for no connection: if its ack carries our HINT bits it belongs to a new
  connection whose first packets were lost (the client will send them again): ignored.
  Otherwise, if it has data or a FIN, it gets a RST (the client is talking to a connection
  we no longer have: after a restart, or it was replaced). 1 in 256 of those match the
  hint by chance and get silence instead. (Without the hint: resets for 1 in 1,000 new
  connections at 3% loss, where netem drops the first five segments as one.)
- An ack that fits no connection in its slot but is a valid cookie replaces the connection
  (the client reused the port and we never saw the old one end), **but only if a SYN has
  come for that slot since its last fitting ack** (`F_SYN`). Without that condition a
  late copy of a connection's own first ack, which is a valid cookie for ever, started
  the connection over once the client's later acks had moved on: every tenth connection
  under `REORDER=25`, as soon as the handshake was quicker than netem's 5 ms.
- Full: when both buckets are full, the new connection is refused: its SYN gets a RST
  (`.deny`), or if room ran out after the SYN-ACK, its first packet does. Connections that
  are held are not given up for new ones. The exception keeps the table from silting up
  with clients that vanished: a slot whose connection has been quiet for more than `IDLE`
  (64 units of 2^37 cycles, about an hour; `C_AGE` is a byte of that clock) is taken if
  there is no free one. (It was "the quietest of 16 goes": that pushed out held
  connections from half full on.)
- A slot is freed by a RST with the expected sequence number, and by a FIN: it gets our
  FIN, and if the client had everything we sent, the slot is free at once (a lost FIN of
  ours means the client's next FIN gets a RST). If the client still lacks something, the
  slot stays (`F_CLOSED`) and answers retransmissions until the client's ack covers our
  FIN.

## How the curve code works
Built for bytes per cycle: one multiplication, one add/subtract, a register machine, and
the curve formulas as data. `tools/ec.py` is the reference: it holds the programs and a
model that asserts every bound.
- Numbers: four limbs of 64 bits, below 2^256, standing for their residue ("weakly
  reduced"); nothing is ever compared with a modulus. `fmul`: the 512-bit product (mulx
  with two carry chains, adcx/adox, a row per limb), then for 2^255 - 19 what is above
  2^256 folded back times 38, for the two Montgomery fields (p and n of P-256) four
  rounds of Montgomery reduction and a subtraction by carry. `fas`: add or subtract, then
  M taken off or put back, once or twice: both corrected values are computed whatever
  the case and one of three is kept (cmov). A field is 104 bytes that `ecinit` builds:
  2^256 - M, M, -1/M mod 2^64 (0 says "fold"), the exponent that inverts.
- `vm` runs programs for 16 registers: in the image 2 bytes an operation, unpacked at
  boot to four dwords (three addresses and the operation). Unpacking them took a ladder
  step from 717 cycles to 529: the decoding had cost more than the additions.
- Our key share, e times the base point: 64 additions on edwards25519 from a table of
  j 16^i B (16 entries a nibble, 98 KiB, made at boot), each entry found by reading all 16
  and masking (`select`). The shared secret, e times the client's point: the Montgomery
  ladder, 256 steps, one conditional swap a step. Both end in a division, which they
  share (`XPRE`, `inv`, `XPOST`), and in `freeze`.
- A signature's r = x(k G): 64 additions on P-256 from a table of (j + 1) 16^i G. Jacobian
  mixed addition can't add a point to itself or to infinity, so the table never holds
  infinity, the sum starts at 2^255 G, and k has the difference taken off first (`KOFFV`;
  ec.py's `sign` asserts that no partial sum can meet the point it is added to, and
  says how unlikely the two exceptions in 2^252 are).
- `stock` makes these 64 at a time: 64 times k G, then two inversions for all of them
  (`binv`, Montgomery's trick: Z of every k G, and every k). `sign` takes one r and one
  1/k and needs four multiplications. The polling loops call `stock` when they have
  nothing else to do and the stock is empty, one k G a call; `sign` does when it finds
  none. So a signature costs 89,000 cycles under full load and next to nothing below it.
- `inv` is a^(m-2) by squaring and multiplying, for all three moduli: 20,000 to 31,000
  cycles, once a handshake (X25519) and twice per 64 (the signatures).
- Our X25519 scalar is used unclamped (the peer only needs our share and the secret to
  agree); the client's u has its top bit cleared (RFC 7748).
- r and s go out as DER INTEGERs of whatever length they have (`derint`); nothing is
  retried.

## Records
`seal` makes a record, or the record a client should have sent (whose tag `tcp` then
compares). The key block of a direction is 32 bytes of key, 4 that say the cipher, 12 of
iv: for ChaCha20 the 4 are its block counter and 0; a 1 means AES-128-GCM (`keys` writes
it, from `SUITE`, which `handshake` sets: the first of the client's suites that is one of
ours).
- ChaCha20: the state's four rows in xmm registers, a quarter round on all four columns
  at once (SSE2). Poly1305: 64-bit limbs, `mul`.
- AES-128-GCM: the key schedule is made again for every record (`aeskey`: 176 bytes would
  not fit a slot), four counter blocks at a time through the same loop that xors
  ChaCha20's key stream, GHASH with pclmulqdq (H kept times x, two folds by 0xC2..00;
  the steps were checked in a model against pyca first).
- A response of this page: about 900 cycles either way.

## Shortcuts that remain
From k2, where they saved bytes. Ask before removing the ones about TLS.
- TLS 1.3 only, two suites: TLS_CHACHA20_POLY1305_SHA256 and TLS_AES_128_GCM_SHA256,
  X25519, ecdsa_secp256r1_sha256. A ClientHello without an x25519 share gets a useless
  answer (no HelloRetryRequest). The key share is found by searching the ClientHello for
  its four bytes of group and length, not by parsing the extensions.
- The client's Finished is not checked as such: it carries handshake keys, fails the tag
  check like any forgery, and is skipped. The first request proves the same thing.
- Client data is authenticated but never decrypted: every authentic record gets one HTTP
  response, a close_notify included. A bad record is skipped, not answered with an alert.
- A client record must arrive whole in one TCP segment to count (requests up to ~1.4 KB).
- No check for an all-zero X25519 result (a client can only weaken its own connection).
- No alerts, no close_notify, no KeyUpdate, no session tickets. No ChangeCipherSpec for
  middleboxes.
- After 2^32 requests on one connection its counter wraps to "no ClientHello yet": the
  connection is dead, the nonces never repeat.
- TCP: no SACK, timestamps or window scaling, no timers, we never close first (not even
  for `Connection: close`: the client has the Content-Length). The IP header's checksum
  is not looked at: what we use of that header is fixed or goes into TCP's checksum, which
  is. Bare-LF HTTP response.
- HTTP: any request, whatever it asks for, gets the page; a request body is not understood.
- `keys` writes 20 junk bytes after an IV: the handshake makes both key blocks in `KA` and
  copies them into the slot.
- The handshake's scratch (transcript, key schedule, curve registers) is one per
  processor: one handshake at a time on each, start to finish, inside one call of `tcp`.
- Secrets are not wiped after use: the last handshake's are overwritten by the next, and
  unused nonces wait in the stock. (The private key is in the same memory.)
Gone since k2: the ground server random (it is random now), r and s forced to 32 bytes by
retrying, the tag compared with `repe cmpsb`, the calls through interrupt gates.

## Learned the hard way
- Under KVM the NE2000 cost a VM exit per byte of port I/O (39 handshakes/s); virtio-net
  has none while polling. Under emulation nothing helps but fewer instructions.
- slirp walks every open socket on each turn of QEMU's main loop: a full core at 25,000
  connections. Load tests of any size go over tap.
- Writes to a page that holds translated code are slow under emulation (k2: 0.85 s per
  handshake with the curve registers at the end of the image). Data lives from 2 MiB.
- nasm: a non-local label ends the scope of `.local` labels (a helper dropped between
  `start` and its `.poll` broke the build with hundreds of errors). Read the first error.
  `K2` and `st4` are registers (AVX-512 mask, x87), not labels. An `equ` used before it
  is defined costs passes until nasm gives up ("label changed during code generation").
  A number is not reached relative to rip; a label plus a number is.
- QEMU keeps the image open: rebuilding under a running VM doesn't change it.
- netem drops a whole GSO packet (several segments) as one loss, and a Linux client whose
  first flight is lost waits by its cached RTT for the destination: 3 s, then 6 s. At 5%
  loss a handshake can run past a 20 s test timeout without the server doing anything
  wrong. `tools/pcap.py FILE IP PORT` prints one connection from a `tcpdump -w` capture
  (in the namespace: `tcpdump -Z root -U -i k2t -w FILE`, and `kill -9` it afterwards: it
  does not go on SIGTERM there; lines `<-` are captured before the loss filter, lines `->`
  after netem). tapc prints the port of each failed connection.
- A failure of 1 in 10,000 connections does not show in one run. Run the lossy test 16
  times, and the same on the last commit (`git worktree add`): that told a regression
  from a bug that had always been there (the duplicate-ack resend, "How TCP works here").
- Making something 30 times faster changes the order of events. The late first ack that
  restarted connections ("The connection tables") had always been possible; it needed a
  handshake quicker than the 5 ms by which netem holds a packet back.
- Killing a load client leaves tens of thousands of sockets in TIME-WAIT for a minute, and
  QEMU can't take its forwarded port back until they are gone. A test that hangs leaves
  its VM polling at 100% of a core for ever: look for stray `qemu-system` after one.
- Every processor of the guest polls: `top` shows 100% each whatever the load. Whether the
  guest is the limit shows in its own cycle counts (`DEBUG=1`), or in what a second
  processor adds.
- In Claude's shell: `pkill -f pattern` also matches (and kills) the shell running it;
  very long shell commands with heredocs can be refused by a safety check, so write scripts
  with the Write tool and run them; snap Firefox can't start through its launcher, so
  `tools/ffcheck.py` runs the binary inside the snap. `perf` is not allowed here
  (perf_event_paranoid 4): time pieces with `make bench`.
- Where a frame's time goes can't be seen from outside: over tap QEMU's packet path is
  the limit (a hash that cost nothing changed no rate). Count cycles in the guest
  (`DEBUG=1`). What it showed, per frame: 2,800 cycles for telling the device about each
  frame sent (a write that leaves the virtual machine), 3,200 for a ChaCha20 block as
  the hash, 1,500 for five trips through interrupt gates, 1,900 for everything else.
- The same for the curves: a multiplication of 190 instructions took 52 cycles, one of 90
  takes 30: it was the number of instructions, not the multiplier. An addition with two
  masked passes cost as much as a multiplication; with cmov it costs 4 cycles. And the
  register machine's decoding cost more than either.
- `mulx` leaves 64 bits of product in rcx: after anything that multiplies, `mov cl, n`
  is not a count. And `and` between an `add` and its `adc` takes the carry away (masking
  has to come first, or be a cmov).
- A helper called from a waiting loop must not touch the loop's registers: `txkick` did,
  and the loop that waits for a free transmit buffer never ended. It only showed under
  load that fills the transmit ring: `build/rawc 1000000 20000` does that.
- With held idle connections, "the quietest one goes" is the wrong rule for a full
  bucket, and a threshold of minutes is too short: opening 80 million took 13 minutes,
  and the first ones were then replaceable.
- The "1 connection in 1,000 failed to connect" on the server: see "Running it on the
  server". Dropped SYNs can't do that (20,000 in flight at once over tap: 88,000 packets
  sent again, every connection made).
- A fetch that sometimes takes +200 ms is a client retransmission timeout: something of
  ours or of the client's didn't count. Count on the server (`DEBUG=1`), and compare with
  Linux on the same machine (`nstat` there) before blaming either side.
- A register that "is still zero" isn't after a call that returns something in it: the
  slot was "freed" by writing a buffer address into it (found by `tools/churn.py`).
- Memory we did not zero is not zero. The transmit lock is in low memory (it has to be
  shared), where the boot sector had left a copy of the image: whether the lock started
  out held depended on which byte of the image lay there, so a build with 60 bytes more
  hung, and one with 40 more did not. Found because `DEBUG=1` and `KNOCK=` images
  stopped answering; it would have been GRUB's leftovers on the server.
- What is in BSS is per processor, whether one thinks of it or not: the knock's "first
  port seen" was, and the two packets of a knock went to different processors half the
  time (on the server: the second knock worked). It is in the shared low memory now. The
  debug counters are per processor too (the page shows the answering one's), and a
  division by "frames counted" faulted on a processor that counted none.
- tc: `action gact drop random netrand drop 100` drops everything (the first action is
  the default); it is `gact pass random netrand drop 100`.
- `pkill -f pattern` over ssh kills the ssh command that carries the pattern too: write a
  pid file, or `pgrep -f "http[.]server"`.
- Hetzner's web console garbles `|` and `[`: use ssh.

## Tried and rejected
- Compressed EC point in the leaf: Firefox says SEC_ERROR_UNSUPPORTED_EC_POINT_FORM.
- subjectAltName not critical with the empty subject: Chrome says INVALID.
- Empty issuer name: curl and Firefox refuse. CA and leaf with the same serial: NSS refuses.
- Python's `VERIFY_X509_STRICT` (default from 3.13) wants an authority key identifier in the
  leaf; none of the three clients does, so the test clients clear that one flag.
- virtio multiqueue for the second processor: the server's card has one queue pair.
- `pdep` to mask without touching the carry: microcoded and slow on Zen 2 (the machine
  the tests run on).
- Ephemeral secrets derived from a boot key and the ClientHello (the flight could then be
  made again instead of kept): a key in memory that opens every recorded session since
  boot. Forward secrecy would be lower: not done.
- An X25519 key share reused for a short window, the same.

## Workflow
`./measure.sh` after every change (a second; also once each with `DEBUG=1`, `KNOCK=` and
`LIFE=` images after touching boot or the loops: those builds move everything); `make
test` after touching crypto or ec.py
(the model first: change `tools/ec.py`, run it, then the asm); `tools/suite.sh` after
anything else, and with `SMP=1` after touching what the processors share. After touching
`.resend`, `tcp_send`, the handshake buffers or the cookie rules, also the lossy runs
many times over (a loop of `B=build-real LOSS=3 ... taprunc.sh 500 1024 4`, 16 or more):
what is wrong there is wrong once in thousands. Then the server (deploy, fetch, knock)
for anything that could behave differently on a real machine.
Commit when the user asks. (The night of 2026-11-11 was worked on a branch, `night`, with
a commit per step, because nobody was there to ask.)
