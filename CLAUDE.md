# Goal: k2's secure HTTPS server on a real cloud server, holding as many connections as it can

k3 is k2 (`../k2`: 3,231 bytes, QEMU with an ISA NE2000, scored in connections per KiB)
taken off its machine contract and put on a Hetzner cloud server. Decided with the user
(2026-11-10):
- the load is k6-style: ramp to N users in 60 s, hold, under 1% errors
- plain HTTP on port 80 (for the connection count) and HTTPS on 443 (as fast as it will go).
  Port 80 has none of the security below: it serves the same public page to anyone.
- size comes later ("we can optimize more later"): correctness and capacity first. The image
  is still one assembly file and still small (5,811 bytes); don't golf it, don't bloat it.
- security as in k2 (below) still holds for everything behind TLS

## Where it stands
Works, locally and on the server: boot from GRUB or a BIOS boot sector, modern virtio-net,
ARP, a TCP that copes with loss, reordering, small segments and made-up clients, two hashed
connection tables sized from the machine's memory (20 bytes per connection on port 80, 128
per TLS connection), TLS 1.3 with a verified certificate on 443, the same page over plain
HTTP on 80, keep-alive requests on both.

On the server (2026-11-11, from the user's machine, RTT 11 ms): HTTPS and HTTP fetched
with curl, Chrome and Firefox (Chrome with no certificate error flags, and refusing
without our CA); 400 TLS connections held and fetched (~45 handshakes/s with 4 in flight);
10 x 1,000 plain connections, all made; 60 of 60 single fetches in 49 ms (HTTPS) and
24 ms (HTTP) each.

| measured | |
|---|---|
| plain connections held over tap, 2 GiB VM (the server's shape) | 83,983,904 of 84,000,000 tried, each fetched twice (16,096 refused at connect, none lost afterwards) |
| the same in a 256 MiB VM | 9.49 million of 9.5 million tried (7,109 refused at connect, none lost) |
| connections opened and fetched per second over tap | ~100,000 (QEMU's packet path is the limit, not the guest) |
| guest cycles per frame, plain HTTP (`DEBUG=1`, counter 1) | 1,880 here, under 2,800 on the server (an average since boot that was still falling) (9,200 before the night of 2026-11-11) |
| guest cycles per frame, TLS keep-alive requests | ~27,000 (the size-coded ChaCha20-Poly1305) |
| handshakes/s, local QEMU with KVM | ~110 through slirp, ~140 over tap |
| keep-alive requests/s through slirp (the Python client is the limit) | ~11,000 |
| handshake cost natively (`make bench`, Ryzen 7 3800X) | X25519 1.35 ms (x2), r and 1/k 3.6 ms, so 6-7 ms |
| handshake on the server | ~13 ms of a ~47 ms fetch |
| with loss over tap | 8,000 TLS at 1%, 2,000 at 5%, 16,000 plain at 3%: all served |
| emulated (KVM=0) | 27 handshakes/s |

## Plan
Steps 1 (virtio-net), 2 (boot on the server) and 3 (a TCP for a real network, the
connection tables, port 80) are done. What they built is in "How TCP works here" and "The
connection tables". Where the limits are now:
- Held connections: memory. 92 million slots for port 80 in the 2 GiB below 4 GiB (and 2
  million for TLS: `TSHARE`). The server's other 2 GiB are above 4 GiB and unused: long
  mode (step 4), or PAE paging before that, would double the tables.
- A ramp ("N users in 60 s"): the guest's cycles per frame, then whatever the host's
  virtio path and the network carry. At 1,880 cycles per frame and three frames to open a
  connection and fetch once, one core of the server does about 350,000 new plain
  connections a second, if they reach it. Not measured there: the load generator is the
  user's to set up, and `tools/rawc.c` only speaks to a tap.
- TLS: the handshake (step 4) and the size-coded record code (~27,000 cycles per request).
- No timers at all: we never close first, a client that vanishes keeps its slot until a
  new connection needs it (and then only after about an hour of silence: `IDLE`), and
  what a client lacks is sent again when the client asks by retransmitting, which after
  an unlucky start can take it seconds (a Linux client whose SYN was lost starts with a
  timeout of 3 s, then 6 s).
- One early segment is kept per client (in 1,024 places), there is no SACK.
- The handshake buffers are 1,024: fine at 140 handshakes/s, to revisit in step 4.

**4. Handshake rate.** Long mode, then 64-bit curve code (the CPU has mulx/adx; no sha_ni,
no avx512ifma). Then the things a size-coded server skipped: one ladder for r instead of
~2 (variable-length DER instead of retrying), ECDSA nonces (k, r, 1/k) computed ahead while
idle, transcript hashes continued instead of restarted (`thash` rehashes from the start 4
times), maybe an X25519 key share reused for a short window. Honest ceiling on one shared
vCPU, from general knowledge: a few thousand handshakes/s for a plain rewrite, 10-15
thousand with the precomputation. 1,000,000 HTTPS connections inside a 60 s ramp (16,700/s)
is at or beyond that; plain HTTP has no such limit. Long mode also lifts the two 4 GiB
limits (RAM above 4 GiB, and a card whose registers the BIOS mapped up there).

**Later.** A real certificate (needs a name; then no `--cacert`), DHCP instead of a baked-in
address, taking out the reset knock, size.

## What "secure" means here
A standard validating client gets server authentication, confidentiality, integrity and
forward secrecy against a network attacker, and no packet makes the server leak its key:
- a fresh X25519 secret and a fresh ECDSA nonce per handshake, from `rdrand`
- a real ECDSA P-256 signature under a key that only exists in the image
- a certificate chain clients verify (private CA by default, or a real chain dropped in)
- a client record gets an answer only if its AEAD tag verifies (next sequence number)
- the curve arithmetic has no secret-dependent branches or memory accesses
- attacker-controlled lengths and indices are bounded (ClientHello size, record sizes, the
  slot a packet selects, what the NIC reports)
The image contains the private key: `build*/` and `cert*/` are secrets and are not in git.
Unlike k2 this one faces the internet: anything a packet can make it do is in scope.

## Commands
- `make` assembles `src/os.asm` into `build/os.bin` (loaded at 1 MiB) and `build/disk.img`
  (`src/boot.asm` + the image; what the tests boot). `python3 tools/sizes.py build/os.lst`
  = bytes per routine. (Of 5,811: boot and driver start-up 977, network 2,321, TLS
  handshake and key schedule 777, SHA-256 258, curves 647, ChaCha20-Poly1305 480,
  certificate, response and tables 351. A flat binary: no padding anywhere.) `make B=dir CERT=dir NAME=n IP=a.b.c.d KNOCK=a,b` builds another
  image: its identity, the name in a generated certificate, the address it answers on, and
  (development only) the two ports that reset it. The scripts take `B` from the environment.
- `./measure.sh` builds, boots the disk image in QEMU, fetches with curl (chain and name
  verified, fresh connections + keep-alive, plain HTTP on port 80, and a check that curl
  refuses without our CA) and runs `tools/abuse.py` (forged, replayed, truncated records
  and bad ClientHellos must be ignored and leave real connections working; requests in
  pieces and pipelined on port 80). Under two seconds with KVM. Through slirp the guest's
  443 is 127.0.0.1:`PORT` (8443) and its 80 is `HPORT` (PORT + 1000).
- `./browsers.sh` checks Firefox and Chrome with our CA as a trusted root in throwaway
  profiles (no exceptions; Chrome's net-log must show no certificate error flags) and that
  Chrome refuses without the CA. Run after any TLS/cert/TCP/HTTP change.
- `unshare -Urn ./tap.sh ./taprunc.sh [PER] [BASE_PORT] [W]`: the load test. A tap
  interface in a throwaway user + network namespace (no root, none of the host's ports),
  `tools/tapc.c` (k1's epoll + OpenSSL client, verifying chain and name) from W source IPs
  (10.0.2.32-47) x PER connections, all open at once, all fetched over at the end. A real
  Ethernet segment: ARP, a Linux TCP as the peer, random ISNs. `LOSS=1` (before `unshare`)
  drops 1% of the packets in each direction, `MTU=n` sets the tap's MTU, and `TIMEOUT=10`
  makes a hung connection fail fast instead of after 60 s. W can be up to 32 (10.0.2.32-63:
  the second 16 share their low nibble with the first). `PLAIN=1 INFLIGHT=64` in front runs
  the same over plain HTTP to port 80.
- `REORDER=25` in front of tap.sh lets a quarter of the packets to the guest overtake the
  rest (held 5 ms). Timing single fetches with curl under it shows whether early segments
  are used: 9 of 60 stalled before `oohold`, none after.
- `make B=build-dbg DEBUG=1` builds an image that counts things (`count n` in the source)
  and shows six counters, four hex digits each, in place of the end of the page on port
  80: frames with a bad length or checksum, cycles per frame handled (an average since
  boot), connections refused for lack of room, early segments, resends, RSTs sent. This is
  how the reordering was found on the server and how the cost of a frame was taken apart.
  Not for images that are measured or kept running (and rawc and tapc don't know its page).
- `unshare -Urn ./tap.sh build/rawc N [W]` (`gcc -O2 -o build/rawc tools/rawc.c`): the
  scale test. N plain connections made of raw packets on the tap, from as many source
  addresses as it takes (12 bytes each in the client, no sockets): each is opened and
  fetched over, then all are fetched over again. W in flight (default 512; thousands
  overflow the guest's receive ring on purpose: lost packets are sent again). `MEM=2048`
  in front for the server's memory. It prints how many were reset (refused, or replaced)
  and how many timed out; 100,000 connections a second.
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
  `test/test_asm.c` in a 32-bit process) against pyca/cryptography and runs `tools/ec.py`,
  the Python model of the curve code. `make bench` times the same object natively.
- KVM is used when /dev/kvm is there; `KVM=0` emulates. `tools/vm.sh` reads `KVM` when it
  is sourced, not when `boot` runs.

## The test machine and the server
`tools/vm.sh` and `tap.sh` boot the server's shape: `-machine q35`, a modern-only
virtio-net (`disable-legacy=on`) behind a PCIe root port, the disk on virtio SCSI, 256 MiB
(`MEM=2048` in front of tap.sh for the server's 2 GiB; the image sizes itself).

The server (seen over ssh): "Hetzner vServer/Standard PC (Q35 + ICH9)", SeaBIOS (no UEFI),
2 vCPUs (we use one), 4 GB, Xeon Skylake with rdrand, aes (both needed), adx, bmi2,
avx512f/bw/vl, no sha_ni, no avx512ifma. RAM: 1 MiB to 0x7ffdc000 below 4 GiB, the other 2 GiB above. Network:
1af4:1041 at 01:00.0, BAR 4 at 0xfd000000 (64-bit, but below 4 GiB), common/ISR/device/
notify structures at +0/+0x1000/+0x2000/+0x3000, notify multiplier 4, rings of 256, MAC
92:00:0a:76:c2:50. Address 2.28.113.14/32, everything through the gateway 172.31.1.1
(d2:74:7f:6e:37:e3). Disk: 38 GB on virtio SCSI (1af4:1048), Ubuntu 26.04 with GRUB 2.14.

Two things differ locally:
- A current SeaBIOS maps the card's 64-bit BAR far above 4 GiB when the VM has RAM above
  4 GiB (`-m 4096`); the driver reads only the low half. Hetzner's BIOS (2017) doesn't.
  Keep local VMs at `-m 2048` or less until the image runs in long mode.
- SeaBIOS won't boot a disk of a few KiB: `disk.img` is 8 MiB, sparse.

## Running it on the server
`ssh root@2.28.113.14` works from the user's machine while the server runs Linux.
- `make B=build-hz CERT=cert-hz NAME=2.28.113.14 IP=2.28.113.14 KNOCK=$(tr ' ' , < build-hz/knock)`
  (`-B` after changing KNOCK or IP: only the address is tracked as a dependency)
- `B=build-hz tools/deploy.sh root@2.28.113.14` copies the image to /boot/k3.bin and
  reboots into it ONCE through a GRUB entry ("k3" in /etc/grub.d/40_custom, loaded with
  `multiboot`). Ubuntu stays installed and is what any later reset boots. Up after ~4 s.
- `curl --cacert build-hz/ca.pem https://2.28.113.14/` and `curl http://2.28.113.14/`
- A connection that fails at once from here is ours, not the server's: tapc prints
  `bind/connect port N: Address already in use` when another program on this machine has
  the port. Ten runs of 1,000 from base port 32000 each lost port 32770 that way (a
  browser's connection had it); ten from 20000 lost none. That was the "1 in 1,000" of
  the first night on the server.
- `B=build-hz tools/knock.sh 2.28.113.14` resets it: a TCP packet to port a, then one to
  port b (build-hz/knock). Linux and ssh are back ~12 s later. This is a backdoor for
  development (two port scans in a row could trigger it); it is only assembled with KNOCK
  set and must be left out of anything that gets benchmarked or kept running.
- The image never answers ping; the user's reset button in the Hetzner console is the
  fallback if a build doesn't come up or the knock doesn't work.
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

## Layout
- `src/os.asm`: everything after the loader, 32-bit protected mode, no paging, interrupts
  off, one polling loop. Start-up: memory size from the loader (multiboot `mem_upper`; 255 MiB
  if it doesn't say), own GDT, stack down from 2 MiB, zero from 2 MiB to the end of the
  connection table, SHA-256 constants, curve constants and moduli, IDT, virtio-net, the
  key for `prf`.
  Memory: frame being handled at address 0 (`FR`: it stays as it came, so its fields are
  the packet's variables, `P_SEQ` and so on, a byte away from ebx = 0); buffers from 2 MiB
  (`BSS`; `OB` is our answer to one packet); virtio rings at 4 MiB (`VQ`), receive and
  transmit buffers at 5 and 7 MiB (`RXB`, `TXB`: 2 KiB each, descriptor i is buffer i, a
  12-byte virtio header in front); early segments at 12 MiB (`OOP`); handshake buffers at
  16 MiB (`HSP`); the two connection tables from 32 MiB (`CONNS`) to the end of memory (at
  most up to 3 GiB): first the TLS table, an eighth of that, then the table for port 80.
  Needs 64 MiB or more.
- `src/boot.asm`: BIOS boot sector: reads 64 sectors, asks the BIOS for the memory size
  (int 15h, E801), protected mode, copies the image to 1 MiB, enters it like a multiboot
  loader (magic in eax, the memory size in a multiboot information structure at ebx).
- virtio-net: `pcird` reads PCI configuration; the driver finds 1af4:1041 or :1000 on any
  bus, walks its capabilities for the common, notify and device structures, negotiates only
  VERSION_1, and polls the used ring. Frames to send are built in the transmit buffers
  (`txbuf` gives the next one and waits if the device holds all N, `txgo` queues it); the
  device is told (`txkick`, if it hasn't set NO_NOTIFY) when the polling loop has handled
  everything that came in, or every 32 frames: telling it leaves the virtual machine and
  costs more than everything else done for a frame.
- `tcp`: ARP requests for OURIP get a reply; then only IPv4 without options, unfragmented,
  TCP, to OURIP, with the TCP checksum right and a length that fits the frame, port 443 or
  80 gets further. `tcp_send` cuts an answer into segments, `tcp_seg` builds and sends one.
- `tools/ec.py`: the curve code's other half. The asm has one Montgomery multiplication
  (R = 2^288, 9 limbs), plain 9-limb add/subtract, and a 16-register machine that runs
  2-byte operations; the X25519 ladder, the P-256 x-only ladder and the ECDSA formula are
  programs for it, written and assembled in ec.py, which also models the machine exactly and
  asserts the bounds that make lazy reduction safe. Read its docstring before touching either.
- `tools/gen.py`: certificate, CertificateVerify template, HTTP response, curve constants
  -> `build/*.inc`. `tools/ip.py`, `tools/mkdisk.py`: the baked-in address, the disk image.
- `tools/vm.sh`: QEMU command line and curl options, sourced by the test scripts
- `tools/ffcheck.py`, `tools/nssdb.py`, `tools/certerr.py`: the browser checks' helpers

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
- An answer of several segments does not acknowledge the client's data at all (`tcp_send`,
  `F_DEFER`); that is done when the client's ack shows it has the whole answer. Until then
  the client keeps retransmitting its data, whichever of our segments were lost, so a
  flight of several segments needs no timer either. (Acknowledging with the last segment
  was not enough: a hole in the middle plus the loss of the client's one duplicate ack
  left it with nothing outstanding. Seen at 4 in 2,000 with 3% loss.) A client that then
  has nothing to say acknowledges late (Linux: 40 ms), and gets our ack after that: one
  more small packet, no delay for the next request (measured with a page of three
  segments: 0.2 ms per keep-alive request).
- A retransmitted ClientHello must get the same flight, not a new handshake: the client may
  have the first one already (its retransmission was only early), and would then hold keys
  we no longer have.
- Handshake buffers (`HSP`: 1024 x 16 KiB): a connection takes the next one in a circle
  with its first ClientHello byte; it holds the ClientHello while that arrives (any number
  of segments) and then the flight. The buffer says whose it is; a connection whose buffer
  went to another and that needs it (the rest of its ClientHello arrives, or its flight
  has to go out again) is reset. That takes 1024 other handshakes starting within one
  client's retransmission time: more buffers when step 4 makes handshakes that fast.
- A segment from further on than we expect is kept (`oohold`) and used as soon as what
  comes before it has arrived (`.reply`). There are 1,024 places of 2 KiB for such
  segments; a client's place is picked by its hash and holds one segment, the earliest;
  two clients that share a place overwrite each other, and the loser's client retransmits.
  This matters on a real network: between the user's machine and the server, two segments
  sent back to back (a ClientHello in two parts; Finished and the request) arrive swapped
  5-25% of the time. Dropping the early one cost a client timeout (+220 ms) on a quarter
  of all fetches; Linux on the same server counts the same swaps (TCPOFOQueue) and hides
  them the same way.
- Port 80 is the same machine without keys: its "records" are the bare response, all the
  same, and its requests are found by counting line ends (`.plain`: two in a row, CRs
  ignored, end a request; a request body would be read as more request lines).
- A record header split over segments is carried in the slot (`C_HDRN` bytes of it, in
  `C_LEN`); a record split over segments is still skipped, not read (see Shortcuts).

## The connection tables
- Two tables, one per port, so that a connection to port 80 costs 20 bytes (address, port,
  a byte of flags, a byte of time, `C_NXT`, `C_SND`, `C_ACK`) and a TLS connection 128 (the
  same, then `C_ST`, `C_LEN`, its handshake buffer, and 96 bytes of keys). They fill the
  memory from 32 MiB up: the TLS table gets an eighth (`TSHARE`), port 80 the rest. On
  the server: 2.06 million TLS slots and 92.5 million for port 80.
- A connection is in one of two buckets of 16 slots, picked by two words of `prf(addresses,
  ports)`; a new one goes into the bucket with more free slots (`find`). A slot is free
  when its address is 0. With two buckets to choose from the table fills to 85% before
  anyone finds both full, and at 92% one in a thousand does; one run of 16 slots from one
  hash, as it was, lost 0.8% of the held connections at 70% (`tools/rawc.c` measures it;
  both match a simulation).
- `prf` is eleven AES rounds (the processor's `aesenc`) over the frame's addresses and
  ports under round keys from rdrand at boot: about 50 cycles, and clients can't aim at
  each other's buckets. One call per packet gives the two buckets, the cookie's secret
  (`W`) and the place of an early segment. (It was a ChaCha20 block: 3,200 cycles, half
  of what a frame then cost.)
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
- An ack that fits no connection in its slot but is a valid cookie replaces the connection:
  the client reused the port and we never saw the old one end.
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

## Calls through interrupt gates
Routines called from several places, and not from inner loops, are reached with `int n`
instead of `call`: `icall name` in the source, `fret` (iret) to return, the list is
`GATELIST`. Boot builds the IDT after the moduli; the gates name code selector 8 of our own
GDT. A gated routine can take flags in but not return them. It is a size trick from k2, and
it is 32-bit: it goes when the image moves to long mode. A round trip through a gate costs
about 300 cycles (measured), which is nothing in a handshake and was most of a frame: `tcp`
and `csum` (five round trips per frame) are plain calls.
The host test build (`-DHOST`) turns `icall`/`fret` back into `call`/`ret`.

## How the curve code works (k2's, built for size, now the bottleneck)
- No reduction, no comparison, anywhere: mul gives a b / R mod m below 2m for inputs below
  4096m; add is a plain add; sub adds 256m, which is the modulus read one byte early (a zero
  byte sits in front of each modulus). Canonical values come out of mul(x, 1).
- One ladder driver for both curves; the step is a program. One inversion (x^(m-2),
  right to left) for both fields and for mod n. Constants are stored times R.
- r and s are forced into plain 32-byte DER INTEGERs by retrying: r by stepping the nonce
  (about 2 ladders per handshake), s by nudging the server random.
- Our X25519 scalar is used unclamped (the peer only needs our share and the secret to agree).

## Shortcuts that remain
From k2, where they saved bytes. Ask before removing the ones about TLS; the ones about TCP
are step 3's job.
- TLS 1.3 only, one suite: TLS_CHACHA20_POLY1305_SHA256, X25519, ecdsa_secp256r1_sha256.
  A ClientHello without an x25519 share gets a useless answer (no HelloRetryRequest).
- The client's Finished is not checked as such: it carries handshake keys, fails the tag
  check like any forgery, and is skipped. The first request proves the same thing.
- Client data is authenticated but never decrypted: every authentic record gets one HTTP
  response, a close_notify included. A bad record is skipped, not answered with an alert.
- The tag comparison is `repe cmpsb` (not constant-time): a forged request would only fetch
  the public page for someone else's connection.
- A client record must arrive whole in one TCP segment to count (requests up to ~1.4 KB).
- The server random is the client's, nudged. Freshness comes from our key share.
- No check for an all-zero X25519 result (a client can only weaken its own connection).
- No alerts, no close_notify, no KeyUpdate, no session tickets.
- TCP: no SACK, timestamps or window scaling, no timers, we never close first (not even
  for `Connection: close`: the client has the Content-Length). The IP header's checksum
  is not looked at: what we use of that header is fixed or goes into TCP's checksum, which
  is. Bare-LF HTTP response.
- HTTP: any request, whatever it asks for, gets the page; a request body is not understood.
- `keys` writes 20 junk bytes after an IV: the handshake makes both key blocks in `KA` and
  copies them into the slot.
- The handshake's scratch (transcript, key schedule, curve registers) is global: one
  handshake at a time, start to finish, inside one call of `tcp`.

## Learned the hard way
- Under KVM the NE2000 cost a VM exit per byte of port I/O (39 handshakes/s); virtio-net
  has none while polling. Under emulation nothing helps: the guest's 40 ms of curve code is
  the time, and a load client is never the bottleneck (the Python one used 4% of a core).
- slirp walks every open socket on each turn of QEMU's main loop: a full core at 25,000
  connections. Load tests of any size go over tap.
- Writes to a page that holds translated code are slow under emulation (k2: 0.85 s per
  handshake with the curve registers at the end of the image). Data lives from 2 MiB.
- `int`/`iret` cost ~1 us each under emulation: no gates for routines in inner loops.
- nasm: a non-local label ends the scope of `.local` labels (a helper dropped between
  `start` and its `.poll` broke the build with hundreds of errors). Read the first error.
- QEMU keeps the image open: rebuilding under a running VM doesn't change it.
- netem drops a whole GSO packet (several segments) as one loss, and a Linux client whose
  first flight is lost waits by its cached RTT for the destination: 3 s, then 6 s. At 5%
  loss a handshake can run past a 20 s test timeout without the server doing anything
  wrong. `tools/pcap.py FILE IP PORT` prints one connection from a `tcpdump -w` capture
  (in the namespace: `tcpdump -Z root -i k2t -w FILE`; lines `<-` are captured before the
  loss filter, lines `->` after netem). tapc prints the port of each failed connection.
- Killing a load client leaves tens of thousands of sockets in TIME-WAIT for a minute, and
  QEMU can't take its forwarded port back until they are gone.
- In Claude's shell: `pkill -f pattern` also matches (and kills) the shell running it;
  very long shell commands with heredocs can be refused by a safety check, so write scripts
  with the Write tool and run them; snap Firefox can't start through its launcher, so
  `tools/ffcheck.py` runs the binary inside the snap.
- Where a frame's time goes can't be seen from outside: over tap QEMU's packet path is
  the limit (a hash that cost nothing changed no rate). Count cycles in the guest
  (`DEBUG=1`). What it showed, per frame: 2,800 cycles for telling the device about each
  frame sent (a write that leaves the virtual machine), 3,200 for a ChaCha20 block as
  the hash, 1,500 for five trips through interrupt gates, 1,900 for everything else.
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
- tc: `action gact drop random netrand drop 100` drops everything (the first action is
  the default); it is `gact pass random netrand drop 100`. tcpdump in the namespace needs
  `-Z root`.
- `pkill -f pattern` over ssh kills the ssh command that carries the pattern too: write a
  pid file, or `pgrep -f "http[.]server"`.
- Hetzner's web console garbles `|` and `[`: use ssh.

## Tried and rejected (k2)
- Compressed EC point in the leaf: Firefox says SEC_ERROR_UNSUPPORTED_EC_POINT_FORM.
- subjectAltName not critical with the empty subject: Chrome says INVALID.
- Empty issuer name: curl and Firefox refuse. CA and leaf with the same serial: NSS refuses.
- Python's `VERIFY_X509_STRICT` (default from 3.13) wants an authority key identifier in the
  leaf; none of the three clients does, so the test clients clear that one flag.

## Workflow
`./measure.sh` after every change (it is under a second); `make test` after touching crypto
or ec.py; `./browsers.sh` and a tap run after any TLS, TCP or HTTP change; then the server
(deploy, fetch, knock) for anything that could behave differently on a real network.
Commit when the user asks.
