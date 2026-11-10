# Goal: k2's secure HTTPS server on a real cloud server, holding as many connections as it can

k3 is k2 (`../k2`: 3,231 bytes, QEMU with an ISA NE2000, scored in connections per KiB)
taken off its machine contract and put on a Hetzner cloud server. Decided with the user
(2026-11-10):
- the load is k6-style: ramp to N users in 60 s, hold, under 1% errors
- plain HTTP on port 80 (for the connection count) and HTTPS on 443 (as fast as it will go)
- size comes later ("we can optimize more later"): correctness and capacity first. The image
  is still one assembly file and still small (3,951 bytes); don't golf it, don't bloat it.
- security as in k2 (below) still holds for everything behind TLS

## Where it stands
Works, locally and on the server: boot from GRUB or a BIOS boot sector, modern virtio-net,
ARP, TLS 1.3 with a verified certificate, keep-alive requests. First fetch over the internet
2026-11-10; 400 verified connections held from the user's machine at ~55 handshakes/s.

| measured | |
|---|---|
| handshakes/s, local QEMU with KVM | ~120 through slirp, ~140 over tap |
| keep-alive requests/s, same | ~11,500 |
| handshake cost natively (`make bench`, Ryzen 7 3800X) | X25519 1.35 ms (x2), r and 1/k 3.6 ms, so 6-7 ms |
| emulated (KVM=0) | 27 handshakes/s, ~15 s to boot |

## Plan
Steps 1 (virtio-net) and 2 (boot on the server) are done. Next:

**3. A TCP that survives a real network, a real connection table, port 80.**
- Lost packets. Our seq is "their ack" and nothing is ever sent twice. Seen over tap: 7 of
  8,000 fetches hung after one dropped packet.
  - A lost response: the client retransmits its request, which today is only re-acked.
    The response is static, so rebuild it: same key, same TLS sequence number, same bytes.
    But only if the client really has not seen it: remember per connection our sequence
    number at the last reply and compare with the retransmission's ack, else a spurious
    retransmit gets the response twice as new data.
  - A lost handshake flight: the client retransmits its ClientHello. If nothing of the
    flight arrived, a fresh handshake is fine. A flight of several segments (a real chain)
    of which only the tail was lost needs the same flight again, and nobody asks for it:
    the client has nothing outstanding. That needs the flight kept (or regenerated) and a
    timer (rdtsc; there is no clock yet). With the private CA the flight is one segment
    and the retransmitted ClientHello is trigger enough.
- The connection table: now 16 tables of 65,536 slots x 128 bytes picked by the low nibble
  of the client's IP, indexed by port (two clients whose IPs share a nibble and a port
  collide). Wanted: open addressing over (client IP, port), a keyed hash (a client must not
  be able to choose collisions), slots freed on FIN/RST, something sane when a SYN flood
  fills it. A slot has 108 live bytes; the 20 after them are overwritten by `keys` (see
  Shortcuts). 32-bit code reaches the 2 GiB of RAM below 4 GiB: ~1 GiB of slots is 8M.
- ClientHello reassembly is keyed by slirp's ISN pattern (`CHB` buckets). Real clients have
  random ISNs: a ClientHello in two segments (Chrome's is ~1.8 KB) can collide with another
  in flight. It belongs with the connection.
- Our SYN-ACK has no options (so no MSS: peers assume 536) and our window is whatever the
  client's last window field said. Send an MSS option and a fixed window.
- Port 80: the same static page without TLS. Everything not 443 is dropped today.
- Not yet checked against a real browser over the internet (only curl and tapc).

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
  = bytes per routine. `make B=dir CERT=dir NAME=n IP=a.b.c.d KNOCK=a,b` builds another
  image: its identity, the name in a generated certificate, the address it answers on, and
  (development only) the two ports that reset it. The scripts take `B` from the environment.
- `./measure.sh` builds, boots the disk image in QEMU, fetches with curl (chain and name
  verified, fresh connections + keep-alive, and a check that curl refuses without our CA)
  and runs `tools/abuse.py` (forged, replayed, truncated records and bad ClientHellos must
  be ignored and leave real connections working). Under a second with KVM.
- `./browsers.sh` checks Firefox and Chrome with our CA as a trusted root in throwaway
  profiles (no exceptions; Chrome's net-log must show no certificate error flags) and that
  Chrome refuses without the CA. Run after any TLS/cert/TCP/HTTP change.
- `unshare -Urn ./tap.sh ./taprunc.sh [PER] [BASE_PORT] [W]`: the load test. A tap
  interface in a throwaway user + network namespace (no root, none of the host's ports),
  `tools/tapc.c` (k1's epoll + OpenSSL client, verifying chain and name) from W source IPs
  (10.0.2.32-47) x PER connections, all open at once, all fetched over at the end. A real
  Ethernet segment: ARP, a Linux TCP as the peer, random ISNs, and packets do get dropped.
  `TIMEOUT=10` in front makes a hung connection fail fast instead of after 60 s.
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
virtio-net (`disable-legacy=on`) behind a PCIe root port, the disk on virtio SCSI, 160 MiB.

The server (seen over ssh): "Hetzner vServer/Standard PC (Q35 + ICH9)", SeaBIOS (no UEFI),
2 vCPUs (we use one), 4 GB, Xeon Skylake with rdrand, adx, bmi2, avx512f/bw/vl, no sha_ni,
no avx512ifma. RAM: 1 MiB to 0x7ffdc000 below 4 GiB, the other 2 GiB above. Network:
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
- `curl --cacert build-hz/ca.pem https://2.28.113.14/`, or tapc from here:
  `B=build-hz DST=2.28.113.14:443 build/tapc 0.0.0.0 30000 400 www/index.html`
- `B=build-hz tools/knock.sh 2.28.113.14` resets it: a TCP packet to port a, then one to
  port b (build-hz/knock). Linux and ssh are back ~12 s later. This is a backdoor for
  development (two port scans in a row could trigger it); it is only assembled with KNOCK
  set and must be left out of anything that gets benchmarked or kept running.
- The image never answers ping; the user's reset button in the Hetzner console is the
  fallback if a build doesn't come up or the knock doesn't work.
- Be modest with load from the user's home connection; the user is setting up a separate
  load generator.

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
- A chain over ~1.1 KB makes the handshake reply longer than one TCP segment; only then is
  the segment loop in `tcp` assembled (`CHAIN_LEN` in `build/conf.inc`).

## Layout
- `src/os.asm`: everything after the loader, 32-bit protected mode, no paging, interrupts
  off, one polling loop. Start-up: own GDT, stack down from 2 MiB, zero 2-160 MiB, SHA-256
  constants, curve constants and moduli, IDT, virtio-net.
  Memory: frame being handled at address 0 (`FR`: received, then rewritten in place as the
  reply); buffers from 2 MiB (`BSS`); ClientHello buckets at 4 MiB; connection slots from
  8 MiB to 136 MiB; virtio rings at 144 MiB (`VQ`), receive and transmit buffers after
  (`RXB`, `TXB`: 2 KiB each, descriptor i is buffer i, a 12-byte virtio header in front).
- `src/boot.asm`: BIOS boot sector: reads 64 sectors, protected mode, copies the image to
  1 MiB, jumps to the entry in its multiboot header.
- virtio-net: `pcird` reads PCI configuration; the driver finds 1af4:1041 or :1000 on any
  bus, walks its capabilities for the common, notify and device structures, negotiates only
  VERSION_1, and polls the used ring. It kicks only when the device hasn't set NO_NOTIFY.
  `nic_send` copies FR into the next transmit buffer and waits if the device holds all N.
- `tcp`: ARP requests for OURIP get a reply; then only IPv4 without options, unfragmented,
  TCP, to OURIP, port 443 gets further. `ethfix` turns the frame's Ethernet header around.
- `tools/ec.py`: the curve code's other half. The asm has one Montgomery multiplication
  (R = 2^288, 9 limbs), plain 9-limb add/subtract, and a 16-register machine that runs
  2-byte operations; the X25519 ladder, the P-256 x-only ladder and the ECDSA formula are
  programs for it, written and assembled in ec.py, which also models the machine exactly and
  asserts the bounds that make lazy reduction safe. Read its docstring before touching either.
- `tools/gen.py`: certificate, CertificateVerify template, HTTP response, curve constants
  -> `build/*.inc`. `tools/ip.py`, `tools/mkdisk.py`: the baked-in address, the disk image.
- `tools/vm.sh`: QEMU command line and curl options, sourced by the test scripts
- `tools/ffcheck.py`, `tools/nssdb.py`, `tools/certerr.py`: the browser checks' helpers

## Calls through interrupt gates
Routines called from several places, and not from inner loops, are reached with `int n`
instead of `call`: `icall name` in the source, `fret` (iret) to return, the list is
`GATELIST`. Boot builds the IDT after the moduli; the gates name code selector 8 of our own
GDT. A gated routine can take flags in but not return them. It is a size trick from k2 and
costs nothing measurable here, but it is 32-bit: it goes when the image moves to long mode.
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
- TCP: our seq = their ack, in-order segments only, nothing retransmitted, requests
  pipelined over several segments get overlapping answers, bare-LF HTTP response.
- `keys` writes 20 junk bytes after an IV: the client key block goes last in the slot.
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
- Killing a load client leaves tens of thousands of sockets in TIME-WAIT for a minute, and
  QEMU can't take its forwarded port back until they are gone.
- In Claude's shell: `pkill -f pattern` also matches (and kills) the shell running it;
  very long shell commands with heredocs can be refused by a safety check, so write scripts
  with the Write tool and run them; snap Firefox can't start through its launcher, so
  `tools/ffcheck.py` runs the binary inside the snap.
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
