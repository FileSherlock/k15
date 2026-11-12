# Goal: a folder of static files as a bootable, sealed HTTPS server

k3 is k2 (`../k2`: 3,231 bytes, QEMU with an ISA NE2000, scored in connections per KiB)
taken off its machine contract and put on a Hetzner cloud server. Decided with the user:
- (2026-11-10) the load is k6-style: ramp to N users in 60 s, hold, under 1% errors
- (2026-11-11) it is to be useful and competitive: the user named nginx, BoringSSL,
  Unikraft and F-Stack, and four gaps: handshakes per second per core, record speed (and
  AES-GCM), all the cores and all the RAM, and timers for the tail. **Security can never
  be lowered, only raised.** The measure is still something like connections divided by
  the size of the binary, so a feature has to pay for its bytes: don't golf it, don't
  bloat it.
- (2026-11-12) the scope is the best product in its niche: "a clunky, limited but fast
  and secure OS", with a hook strong enough to be noticed. The hook (from a review the
  user had made and told Claude to follow): **compile a folder of static files into a
  bootable x86-64 HTTPS server of a few KB plus the files; nothing to log into, because
  there is no system behind it; holds millions of connections on the smallest cloud
  server.** One command packs it, one deploys it; what is clunky (a new image for every
  change of content or certificate) is the point, not a defect. Session tickets are
  dropped for it: with forward secrecy kept they save the signature only, which is
  already made while idle. (The review also said RFC 8446 forbids sending a ticket
  before the client's Finished; it does not, 4.6.1 allows it without client
  authentication. The decision stands on the other reasons.)
- security as in k2 (below) holds for everything behind TLS. Port 80 has none of it: it
  says one public thing to everyone (where the site is, or its front page).

## Where it stands
The image is one assembly file's worth of system, 13,371 bytes, and behind it the site
(`tools/pack.py`): every file as the HTTP response it is sent as. Works, locally and on
the server: boot from GRUB or a BIOS boot sector into 64-bit long mode, an image of any
length, all the RAM the machine has (also above 4 GiB), all its processors (up to 4),
modern virtio-net, ARP, a TCP that copes with loss, reordering, small segments and
made-up clients, two hashed connection tables sized from the machine's memory (20 bytes
per connection on port 80, 128 per TLS connection), TLS 1.3 with a verified certificate
(ChaCha20-Poly1305 and AES-128-GCM; a client whose key share is for another curve is
asked for x25519, one that can't be served is told why in an alert), and behind it HTTP
as a static site needs it: GET and HEAD by path,
files of any size sent a record to a segment with nothing buffered, requests of up to
4 KB in any number of segments, 404, a redirect for a folder without its slash, "no" and
a closed connection for other methods, keep-alive. Port 80 redirects to the site, or
serves its front page. No memory is both written and executed.
`./k3 pack FOLDER`, `./k3 run`, `./k3 deploy HOST` (see Commands).

On the server (cx23, 2 shared vCPUs; from a load generator 0.4 ms away; method in
`bench/README.md`). The night of 2026-11-11, the image that served one page, next to
nginx and Caddy with the same page, key and certificate:

| on the server (2 vCPUs) | k3 | nginx + BoringSSL | nginx + OpenSSL 3.5 | Caddy |
|---|---|---|---|---|
| new TLS connections a second (full handshake) | 8,800 - 9,100 | 3,900 - 4,100 | 2,100 - 2,200 | 1,800 |
| HTTPS requests a second, connections kept | 109,000 - 122,000 | 47,000 | 37,000 - 40,000 | 9,000 - 12,000 |
| new plain connections a second | 30,000 - 35,000 | 17,000 - 22,000 | 16,000 - 22,000 | 7,000 |
| HTTP requests a second, connections kept | 110,000 - 128,000 | 60,000 - 71,000 | 58,000 - 68,000 | 14,000 |
| memory for a held connection: plain, TLS | 20 B, 128 B | 3.2 KiB, 7.1 KiB | 4.0 KiB, 25.8 KiB | |

The afternoon of 2026-11-12, the image that serves files (the server was 10% slower at
handshakes and a third faster at plain connections than in the night, so the two images
were run in turn):

| the same day, in turn | today's image | the night's image |
|---|---|---|
| new TLS connections a second (8 runs each) | 7,400 - 8,300 (mean 7,820) | 7,300 - 8,600 (mean 7,880) |
| HTTPS requests a second, connections kept | 104,000 - 115,000 | 106,000 - 112,000 |
| new plain connections a second | 43,000 - 46,000 | 42,000 - 47,000 |
| HTTP requests a second, connections kept | 103,000 - 111,000 | 111,000 - 116,000 |

| files, 64 connections (wrk) | k3 | nginx + OpenSSL 3.5 |
|---|---|---|
| a page of 167 bytes, requests a second | 105,000 - 114,000 | 30,000 - 31,000 |
| a file of 14 KB | 10,900 a second, 148 MB/s | 22,100 a second, 300 MB/s |
| a file of 1.5 MiB | 108 a second, 162 - 166 MB/s | 500 a second, 742 - 757 MB/s |

- Small things k3 does three times as fast as nginx; large files nginx does four and a
  half times as fast. The reason is one and the same: the server's network path carries
  about 130,000 frames a second each way (k3's processors are four fifths idle at that
  point), and k3 sends a segment a frame, where Linux hands the card 64 KB at a time
  (segmentation offload). That is the first thing in the plan that is about speed.
- Only new TLS connections are bounded by k3's processors (460,000 cycles of both
  processors' time per connection in the night; nginx 1.0 and 1.9 million).
- With 4,096 new TLS connections in flight: median 0.47 s, 99% 1.5 s, none over 10 s.
  With 4,096 new plain connections in flight k3 asks more of the path than it carries: 1%
  take a second longer (a SYN lost on the way; the same for nginx), and up to 0.05% lose
  it four times running and take over 10 s (353 of 645,000; the night's image the same
  day 155, in the night 83 of 517,000; nginx, which does not get to the path's limit,
  none).
- Held: 60,000 TLS connections (what one client address has ports for), each with the
  chain verified, held and fetched over, and 60,000 plain ones: all, with today's image.
  In the night: 30 runs, 1.8 million connections, all but one the client could not start.
- From the user's machine (RTT 11 ms; 2026-11-12): `tools/sitecheck.py` passes against
  the server (57 paths, every kind of client it plays); 1.5 MiB take 0.3 s; Chrome and
  Firefox load the test site's page with its stylesheet and picture, our CA trusted in
  throwaway profiles. `./k3 deploy --persist` survived a reset: back by itself in 90 s.
- **https://15kb.org/ is k3** (since the evening of 2026-11-12): the folder `site/` (the
  project's own page), a certificate from Let's Encrypt that `./k3 renew --force` got
  (69 s from the command to a verified fetch, the server away for about a minute of
  it), `--persist`. curl with the system's roots, Chrome with its own, `tlsprobe.sh`
  and `sitecheck.py` pass against it. The image is 19,841 bytes: 16,552 of system, of
  which 3,400 are the chain as Let's Encrypt sends it (four certificates), 3,289 of site.

| measured here (Ryzen 7 3800X, KVM) | |
|---|---|
| full handshakes/s over tap (`NOMARK=1 ... taprunc.sh 8000 1024 8`: 64,000, all verified) | 7,400 on one processor, 10,700 on two (the client is the limit there); the night's image 7,700 and 10,800 |
| a handshake's crypto natively (`make bench`) | 300,000 cycles: X25519, both halves, 211,000; an ECDSA signature 89,000, or 2,000 when the nonces were made while idle |
| 1.5 MiB over a round trip of 20 ms, of 100 ms (`DELAY=n` in front of tap.sh) | 0.6 s, 2.9 s (a connection included; 64 KB a round trip is the most: no window scaling) |
| guest cycles per frame, TLS keep-alive requests (the night's image) | 3,900 |
| TLS connections held over tap, 256 MiB VM (the night's image) | 144,000 of 144,000, each verified and fetched |
| plain connections held over tap, 2 GiB VM (32-bit image, k3's first week) | 83,983,904 of 84,000,000 tried, each fetched twice |
| connections opened and fetched per second over tap | ~80,000-100,000 (QEMU's packet path is the limit, not the guest) |
| `tools/suite.sh`: 52 runs (loss 3%, MTU 300 and 600, reordering, both ciphers, a two-segment flight, HelloRetryRequest, sequence numbers that go round, a site of 80 files, W^X, a million raw connections) | all pass on 1 and 2 processors; on 4, all but `raw1m_20k` when the host is that busy (3 of 3 alone) |
| the lossy runs many times over (2026-11-12: 16 x 2,000 handshakes each of seven kinds, the site test 44 times) | none failed (the end of "Workflow" has the list) |
| emulated (KVM=0) | boots in 7 s (the tables for the curves), `measure.sh` passes |

## Plan
Done of the review's four things (2026-11-12): files by path with nothing buffered; the
gaps a browser or scanner finds (requests in several segments, HelloRetryRequest, port 80
redirecting, HSTS, a timer for what we sent); W^X; and the one-command tool, of which
`renew` got 15kb.org its certificate (first against Let's Encrypt's staging server,
then the real one; the user agreed to the terms, the account has no email address).
A second review the same day found four things, all fixed: `renew` would have reset the
server every night from cron and run into Let's Encrypt's limit of five certificates a
week (it now does nothing while the certificate has 30 days left); the key was made on
the server and stayed on its disk, and /boot/k3.bin was readable by all (the key is
made here now and only a request travels; the image is root's alone); `renew` packed
with settings of its own (it packs as the image was packed: OUT/pack.conf); and a client
without TLS 1.3, without our cipher suites or without x25519 got a ServerHello it had
not asked for (it gets an alert and the connection's end).

**Next, in the order of what they are worth:**
- **What is left of the proof.** The name is 15kb.org and the project's page is served
  by itself. Still to do: SSL Labs (the user's to start: it publishes), `./k3 renew
  2.28.113.14 build-15kb.org --reset 'hcloud server reset k3'` in the user's cron (the
  certificate ends on 2027-02-10; renew does nothing before 2027-01-11), `www.15kb.org`
  (it points at the server and port 80 sends it on, but the certificate has one name:
  https://www.15kb.org/ is refused by clients; an image has one name), and a shorter
  chain: Let's Encrypt sends four certificates (3.4 KB, a flight of three segments) where
  leaf and intermediate would do for clients that know the new root.
- **Segmentation offload** (the card offers CSUM and TSO). Large files go at a quarter
  of nginx's speed because a frame is a segment; with TSO a frame is up to 45 records
  (the device cuts where we would have: a record is a segment). Needs transmit buffers
  of 64 KB, the virtio header filled in, and a pseudo-header checksum.
- **Window scaling.** A client's window counts to 64 KB without it: that is all that can
  be on its way, so a large file goes at 64 KB a round trip. The scale is in the SYN,
  for which we keep nothing: it would have to go into the cookie.
- **What a browser asks a second time**: If-None-Match (304; pack.py would add the
  ETags), and files packed compressed for clients that say they take that.
- **The handshake further.** Where its 430,000 cycles go: the ladder for the client's
  share 142,000, k G for the signature 86,000, our own share 31,000, the inversion
  20,000, SHA-256 about 60,000, the rest records and TCP. OpenSSL's assembly does the
  ladder in 113,000 and the signature in 71,000 on the same machine: there is a fifth
  to be had.
**Later.** DHCP instead of a baked-in address, taking out the reset knock, rings for
the processors there are, Unikraft and F-Stack next to k3 (bench/README.md
says what that takes). Not planned: session tickets (see Goal).

## What "secure" means here
A standard validating client gets server authentication, confidentiality, integrity and
forward secrecy against a network attacker, and no packet makes the server leak its key:
- a fresh X25519 secret and a fresh ECDSA nonce per handshake, from `rdrand`; a fresh
  server random too (k2 reused the client's)
- a real ECDSA P-256 signature under a key that only exists in the image
- a certificate chain clients verify (private CA by default, or a real chain dropped in)
- the key is in the image and nowhere else that a network can reach: `./k3 renew` makes
  it on the user's machine and sends the server's Linux a request for a certificate,
  not the key; what holds it (the build folder, the certificate folder, /boot/k3.bin on
  the server) is for its owner's eyes only
- a client record is read only if its AEAD tag verifies (next sequence number); the
  comparison looks at all 16 bytes whatever they are. What it decrypts to is looked at
  after that, not before
- only the code is executed, and it is not written; nor is the site. Everything a packet
  can put into memory (frames, buffers, tables, the stack) is data that the processor
  refuses to run (`start`; `tools/wxtest.sh` does each forbidden thing and expects the
  machine's end)
- a connection's key seals 2^24 records and the response in hand, then the connection is
  closed (RFC 8446, 5.5: no more than 2^24.5 under AES-GCM); we never change keys
- what we send is a function of the image and the client's acks: no request leaves
  anything of itself in an answer (there are no reflected headers, no error pages with
  the path in them)
- nothing in the curve arithmetic, the table lookups (`select`) or the two ciphers
  branches on, or indexes memory with, anything secret
- attacker-controlled lengths and indices are bounded (ClientHello size, cipher suite
  list, record sizes, the request's path, the slot a packet selects, what the NIC
  reports)
- ECDSA nonces are made 64 at a time and kept until used (`stock`): each is used once,
  each processor has its own stock (its own memory: see "Processors"), and nothing is
  made before the processors are started. A nonce used twice gives the key away: keep it
  that way.
The image contains the private key: `build*/` and `cert*/` are secrets and are not in git.
Unlike k2 this one faces the internet: anything a packet can make it do is in scope.

## Commands
- `./k3` is the tool for somebody who has a site and a server:
  `./k3 pack FOLDER [-n NAME] [-i IP] [-c CERTDIR] [-o OUT] [--plain80] [--hsts SECONDS]
  [--cache SECONDS] [--header 'Name: value']` makes OUT/os.bin and OUT/disk.img (port 80
  redirects to https://NAME/ unless `--plain80`); `./k3 run [OUT]` boots it in QEMU
  (https://127.0.0.1:8443/, http://127.0.0.1:9443/); `./k3 deploy HOST [OUT] [--persist]
  [--reset 'COMMAND']` puts it on a server that runs Linux with GRUB and starts it (see
  "Running it on the server"); `./k3 renew HOST [OUT] --reset 'COMMAND' [--days N]
  [--force] [--dry-run]` gets a new certificate from Let's Encrypt when the one OUT was
  packed with ends within N days (30), and does nothing at all before that, so cron may
  run it daily. When it is time: a new key and a request (CSR) are made here, the server
  is reset into Linux, certbot answers the challenge on port 80 there for that request,
  the certificate comes back, OUT is packed again as it was packed (OUT/pack.conf: the
  folder, name, address, certificate folder, headers, what port 80 does) and started. If
  no certificate comes, the image as it was is started again. The key is never on the
  server but inside the image. `--force` for the first one (the private CA's lasts until
  2049), `--staging` for Let's Encrypt's test server (its certificate is trusted by
  nobody, so the fetch at the end fails: "did not answer" is then the expected last
  line). Everything `./k3` makes is
  for its owner's eyes only (umask 077), and /boot/k3.bin on the server for root's.
- `make` assembles `src/os.asm` into `build/os.bin` (loaded at 1 MiB) and `build/disk.img`
  (`src/boot.asm` + the image; what the tests boot), with the site of `www/` in it.
  `python3 tools/sizes.py build/os.lst` = bytes per routine. (Of the system's 13,371:
  boot, page tables, driver and the other processors 2,500, network 3,700 with the
  timers, requests and the site's tables 600, TLS handshake and key schedule 1,530,
  SHA-256 450, curves 2,850 with their programs and constants, the two ciphers 1,250,
  certificate 230, and 320 of padding in front of the routines a handshake spends its
  time in: see HOT in "How the curve code works".) `make B=dir CERT=dir NAME=n
  IP=a.b.c.d SITE=folder P80=redirect HSTS=seconds KNOCK=a,b` builds another image: its
  identity, the name in a generated certificate, the address it answers on, what it
  serves, what port 80 does, and (development only) the two ports that reset it. The
  scripts take `B` from the environment. Only the address, the site and its settings are
  tracked: after changing another setting, `make -B`.
- `tools/pack.py FOLDER OUT` (what `make` runs): every file becomes its response (status
  line, headers, body), found through a hash table of paths. A folder's `index.html` is
  served at the folder's name with a slash, the name without it redirects there,
  `404.html` is what unknown paths get, files and folders whose names begin with a dot
  are left out (but `.well-known`). OUT/site.json says what each path must return (for
  the tests), OUT/page80.bin what port 80 says.
- `tools/suite.sh [JOBS] [name...]`: everything below, a few at a time, one line each
  (52 runs, three minutes). `SMP=1` or `SMP=4` in front for other machines than the
  default of 2 processors. Its verdict is strict: one failed connection is a FAIL. Under
  a loaded host a run that overflows rings on purpose (`raw1m_20k`) can time out a few
  hundred of a million (on 4 processors it does every time the suite runs five at once):
  run it alone before believing it. Don't edit a script the suite is running (see
  "Learned the hard way").
- `tools/sitetest.sh [quick]`, and over tap `unshare -Urn tools/sitetest.sh tap [quick]`
  with `LOSS=3`, `REORDER=25`, `MTU=600`, `SMP=n` in front: an image with the site of
  `tools/mksite.py` in it (80 files: sizes on and around every boundary a record can
  have, names that need escaping, a folder, one file of 1.5 MiB, so the image is over
  1 MiB and everything else lies higher) must serve every path as pack.py made it, to
  every kind of client `tools/sitecheck.py` plays: one connection or many, GET and HEAD,
  clients that take small segments, that read slowly, 16 at once, curl with each cipher,
  unknown paths, other methods, records that are no requests, requests in pieces, of
  3 KB, of over 4 KB, two at once, a client that closes its side, clients that go away.
  `ONLY=text` runs the checks with that in their name. `HOST=a.b.c.d PORT=443
  B=build-hz python3 tools/sitecheck.py quick` is the same against the server.
- Test images (make variables, each for its test): `ISNTOP=n ISNBITS=b` forces the top b
  bits (12) of every initial sequence number, so that what we send crosses 2^31 or 2^32
  (the suite's `*isn*` and `site_wrap*` runs); `KEYLIFE=n`: a connection's key seals 2^n
  records (`site_keylife`); `WXTEST=n`: do one thing the page tables forbid
  (`tools/wxtest.sh`: all five must be the machine's end); `WIN=n`: so many segments may
  be on their way to begin with (10).
- `./measure.sh` builds, boots the disk image in QEMU, fetches with curl (chain and name
  verified, fresh connections + keep-alive, each of the two ciphers by name, a client
  whose key share is for P-256, port 80, an unknown path, HEAD, and a check that curl
  refuses without our CA) and runs `tools/abuse.py` (forged, replayed, truncated records
  and bad ClientHellos, also in place of the second one after a HelloRetryRequest, must
  be ignored and leave real connections working; requests in pieces and pipelined on
  port 80). Ten seconds with KVM. Through slirp the guest's 443 is 127.0.0.1:`PORT`
  (8443) and its 80 is `HPORT` (PORT + 1000). It reads `NAME`, `SITE`, `P80`, `HSTS`
  from the environment like make, and checks what the image was built to do.
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
  `MEM=n` shape the VM (default 2 processors, 256 MiB), `KEX=P-256:X25519` makes the
  clients offer a key share we don't take (a HelloRetryRequest each). W can be up to 32
  (10.0.2.32-63: the second 16 share their low nibble with the first).
- Also in front of tap.sh: `DELAY=20` (what goes to the guest takes 20 ms: a round trip
  of that length; `curl -w %{time_total}` then shows what the window does) and
  `MON=path` (QEMU's monitor on a unix socket, with a short path: `info registers` and
  `xp /16xw ADDRESS` say where a guest that hangs is and what its memory holds).
- `REORDER=25` in front of tap.sh lets a quarter of the packets to the guest overtake the
  rest (held 5 ms). Timing single fetches with curl under it shows whether early segments
  are used: 9 of 60 stalled before `oohold`, none after.
- `make B=build-dbg DEBUG=1` builds an image that counts things (`count n` in the source)
  and shows six counters, four hex digits each, in place of the end of the page on port
  80: frames with a bad length or checksum, cycles per frame handled (an average since
  boot), connections refused for lack of room and frames lost to a full ring, early
  segments, resends, RSTs sent (those of the processor that answers; the page's first two
  digits are how many processors take frames, less 1, and which one answered). Four
  digits are the low 16 bits: 69,277 cycles a frame reads `0E9D`. This is how the
  reordering was found on the server and how the cost of a frame was taken apart. With
  `DEBUG=2` the fourth and sixth are instead the turns the polling loop made with nothing
  to do (in units of 4,096) and the time (in units of 2^24 cycles): how busy a processor
  is (`bench/busy.sh`). Not for images that are measured or kept running (and rawc, tapc
  and measure.sh's check of port 80 don't know its page).
- `python3 tools/jcc.py build/os.lst [ROUTINE...]` lists the jumps that cross or end on
  a 32-byte boundary (make runs it for the routines of `HOT` in the Makefile and says so
  if there are any); `... fit ROUTINE` says where a routine would have to begin to have
  none. See HOT in "How the curve code works".
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
- `tools/bench.c` (`gcc -O2 -o build/bench tools/bench.c -lssl -lcrypto`) measures rates,
  of k3 and of what it is compared with: P processes with W connections each; a
  connection is made, does the TLS handshake (1.3, X25519, AES-128-GCM unless `SUITES` or
  `KEX` say otherwise: `KEX='*X25519MLKEM768:*X25519'` is the 1.5 KB ClientHello with two
  key shares that browsers send; the chain is verified only with `CA=file`), fetches the
  page `KA` times, is closed with a reset and made again, for T seconds. `DST=ip:port`,
  `PLAIN=1` for port 80, `KA=1000000` for requests on connections that stay. It prints
  connections and requests a second, errors, timeouts (`TIMEOUT`, 10 s) and how long one
  took: median, 90%, 99%, 99.9%, longest. `bench/run.sh IP` is the eleven rows of the
  comparison, `bench/busy.sh IP ENV...` one run with how busy k3's processors were (a
  `DEBUG=2` image), `bench/hold.sh` 60,000 connections held with tapc; `bench/README.md`
  has the method, the other servers' configurations and the results.
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
sha_ni, no avx512ifma. RAM: 1 MiB to 0x7ffdc000 below 4 GiB, another 1,952 MiB above (to
0x17a000000).
Network: 1af4:1041 at 01:00.0, BAR 4 at 0xfd000000 (64-bit, but below 4 GiB),
common/ISR/device/notify structures at +0/+0x1000/+0x2000/+0x3000, notify multiplier 4,
rings of 256, **one queue pair** (no multiqueue on offer; it offers CSUM, GUEST_CSUM, TSO,
MRG_RXBUF, CTRL_VQ, EVENT_IDX, INDIRECT_DESC), MAC 92:00:0a:76:c2:50. Address
2.28.113.14/32, everything through the gateway 172.31.1.1 (d2:74:7f:6e:37:e3). Disk: 38 GB
on virtio SCSI (1af4:1048), Ubuntu 26.04 with GRUB 2.14.

SeaBIOS won't boot a disk of a few KiB: `disk.img` is 8 MiB, sparse.

## Running it on the server
`ssh root@2.28.113.14` works from the user's machine while the server runs Linux.
- `./k3 pack FOLDER -n 2.28.113.14 -i 2.28.113.14 -c cert-hz -o build-hz` (for the
  comparison's page: `./k3 pack www ... -o build-hzb --plain80`), then
  `./k3 deploy 2.28.113.14 build-hz --reset 'hcloud server reset k3'`: if Linux does not
  answer ssh (k3 is running), the server is reset; then the image is copied to
  /boot/k3.bin and the server reboots into it ONCE through a GRUB entry ("k3" in
  /etc/grub.d/40_custom, loaded with `multiboot`), and the command waits for a verified
  fetch. Ubuntu stays installed and is what any later reset boots. Up 4 s after the
  reboot (all 4 GiB are zeroed, and the curve tables take 25 ms).
- With `--persist`, Linux gets a unit (`k3-chain.service`) that starts k3 a minute after
  Linux has come up, unless /run/k3.hold exists: so k3 comes back by itself after a reset
  (90 s, measured), and `./k3 deploy`, which touches that file as soon as ssh answers,
  still gets in. Without `--persist` the next deploy takes the unit out again. The
  server runs 15kb.org with it since 2026-11-12 (`build-15kb.org`, `cert-15kb.org`):
  a deploy of anything else takes the site down, so put it back afterwards (`./k3
  deploy 2.28.113.14 build-15kb.org --persist --reset 'hcloud server reset k3'`).
  On its Linux: /boot/k3.bin, the GRUB entry, the unit, certbot and its account
  (/etc/letsencrypt: no key of the site's).
- The name: 15kb.org is the user's, at Namecheap, with Namecheap's name servers; `@` and
  `www` are A records for 2.28.113.14 (TTL 300), set through Namecheap's API with the
  settings of `~/.namecheap.env` (`namecheap.domains.dns.setHosts` replaces all records
  at once: read them first with `getHosts`). This machine's resolver kept the old answer
  for its 30 minutes: `curl --resolve 15kb.org:443:2.28.113.14`, or Chrome with
  `--host-resolver-rules="MAP 15kb.org 2.28.113.14"`, until it forgets.
- `curl --cacert build-hz/ca.pem https://2.28.113.14/` and `curl http://2.28.113.14/`
- By hand, with the reset knock (development only): `make B=build-hz CERT=cert-hz
  NAME=2.28.113.14 IP=2.28.113.14 KNOCK=$(tr ' ' , < build-hz/knock)` and
  `B=build-hz tools/deploy.sh root@2.28.113.14`.
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
- `hcloud` is set up on the user's machine (since 2026-11-11 the user lets Claude create,
  reset and delete servers with it): `hcloud server reset k3` is the reset button, and
  boots Linux (GRUB's default) whatever the image does. So an image that is measured
  needs no knock: build it without `KNOCK=`, deploy, measure, `hcloud server reset k3`.
- A load generator is a second server next to it, for an hour: `hcloud server create
  --name k3-load --type ccx33 --image ubuntu-26.04 --location nbg1 --ssh-key KEY --label
  purpose=k3-bench` (KEY from `hcloud ssh-key list`; the account's limit on dedicated
  cores allows one ccx33, a second generator has to be a shared type such as cpx42), then
  `bench/README.md`. It costs by the hour: `hcloud server delete k3-load` when done, and
  `hcloud server list` to see that nothing is left.
- The image never answers ping; the user's reset button in the Hetzner console is the
  fallback if a build doesn't come up or the knock doesn't work. A fault resets the
  machine by itself (there is no IDT), which boots Linux again; a hang does not.
- Be modest with load from the user's home connection: load comes from a generator next
  to the server (above). From here, for a look: `B=build-hz DST=2.28.113.14:443 build/tapc
  0.0.0.0 20000 400 www/index.html`, and with `PLAIN=1 INFLIGHT=32` and `DST=...:80` for
  port 80. Base ports below 32768.
- A browser against the server: `tools/nssdb.py DIR/.pki/nssdb build-hz/ca.pem`, then
  `HOME=DIR google-chrome --headless=new --no-sandbox --user-data-dir=DIR/c --dump-dom
  https://2.28.113.14/`; `tools/ffcheck.py https://2.28.113.14/ build-hz/ca.pem "Hello"`.

## The certificate (`tools/gen.py`, `cert/`)
- `cert/server.key` (ECDSA P-256) and `cert/server.pem` (leaf, then intermediates) are the
  identity that gets baked in. Nothing renews by itself: `./k3 renew` is the command to
  run from cron (Commands; a minute or two without a server when it is time, nothing
  before). To use a certificate from elsewhere, put those two files there (and no
  `ca.pem`); `tools/mkchain.py DIR` makes a realistic test chain.
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
- `src/os.asm`: everything after the loader, and at its end the site (`incbin`). 64-bit
  long mode, interrupts off, no IDT (a fault resets the machine), one polling loop per
  processor. Start-up, in 32-bit code as the loader leaves us: everything of ours below
  the table space zeroed, page tables for it (who may write and execute what), long
  mode. Then: the memory map into page tables (below), the table space zeroed and divided,
  SHA-256 constants, `ecinit` (fields, constants and tables for the curves, the programs
  unpacked), the start of the key schedule, virtio-net, the key for `prf`, the other
  processors.
  Code is 32-bit in style where it came from k2 (`pushad` is a macro for the eight old
  registers; r8-r15 belong to the crypto and are nobody's to keep). Addresses below 4 GiB
  live in 32-bit registers; a connection's slot does not (`rbp`).
- `src/boot.asm`: BIOS boot sector: reads the image, however long, 64 sectors at a time
  and copies each piece to where it goes from 1 MiB up (from real mode, with segments
  that reach all of memory: set anew for every piece, the BIOS may put them back), asks
  the BIOS for its memory map (int 15h, E820), protected mode, enters the image like a
  multiboot loader (the map in a multiboot information structure at ebx, as GRUB passes
  it). `tools/mkdisk.py` writes the image's length into it.
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
  In it: `.walk` (records, whole or put together), `.tx` (a response on its way).
- `record` (a client's record: authentic? a request? for which response), `geom` (how the
  response in hand is cut), `sendseg` (one segment of it), `tarm`/`tqrun` (who waits for
  an ack), `sm` (is this a connection past its handshake).
- `handshake`, `hrrmsg`, `thash` (the transcript's hash, continued, not restarted),
  `keys`, `hmac`, `expand`; `sha256`/`shablk`; `seal` with `chacha`, Poly1305, `aeskey`,
  `aesblk`, GHASH.
- `xdh`, `sign`, `stock`, `binv`, `comb`, `select`, `vm`, `fas`, `fmul`, `inv`, `ecinit`:
  the curves, see below.
- `tools/ec.py`: the curve code's other half: the programs, and a model of the arithmetic
  that the asm must match number for number. Read its docstring before touching either.
- `tools/gen.py`: certificate, curve programs and constants -> `build/*.inc`.
  `tools/pack.py`: the site -> `build/site.bin`, `site.inc`. `tools/ip.py`,
  `tools/mkdisk.py`: the baked-in address, the disk image. `k3`: the tool on top.
- `tools/mksite.py`, `tools/sitecheck.py`, `tools/sitetest.sh`, `tools/wxtest.sh`,
  `tools/jcc.py`, `tools/tlsprobe.sh`, `tools/k3test.sh`: the test site and its checker,
  the W^X test, the jumps on boundaries, a scanner's questions, the tool's own test.
- `tools/vm.sh`: QEMU command line and curl options, sourced by the test scripts
- `tools/bench.c`, `bench/`: the comparison with other servers (see Commands)
- `tools/ffcheck.py`, `tools/nssdb.py`, `tools/certerr.py`: the browser checks' helpers

## Memory
What the page tables say (`start`):
- The first 16 MiB as they are: the frame being handled at address 0 (`FR`: it stays as
  it came, so its fields are the packet's variables, `P_SEQ` and so on, a byte away from
  ebx = 0); the image at 1 MiB, up to 1 MiB of it; buffers and variables from 2 MiB
  (`BSS`; `OB` is our answer to one packet; the stack comes down from 4 MiB); virtio
  rings at 4 MiB (`VQ`) and behind them the page tables; receive and transmit buffers at
  5 and 7 MiB (`RXB`, `TXB`: 2 KiB each, descriptor i is buffer i, a 12-byte virtio header
  in front); the other processors' page tables at 9 MiB and their memory from 10 MiB.
- An image of more than 1 MiB (a site with large files) pushes all of that up, in whole
  pages of 2 MiB (`LOW`, known when it is assembled: pack.py says how long the site is):
  "2 MiB" in this file and in the source means 2 MiB + LOW. An image can have 768 MiB.
- Who may do what: the first 2 MiB are in pages of 4 KiB: low memory is data (written,
  never executed) but for the page the other processors start in (code); of the image
  the pages with code are executed and not written, the rest only read. Everything from
  BSS up, in pages of 2 MiB, is data. `CR0.WP` is set once start-up has made its last
  write to a page that is not to be written (the copy of `tramp`).
- Behind that, from 16 MiB up, **the table space**: every 2 MiB of RAM that the loader's
  memory map calls available, one after the other, wherever it is. On the server that is
  the rest of the 2 GiB below 4 GiB and then what is above. Boot divides it: n handshake
  buffers and n places of 2 KiB for early segments (n a power of two: about 1/32 and 1/64
  of it; one mask, `HSMASK`), 4 n SYNs of late (128 bytes each, and a dword for when:
  `tnote`), for each of four processors a ring of n frames (2 KiB each: `drain`) and a
  queue of 4 n connections that wait for an ack (64 bytes each: `tarm`), then the table
  for TLS (an eighth of the rest: `TSHARE`), then the table for port 80. In a 4 GiB
  machine n is 16,384, and the buffers, places, SYNs, rings and queues take 248 MiB of
  it; on the server (3,982 MiB of table space) that leaves 3.8 million TLS slots and 172
  million for port 80.
- The card's structures (and the local APIC), each in 4 MiB of its own in GiB 505.
Variables in BSS are reached relative to the instruction pointer (`BSS equ mb + ...`:
nasm won't do that for a plain number). Needs 64 MiB or more.

## Processors
The server's card has one receive queue, so the processors are fed in software. The
first one (the one that booted) empties the device's ring (`drain`): each frame is copied
into the ring of the processor whose connection it is (`prf` of its addresses and ports,
the low bits of the word that also picks the place of an early segment), its own
included. A ring holds n frames (16,384 in 4 GiB): with handshakes to make, that is half
a second of work; beyond that frames are lost, and clients send them again. Each
processor handles the frames in its ring, one at a time (`ring1`), with the same code.
The device's ring is small (256 on the server), and what finds no room in it is lost on
the host's side: so the first processor empties it before every frame it handles, and from inside whatever takes long
(`bdrain`: every 64 steps of the ladder, after each k G that `sign` has to make itself,
and while it waits for the transmit lock or a free transmit buffer).
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
  early segments (a place's low bits are its processor). The queue of connections that
  wait for an ack is each processor's own.
- They are started with INIT and SIPI to "all but self" (`tramp`, copied to 0x8000: from
  real mode straight to long mode); each takes a number with `lock xadd`. Frames go to
  the largest power of two of them (`NCPUM`). With one processor nothing changes but the
  uncontended lock.
- Not closed: a slot given up for being idle (full table, an hour of silence) is taken by
  another processor's `cmpxchg` while a packet of the idle connection could be arriving
  on its own processor in the same microsecond.

## How TCP works here
No copy of what was sent, except the handshake flight: everything else is made again
from what does not change. A connection knows the next byte it expects (`C_NXT`), our
next byte (`C_SND`) and the client's last ack (`C_ACK`). There are two ways of sending.
The old one, for the flight and for port 80 (whose answer is one response, the same for
every request): build all of it, send it at once, and build the end again when the
client turns out to lack it (`.resend`; the bullets from "In-order data" on). And the
one for files:

**A response on its way (`tcp.tx`).** A TLS connection past its flight (`sm`) has one
response in hand: which (`C_AS`: a number in the site; a bit for "only its head"), where
it began in our sequence numbers (`C_RS`), and the number of its first record (`C_SR`).
The response is a stretch of the image, cut into records of as many bytes as the
client's segments take (`geom`: 216, 536, 1220 or 1440, less 22 of record), so a
segment is a record, and segment number i of a response can be made at any time from
those three and i: nothing is kept, a file of a gigabyte costs a connection its 128
bytes.
- The client's acks let the next segments go. So many may be on their way as the client
  takes (its window: 64 KB at most, we have no window scaling) and as `C_CW` says: 10 to
  begin with, as many more as are acknowledged while nothing was ever lost (twice as
  many each round trip), half as many after a loss (2 at least), and from then on one
  more for every 16 KiB acknowledged. That is TCP's congestion control in a byte and a
  bit; without it (a fixed 10, the first version) 1.5 MiB took 2.2 s over a round trip
  of 20 ms, with it 0.6 s.
- Lost, says: an ack that repeats, once if no more than two segments are on their way
  (more such acks can't come), else three times (swapped neighbours look the same once
  or twice); then, an ack that moves on by no more than the segment sent again (the next
  one is lost too: had it arrived, the ack would have gone past it); the client sending
  old data again; and time (below). What goes again is the one segment at the client's
  ack, once per ack that asks.
- **The timer for what we sent** (`tarm`, `tqrun`). A connection that is owed something
  (an ack is outstanding, or the client's window is shut) is in its processor's queue,
  once: the first 64 bytes of a frame of its client's, the time, the ack. A polling loop
  with nothing else to do takes the oldest: not 2^29 cycles old yet (a quarter second
  on the server; twice as long for every time in vain, up to 16 s): to the back. Old
  enough: if the client has everything by now, that is that; if its ack has moved,
  back into the queue; if not, the segment at its ack goes again (and half as many may
  be on their way). As with SYN-ACKs: only when idle.
- A request for the next response is taken only when the client has acknowledged all of
  this one. One that comes earlier (two requests at once) is as good as not arrived, and
  what follows it in its segment too: the client sends it again (`.busy`).
- A response that goes at once and takes several segments does not acknowledge the last
  byte of the request until the client has all of it, as in the old way (`F_DEFER`):
  then even with every timer of ours lost, the client asks again. One that is longer
  than that is acknowledged at once: a client that waited minutes for an ack would give
  the connection up (Windows after five tries).
- The client's FIN (or a method we don't serve: `record` closes after its answer) makes
  the connection closed: nothing more is taken from the client, our FIN goes with the
  last segment of what it still has to get, and the slot is free when that is
  acknowledged.
- Sequence numbers go round: which of two is further on is the sign of their difference
  (`js`/`jns` after a `sub`), never a signed comparison (`jl`, `jle`: they look at the
  overflow as well). One `jle` stopped a response for ever where it crossed 2^31
  ("Learned the hard way"); the suite's `*isn*` and `site_wrap*` runs make every
  connection cross.

**Requests (`tcp.walk`, `record`).** What comes in on 443 is records. One that lies whole
in a segment is looked at where it is; one that does not (and every ClientHello) is put
together in a handshake buffer, up to 4 KB; one that says it is longer gets a reset. A
record counts if its tag is right for the client's next sequence number (`C_ST`); then
it is decrypted, and if it holds application data that begins with `GET ` or `HEAD `,
the path (up to a space, `?` or the line's end) is looked up in the site's table: the
response for it, or the one that says 404. What begins with another word in capitals
and a space gets the 405 and the end of the connection; anything else that is authentic
(an alert, a header line in a record of its own) counts and gets nothing.

The old way, and what both share:
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
  go out again) is reset. Later a connection takes one again for every record that comes
  in pieces, until the record is whole.
- A ClientHello without an x25519 key share gets a HelloRetryRequest as its whole flight
  (`hrrmsg`), and the connection goes on waiting for a ClientHello: all it keeps is the
  hash of the first one, where its keys will be (the transcript begins with that hash and
  with the request, which is made again from the second ClientHello: same session id,
  same suite). Clients send a ChangeCipherSpec record in front of the second one: while
  we wait for a ClientHello, a record that is not a handshake record is passed over.
- A client we can't serve gets seven bytes and our FIN: a fatal alert, "protocol version"
  if TLS 1.3 is not among the versions it offers (extension 43; a client of TLS 1.2 has
  none), "handshake failure" if neither of our cipher suites is among its, if x25519 is
  not among its groups (extension 10: then there is nothing to ask for), or if it sent no
  x25519 share after being asked. The alert is its connection's flight (kept, sent again
  if lost), and the connection is closed from our side (`handshake` sets F_CLOSED,
  `tcp.fin` sends the FIN). Before 2026-11-12 such a client got a ServerHello with a
  suite it had not offered, or with its own random as a key share: scanners call that
  intolerance, and it cost a handshake's work for every piece of junk. `tools/tlsprobe.sh
  HOST[:PORT] [CA]` asks what a scanner asks, one thing at a time.
- A segment from further on than we expect is kept (`oohold`) and used as soon as what
  comes before it has arrived (`.reply`). There are n places of 2 KiB for such segments; a
  client's place is picked by its hash and holds one segment, the earliest; two clients
  that share a place overwrite each other, and the loser's client retransmits. This
  matters on a real network: between the user's machine and the server, two segments sent
  back to back (a ClientHello in two parts; Finished and the request) arrive swapped 5-25%
  of the time. Dropping the early one cost a client timeout (+220 ms) on a quarter of all
  fetches; Linux on the same server counts the same swaps (TCPOFOQueue) and hides them the
  same way.
- The one thing sent unasked is a SYN-ACK again. A SYN gets no slot, so the SYNs of late
  are kept on the side (`tnote`: 4 n places, a client's picked by its hash, the frame as
  it came), and a connection made takes its SYN out. A polling loop that has no frame to
  handle goes round the places (`tidle`, 8 a turn); a SYN still there after 2^29 cycles
  (a quarter second on the server) goes through `tcp` once more, three times at most,
  one a tick (2^20 cycles) at most: a flood of SYNs gets at most 2,000 SYN-ACKs a second
  and processor on top of its own. Without it a lost SYN-ACK costs the client a second,
  and a retransmission timeout of 3 s for the rest of the connection. Only when idle:
  while frames wait in a processor's ring, the client's answer may be one of them (it
  ran on every frame at first, and under load the clients counted thousands of second
  SYN-ACKs for connections they had made long ago: `TcpInErrs` in nstat).
- Port 80 has no keys and no files: every request gets the same response (pack.py:
  where the site is, or its front page), and requests are found by counting line ends
  (`.plain`: two in a row, CRs ignored, end a request; a request body would be read as
  more request lines).

## The connection tables
- Two tables, one per port, so that a connection to port 80 costs 20 bytes (address, port,
  a byte of flags, a byte of time, `C_NXT`, `C_SND`, `C_ACK`) and a TLS connection 128: the
  same, then the number of the client's next record (`C_ST`), the response in hand
  (`C_SR`, `C_RS`, `C_AS`: ten bytes), its handshake buffer and how much of a record is
  in it, a byte of flags and counts (`C_FL2`), a byte of window (`C_CW`), and 88 bytes of
  keys (two of 32 with their 12 of iv; which cipher is a flag). They fill the table
  space behind the buffers: the TLS table gets an eighth (`TSHARE`), port 80 the rest.
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
- `HOT n` in front of a routine puts it n bytes behind a 32-byte boundary: the routines a
  handshake spends its time in (the hash, the ladder, the register machine, the field
  arithmetic, the ciphers) each lie where none of their jumps crosses such a boundary
  or ends on one. On Intel's processors from Skylake to Cascade Lake (the server's is
  one) such a jump is decoded again every time, and all that shares its 32 bytes with
  it. Where the jumps fall depends on every byte in front, so two builds differed by 6%
  in handshakes a second there, and by nothing here (Zen 2). It costs 320 bytes of
  padding. `tools/jcc.py` finds such jumps (make says so if one of these routines has
  one) and, with `fit`, the n for a routine that has been changed.

## Records
`seal` makes a record for some bytes and the byte that says what they are (handshake
messages, application data); or, the other way round (carry set), decrypts what a
client's record held and puts behind it the tag that record should have had, which
`record` compares before it looks at anything. The key block of a direction is 32 bytes
of key and 12 of iv; which cipher, `CIPH` says (0 ChaCha20-Poly1305, else AES-128-GCM:
from `SUITE` in the handshake, which is the first of the client's suites that is one of
ours, and from the connection's flag after it).
- ChaCha20: the state's four rows in xmm registers, a quarter round on all four columns
  at once (SSE2). Poly1305: 64-bit limbs, `mul`.
- AES-128-GCM: the key schedule is made again for every record (`aeskey`: 176 bytes would
  not fit a slot), four counter blocks at a time through the same loop that xors
  ChaCha20's key stream, GHASH with pclmulqdq (H kept times x, two folds by 0xC2..00;
  the steps were checked in a model against pyca first).
- A record of a small page: about 900 cycles either way; a full one (1,418 bytes of a
  file): some 8,000, a block at a time. Faster ciphers (several blocks at once) would
  show only where the network is not the limit.

## Shortcuts that remain
From k2, where they saved bytes, and from the first version that served files. Ask before
removing the ones about TLS.
- TLS 1.3 only, two suites: TLS_CHACHA20_POLY1305_SHA256 and TLS_AES_128_GCM_SHA256,
  X25519, ecdsa_secp256r1_sha256; who has none of these is told so (an alert) and
  nothing else. Of the ClientHello the cipher suites, the versions, the groups and the
  x25519 key share are looked at (`handshake` walks the extensions; every length on the
  way is bounded by the ClientHello's end, and what is looked at inside an extension by
  that extension's): no name (SNI), no ALPN (we speak HTTP/1.1 whatever the client
  offers), no signature algorithms (ours is ecdsa_secp256r1_sha256, which every TLS 1.3
  client must have).
- The client's Finished is not checked as such: it carries handshake keys, fails the tag
  check like any forgery, and is passed over. The first request proves the same thing.
- A bad record is passed over, not answered with an alert. No close_notify, no KeyUpdate
  (a client that changes its keys is not understood after that; a connection of ours
  ends before its key has sealed too much), no session tickets, no ChangeCipherSpec for
  middleboxes.
- A client record of more than 4 KB (a request with that many headers and cookies) ends
  the connection.
- No check for an all-zero X25519 result (a client can only weaken its own connection).
- After 2^32 records from the client its counter wraps to "no ClientHello yet": the
  connection is dead, the nonces never repeat.
- HTTP: GET and HEAD, the path compared byte for byte with what pack.py made of the file
  names (so `/a%20b.txt`, not `/a b.txt`; a query is cut off; no `..` to resolve: a path
  is in the table or it is not). A request is a record that begins with its request
  line: the line in pieces over several records is not found, and of two requests in
  one record the second is not seen. The request's headers are not read: no Host (one
  site), no If-None-Match (a browser gets the file again when its copy is too old), no
  Range, no Accept-Encoding (files go as they are), no `Connection: close` (the client
  has the Content-Length; we close first only after a 405). No Date header: there is no
  clock.
- Two requests at once: the second waits for the client's retransmission timer (0.2 s).
- TCP: no SACK, timestamps or window scaling (so 64 KB at most on their way), a first
  timeout of 2^29 cycles whatever the round trip is (a path slower than that gets a
  segment twice), and the old way (`tcp_send`) for the flight and port 80: all at once,
  no window. The IP header's checksum is not looked at: what we use of that header is
  fixed or goes into TCP's checksum, which is.
- Port 80: one response, whatever is asked; a request body is not understood.
- `keys` writes 20 junk bytes after an IV: the handshake makes both key blocks in `KA` and
  copies them into the slot.
- The handshake's scratch (transcript, key schedule, curve registers) is one per
  processor: one handshake at a time on each, start to finish, inside one call of `tcp`.
- Secrets are not wiped after use: the last handshake's are overwritten by the next, and
  unused nonces wait in the stock. (The private key is in the same memory, which is
  data: read, written, never executed.)
- The first page with data behind the code can be executed (code and what follows share
  it: 4 KiB at most, of constants, among them the key).
Gone since k2: the ground server random (it is random now), r and s forced to 32 bytes by
retrying, the tag compared with `repe cmpsb`, the calls through interrupt gates, the key
share found by searching the ClientHello for its first four bytes. Gone on 2026-11-12:
client data authenticated but never read, one page for every request, a record having to
arrive in one segment, no HelloRetryRequest, no timer but the one for SYN-ACKs, bare
line feeds in the response, memory that is written and executed.

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
  after netem). tapc prints the port of each failed connection, and why it failed.
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
- A ceiling is not ours until it is measured from inside. On the server plain HTTP stops
  at 35,000 connections a second and keep-alive at 130,000 requests, whatever is asked:
  k3's processors are 80 to 89% idle there (`DEBUG=2`, `bench/busy.sh`), a second load
  generator adds nothing (60,000 + 65,000), and one processor alone gets the same
  (133,000, 85% idle). It is the instance's network path: about 130,000 frames a second
  each way. The load generator had spare time too (its `/proc/stat`), which alone would
  not have told.
- What the load generator's own TCP counted says what kind of trouble it is (`nstat -n`
  before, `nstat` after): TcpExtTCPSynRetrans (a SYN or its answer lost, or kept waiting
  a second), TcpExtTCPTimeouts (the same for data), TcpInErrs (a SYN-ACK for a
  connection that was made long ago: ours, sent again). In the times: a median far above
  the round trip with a smooth tail is a queue; a step at 1 s is a SYN, at 200 ms a
  segment.
- With more connections in flight than can be served at once, what matters is where the
  frames wait. Rings of 4,096 lost 3% of them at 4,096 new TLS connections in flight (a
  count in `drain` showed it), and a client whose SYN was answered late takes three times
  that wait as its retransmission timeout: three losses in a row were ten seconds, 177
  connections in 120,000. Rings of 16,384: nothing lost, 99% done in 0.8 to 1.6 s, none
  over 10 s.
- Waiting to send is no reason not to receive: the transmit ring (256) fills in bursts
  (50,000 short waits in 12 s of new TLS connections), and while the first processor
  waited there for the device, nobody emptied the receive ring.
- One handshake in two million failed, and it took a million held connections on the
  server to see it twice: the client said "bad record mac". The key share was found by
  searching the ClientHello for the four bytes that introduce it (00 1d 00 20), as in k2.
  Clients now send a second, post-quantum key share in front of it (OpenSSL 3.5, Chrome,
  Firefox: X25519MLKEM768, 1,216 bytes that look random), and once in so many times
  those bytes are in there. We then took 32 bytes of it for the client's key, and the
  client could not read our answer. Found because tapc was made to print why a
  connection failed (it only gave the port); settled by a test that puts the four bytes
  into an earlier extension on purpose (`tools/abuse.py`), and by counting them in real
  ClientHellos (10 in 24 million of this machine's). A shortcut that was sound for the
  ClientHellos of its day can stop being so without a line of ours changing.
- nginx against BoringSSL (`bench/build-nginx-boring.sh`): the C++ runtime must not be
  dropped by the linker before the archives that need it: `--with-ld-opt="-L.../
  boringssl/build -Wl,--no-as-needed -lstdc++ -Wl,--as-needed -lpthread"`.
- `GROUPS=x command` gives the command nothing: bash keeps that name for itself. The rate
  client's option for key shares had it, and "two key shares" measured one until it was
  called `KEX`.
- `pkill -f` and `pgrep -f` did it again, twice in one night: a pattern that is in the
  command line of the shell that runs it (over ssh or here) kills that shell. `pkill -f
  "holdloo[p]"`.

- Sequence numbers are compared by the sign of their difference, not with a signed
  jump. `sub ebx, [C_SND]` / `jle` is wrong when the subtraction overflows, which it does
  exactly where a segment straddles 2^31: C_SND never moved on, the loop that sends
  never ended, and the machine sent one segment 110,000 times a second for ever. One
  download of 1.6 MB in 2,700 hits it (initial sequence numbers are random). It showed
  as a site test that stalled once in a few runs, looked like a matter of one processor
  and reordering (it was neither), and was found by capturing the storm: the same
  segment over and over, and its sequence number was 2147483206. Print the numbers as
  they are, not relative ones. `make ISNTOP=n` now puts every connection there.
- That test knob first forced all of the initial sequence number's upper bits, and under
  loss one handshake in 1,300 then failed, at 2^31 and anywhere else: the SYN cookie no
  longer said that a packet was the client's first, so the second segment of a
  ClientHello could begin a connection whose first was lost. A control (the same knob far
  from 2^31) told the knob's fault from the code's. It forces 12 bits now, and 17 only
  where nothing is lost.
- Where a jump lies can cost 6%, on one kind of processor and not on another (HOT in "How
  the curve code works"). The afternoon's image was 6% behind the night's at handshakes
  on the server, in every pair of runs, and equal to it here; its cycle counts per frame
  were the same, its crypto natively too. It was 130 bytes of new code in front of the
  SHA-256 loop. A regression that shows on one machine only may be where the code lies.
- The server is not the same machine from hour to hour (shared processors, and the
  network path: plain connections went from 35,000 a second in the night to 45,000 in
  the afternoon, handshakes from 9,000 to 8,000). Two images are compared in turn, in
  one session, several times each (`./k3 deploy --reset` makes that a loop).
- Clients send a ChangeCipherSpec record in front of their second ClientHello. Taking the
  first record for the ClientHello, as it had always been, made a handshake of those six
  bytes.
- `XEND` is an instruction (so are `XBEGIN`, `XTEST`): not a name for a constant. make
  can't have file names with spaces as prerequisites: the site's files are listed into a
  file whose change is what make sees.
- A script that bash is running must not be rewritten in place: bash reads on from where
  it was, in the new text (`ntf: command not found`, and a suite's last runs lost). Tools
  that edit write a new file and rename it; better still, don't edit what a background
  run uses.
- Through QEMU's own network (slirp) one connection in 20 waits a second when connections
  follow each other faster than 2 ms apart: QEMU takes them one at a time, and the host
  drops the SYN. It looked like a slow server (abuse.py's 1,565 ClientHellos took a
  minute); the night's image did the same.
- Claude's shell refuses long commands with a here-document it can't check ("could not be
  checked for dangerous rm operations"), also when nothing is removed: write the script
  with the Write tool and run that.

- A tool that is "to be run from cron" must be a no-op on most days, and must say so
  itself. `./k3 renew` reset the server and asked for a certificate every time it ran:
  every night without a server, and Let's Encrypt's limit (five of the same certificate
  in seven days) on the sixth. And where a key is made is where it stays: certbot's own
  key lands in /etc/letsencrypt on the server's disk, in a Linux that is supposed to
  hold nothing. A request (CSR) travels instead. Both were found by a review, not by a
  test: what never ran against the real thing has not been tested, however often its
  other half has.
- A ClientHello's extensions come in any order (Chrome shuffles them), and the short ones
  can be the last: a walk that wants 36 bytes behind every header, as the search for the
  key share did, would not see a `supported_versions` at the end.

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
- Getting past 130,000 frames a second on the server: telling the card that we take no
  interrupts (kept, it is the truth; no difference measured), a second load generator,
  the second processor left out so that the host has it: the same ceiling each time.
- The SYN-ACK timer on every frame handled: under load it fired for clients whose answer
  was waiting in our ring. It runs when a processor is idle.
- Dropping SYNs first when a ring fills, instead of whatever comes: the wait would move
  into the clients' SYN timers (1 s, 3 s, 7 s), which is worse for them than the same
  wait in our ring. Not done.
- A flood of small UDP packets to see what packet rate Linux takes on the same server: it
  would look like an attack to the provider. Not done.
- Session tickets: see Goal. Dropped by the user on 2026-11-12.
- A fixed number of segments on their way (10, what a connection may begin with) instead
  of congestion control: safe, and 14 KB a round trip for ever.
- The timer for what we sent in the SYNs' table (a place per client, picked by its
  hash): a SYN flood would have pushed the timers of real connections out. It has a
  queue of its own, in which a connection is once.
- Holding back the ack of the request's last byte for the whole of a long response (so
  that the client asks again whatever we lose): a client gives a connection up when its
  data stays unacknowledged for long (Windows after five tries, some ten seconds).
- Putting ACME, DNS or a clock into the image: the certificate is renewed from outside
  (`./k3 renew`), by packing a new image.

## Workflow
`./measure.sh` after every change (ten seconds; also once each with `DEBUG=1`, `KNOCK=`
and `LIFE=` images after touching boot or the loops: those builds move everything); `make
test` after touching crypto or ec.py (the model first: change `tools/ec.py`, run it, then
the asm); `tools/suite.sh` after anything else, and with `SMP=1` and `SMP=4` after
touching what the processors share or how the machine starts. make says if a routine a
handshake spends its time in has a jump on a 32-byte boundary: then `tools/jcc.py ... fit`
and a new number after `HOT`. After touching `.resend`, `.tx`, `sendseg`, `tcp_send`, the
handshake buffers or the cookie rules, also the lossy runs many times over (a loop of
`B=build-real LOSS=3 ... taprunc.sh 500 1024 4`, 16 or more, and the site test under loss
a few times): what is wrong there is wrong once in thousands. And a control: the same
runs on the last commit (`git worktree add`), or with the one thing changed back. Then
the server (`./k3 deploy`, `tools/sitecheck.py` against it, a browser) for anything that
could behave differently on a real machine, and `bench/run.sh` from a load generator
(bench/README.md), in turn with the image before, for anything that could change what it
does under load.
Commit when the user asks. (The night of 2026-11-11 was worked on a branch, `night`, with
a commit per step, because nobody was there to ask.)

The lossy runs of 2026-11-12, after the last change to the code:
- handshakes, 16 runs of 2,000 each (`... taprunc.sh 500 1024 4`): the two-segment flight
  at 3% loss; AES-128-GCM at 3%; the two-segment flight with a HelloRetryRequest at 3%;
  MTU 300 at 3%; the two-segment flight with reordering; the same across 2^31 at 3%;
  and at 5% loss with two minutes to wait. 224,000 handshakes, none failed.
- the site test over tap (`sitetest.sh tap quick`): 8 runs each at 3% loss, with
  reordering, with MTU 600 at 3% loss, and across 2^31 at 3% loss; 6 on one processor
  at 5% loss and 6 on four at 3%. 44 runs, every check of every run passed.
- after `handshake` learned to say no (the same day, later): the two-segment flight at 3%
  loss, the same with a HelloRetryRequest, MTU 300 with AES-128-GCM at 3%, and the
  two-segment flight with reordering, 16 runs of 2,000 each: none of 128,000 failed. And
  300 clients that can't be served (TLS 1.2), 20 at a time, at 10% and at 25% loss: each
  got its alert.
