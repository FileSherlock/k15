# Commands

Every command, script and make variable. Rules for when to run which: CLAUDE.md, "Workflow".

- `./k15` is the tool for somebody who has a site and a server:
  `./k15 pack FOLDER [-n NAME] [--san NAME]... [-i IP] [-c CERTDIR] [-o OUT] [--plain80]
  [--hsts SECONDS] [--cache SECONDS] [--header 'Name: value'] [--no-compress]` makes
  OUT/os.bin and OUT/disk.img (port 80 redirects to https://NAME/ unless `--plain80`;
  `--no-compress`: no file is packed a second and third time, compressed; `--san` is a
  further name for the certificate, `www.NAME` say: the server does not look at the
  name it is asked for, so every name that points at it and is in its certificate gets
  the site; pack says which of the names the certificate in CERTDIR is not for, and
  renew asks for all of them); `./k15 run [OUT]` boots it in QEMU
  (https://127.0.0.1:8443/, http://127.0.0.1:9443/); `./k15 deploy HOST [OUT] [--persist]
  [--reset 'COMMAND']` puts it on a server that runs Linux with GRUB and starts it (see
  "Running it on the server"); `./k15 renew HOST [OUT] --reset 'COMMAND' [--days N]
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
  line). Everything `./k15` makes is
  for its owner's eyes only (umask 077), and /boot/k15.bin on the server for root's.
- `make` assembles `src/os.asm` into `build/os.bin` (loaded at 1 MiB) and `build/disk.img`
  (`src/boot.asm` + the image; what the tests boot), with the site of `www/` in it.
  `python3 tools/sizes.py build/os.lst` = bytes per routine. (Of the system's 14,491,
  about: boot, clock calibration, page tables, driver and the other processors 2,700,
  network 4,300 with the timers, requests and the forms of a file 700, TLS handshake
  and key schedule 1,600, SHA-256 450, curves 3,000 with their programs and constants,
  the two ciphers 1,650, certificate 230; among them some 250 of padding in front of the
  routines a handshake spends its time in: see HOT in "How the curve code works". Of the
  874 that the night of 2026-11-12 added: frames for the card to cut 450, window scaling
  and what goes with it 130, the forms of a file 290; `seal` got faster in the same
  bytes.) `make B=dir CERT=dir NAME=n IP=a.b.c.d SITE=folder P80=redirect HSTS=seconds
  COMPRESS=0 KNOCK=a,b` builds another image: its identity, the name in a generated
  certificate (`SAN='a b'`: its further names), the address it answers on, what it
  serves, what port 80 does, whether files are packed compressed too, and
  (development only) the two ports that reset it. The scripts take `B` from the
  environment. Only the address,
  the names, the site and its settings are tracked: after changing another setting,
  `make -B`.
- `tools/pack.py FOLDER OUT` (what `make` runs): every file becomes its response (status
  line, headers, body), found through a hash table of paths. A folder's `index.html` is
  served at the folder's name with a slash, the name without it redirects there,
  `404.html` is what unknown paths get, files and folders whose names begin with a dot
  are left out (but `.well-known`). A file's other forms lie behind it in the table of
  responses, and its flags say which there are: its 304 (the next one: for every file
  longer than that answer; it begins with the ETag, which is 16 hex digits of a hash of
  the whole response, so any header changes it), the file with gzip (two on) and with
  brotli (four on), each with its own ETag and 304. A compressed form is kept if the
  response then takes at least one record less and is a tenth shorter (so not for a
  page of one segment, nor for what is compressed already); brotli comes from the
  Python module, from libbrotlienc (every curl is linked with it) or from the command,
  and if there is none, gzip is all (pack says so). `Vary: Accept-Encoding` is on every
  form of a file that has more than one. The page for unknown paths has every header a file
  has but Cache-Control; a folder's redirect and the 405 have the HSTS one; port 80 has
  none (a browser may not believe it there). OUT/site.json says what each path must
  return (for the tests), OUT/page80.bin what port 80 says.
- `tools/suite.sh [JOBS] [name...]`: everything below, a few at a time, one line each
  (61 runs, seven minutes). `SMP=1` or `SMP=4` in front for other machines than the
  default of 2 processors. Its verdict is strict: one failed connection is a FAIL. Under
  a loaded host a run that overflows rings on purpose (`raw1m_20k`) can time out a few
  hundred of a million (on 4 processors it does every time the suite runs five at once):
  run it alone before believing it. Don't edit a script the suite is running (`docs/pitfalls.md`).
- `tools/sitetest.sh [quick]`, and over tap `unshare -Urn tools/sitetest.sh tap [quick]`
  with `LOSS=3`, `REORDER=25`, `MTU=600`, `SMP=n` in front: an image with the site of
  `tools/mksite.py` in it (80 files: sizes on and around every boundary a record can
  have, names that need escaping, a folder, one file of 1.5 MiB, so the image is over
  1 MiB and everything else lies higher) must serve every path as pack.py made it, to
  every kind of client `tools/sitecheck.py` plays: one connection or many, GET and HEAD,
  clients that take small segments, that read slowly, 16 at once, curl with each cipher,
  clients that take gzip or brotli (in every spelling of Accept-Encoding the checker
  knows, "q=0" among them), clients that have a file (each form by its own ETag: alone,
  in a list, weak, in small letters; and other headers with an ETag in them),
  unknown paths, other methods, records that are no requests, requests in pieces, of
  3 KB, of over 4 KB, two at once, a client that closes its side, clients that go away.
  Over tap the card cuts our frames (TSO), through QEMU's own network it does not:
  `NOTSO=1` in front builds an image that never asks it to (the suite's
  `site_notso_loss3`). `SUITES=TLS_CHACHA20_POLY1305_SHA256` in front makes the
  checker's clients offer that alone (by themselves they get AES-128-GCM): half of the
  suite's site runs do.
  `ONLY=text` runs the checks with that in their name. `HOST=a.b.c.d PORT=443
  B=build-hz python3 tools/sitecheck.py quick` is the same against the server.
  `GONE=1` in front (over tap; the suite's `site_gone`, three minutes) adds a client that
  vanishes in the middle of a file: what it sends is dropped on its way out (`ip rule
  add blackhole from` its address), the server's reset for it must be seen on the wire
  between 50 and 170 s later, and a second client, which only stopped reading, must
  still get its file after that.
- Test images (make variables, each for its test): `ISNTOP=n ISNBITS=b` forces the top b
  bits (12) of every initial sequence number, so that what we send crosses 2^31 or 2^32
  (the suite's `*isn*` and `site_wrap*` runs); `KEYLIFE=n`: a connection's key seals 2^n
  records (`site_keylife`); `WXTEST=n`: do one thing that must be the machine's end
  (`tools/wxtest.sh`: 1 to 5 what the page tables forbid; 6 and 7 a fault while the
  frame in hand reads as an interrupt gate to our own code, on the first processor and
  on another; 8 a random number generator that says the same twice); `WIN=n`: so many segments may
  be on their way to begin with (10); `NOTSO=1`: a segment a frame, whatever the card
  offers; `BIGSH=n`: 2^n buffers a processor for the frames the card cuts (3; with 0 or
  1 a frame waits for the device to have sent the one before: the way to test that).
- `tools/bneck.sh` (inside tap.sh, with an image built `NOTSO=1`): a bottleneck between
  guest and client, `BRATE` Mbit/s with a queue of `BQUEUE` packets, `BDELAY` ms each
  way, `BLOSS` % lost besides; it fetches a large file and says how long that took and
  how many packets the queue dropped. `CAP=file` captures at the client, and
  `tools/tl.py file` prints the timeline: new bytes, segments sent again and acks per
  quarter second. This is what shows what a window does on a path narrower than it
  (nothing else here does: over tap there is no queue to overflow).
  `tools/bnecktest.sh` is two such paths with times they must keep (the suite's
  `bneck`).
- `./measure.sh` builds, boots the disk image in QEMU, fetches with curl (chain and name
  verified, fresh connections + keep-alive, each of the two ciphers by name and in every order a client can
  name them in, a client
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
  TLS_CHACHA20_POLY1305_SHA256` picks the cipher (OpenSSL's own order gets AES-128-GCM),
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
  if there are any); `... mask ROUTINE` says where a routine may begin to have none, as
  the mask that `HOT` in the source takes (`fit`: and what would lie on a boundary at
  each place); `ROUTINE:loops` counts only the jumps inside its loops. See HOT in "How
  the curve code works".
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
  an hour). The test of that rule is `make B=build-small-idle1 CAP=1024 IDLE=1` (quiet
  for more than one unit of 64 s) and `B=build-small-idle1 unshare -Urn ./tap.sh python3
  tools/idletest.py`: the table for port 80 is filled, nobody new gets in, and 140 s
  later 200 new connections each take a quiet one's place and none the place of the 32
  that kept talking (three minutes; the suite's `idle`). `TSHARE=n` gives the TLS table
  1/2^n of the memory.
- `tools/bench.c` (`gcc -O2 -o build/bench tools/bench.c -lssl -lcrypto`) measures rates,
  of k15 and of what it is compared with: P processes with W connections each; a
  connection is made, does the TLS handshake (1.3, X25519, AES-128-GCM unless `SUITES` or
  `KEX` say otherwise: `KEX='*X25519MLKEM768:*X25519'` is the 1.5 KB ClientHello with two
  key shares that browsers send; the chain is verified only with `CA=file`), fetches the
  page `KA` times, is closed with a reset and made again, for T seconds. `DST=ip:port`,
  `PLAIN=1` for port 80, `KA=1000000` for requests on connections that stay. It prints
  connections and requests a second, errors, timeouts (`TIMEOUT`, 10 s) and how long one
  took: median, 90%, 99%, 99.9%, longest. `bench/run.sh IP` is the eleven rows of the
  comparison, `bench/files.sh IP [all]` the rows about files (wrk; each large one with
  OpenSSL's order of ciphers and with AES-128-GCM alone, and what the generator's TCP
  counted meanwhile), `bench/busy.sh IP ENV...` one run with how busy k15's processors
  were (a `DEBUG=2` image), `bench/hold.sh` 60,000 connections held with tapc;
  `bench/README.md` has the method, the other servers' configurations and the results.
- `tools/load.py` (through slirp, `PORT=`): `hold N`, `burst K`, `seq N` (handshake rate),
  `ka N` (keep-alive rate). Start a VM first: `source tools/vm.sh; boot` with `B`, `PORT`
  and `IMG=$B/os.bin` set.
- From outside, what was not written beside the code (`tools/outside.sh fetch` gets all
  of it into `ext/`, which is not in git: Wycheproof's vectors, tlsfuzzer with
  tlslite-ng, Ubuntu's Valgrind unpacked; no root):
  `make outside` (a second): the host build against Project Wycheproof's vectors for
  X25519 (all 518), ChaCha20-Poly1305 and AES-128-GCM (those with our sizes of key,
  nonce and tag: opened, and sealed), HMAC-SHA256, against RFC 6979's two signatures
  for P-256 with SHA-256, and against OpenSSL's point multiplication for nonces and
  hashes on the edges (`test/outside.py`, which says what each takes for granted).
  `make ct` (ten seconds): the host build under Valgrind's memcheck with every secret
  marked as undefined memory: a jump decided by one, or an address made of one, is an
  error. Six runs with such a jump or address planted must each be found
  (`test/ct.c`).
  `unshare -Urn tools/tlsfuzz.sh [NAME...]` (three minutes): 31 of tlsfuzzer's scripts
  for TLS 1.3 against the image in `build/`, over tap: 1,300 conversations, most of
  them wrong in one place. The server must still serve after each script; a
  conversation may fail only if the script's line in `tools/tlsfuzz.sh` names it, with
  the shortcut of ours that is the reason. `tools/tlsfuzz.py SCRIPT -h HOST -p PORT`
  is one script by itself, and says what it does to make the scripts fit us.
  `unshare -Urn ./tap.sh python3 tools/hellofuzz.py [N] [SEED]` (a minute; the suite's
  `hellofuzz`): 20,000 ClientHellos as OpenSSL makes them, each with bytes changed,
  lengths set wrong, parts cut, grown or copied about at random. The server must
  answer or not, and go on serving: a real client is sent in after every 500.
- `unshare -Urn tools/racetest.sh 1` (and `2`; the suite's `race1` and `race2`, three
  minutes each): an image built `RACE=n IDLE=1 CAP=32`, in which the timer of a
  connection that may be taken stops for up to 30 s, before it has said "in use" (1) or
  after (2), and a new connection that finds no room. Whoever is second must get
  nothing (`tools/racetest.py`).
- `make test` checks the asm crypto (`src/os.asm` built with `-DHOST`, driven by
  `test/test_asm.c`) against pyca/cryptography (hashes, both ciphers, X25519 with edge
  scalars, 70 signatures) and against the model (every pair of 22 edge numbers through
  add, subtract and multiply in each of the three fields), and runs `tools/ec.py`, the
  Python model of the curve code. `make bench` times the same object natively, down to
  one multiplication, and a record under each cipher.
- KVM is used when /dev/kvm is there; `KVM=0` emulates. `tools/vm.sh` reads `KVM` when it
  is sourced, not when `boot` runs.
