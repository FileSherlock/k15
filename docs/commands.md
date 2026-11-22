# Commands

Every command, script and make variable. Rules for when to run which: CLAUDE.md, "Workflow".

- `./k15` is the tool for somebody who has a site and a server (its head says all of
  this at more length; what happens on the machine: docs/server.md):
  - `./k15 pack FOLDER [-n NAME] [--san NAME]... [-i IP] [-6 IP6] [-c CERTDIR] [-o OUT]
    [--plain80] [--hsts SECONDS] [--cache SECONDS] [--header 'Name: value']
    [--no-compress]` makes OUT/os.bin and OUT/disk.img. The image asks for its address
    where it boots (DHCP), so it is not tied to a machine; with `-i IP` it has that
    address, asks nobody, and is 514 bytes smaller; with `-6 IP6` it has that IPv6
    address as well (752 bytes). Port 80 redirects to https://NAME/ unless `--plain80`.
    `--san` is a further name for the certificate: the server does not look at the name
    it is asked for, so every name that points at it and is in its certificate gets the
    site (pack says which names the certificate in CERTDIR is not for). `--no-compress`:
    no file is packed a second and third time, compressed. How it was packed is kept in
    OUT/pack.conf.
  - `./k15 run [OUT] [-p PORT]` boots it in QEMU (https://127.0.0.1:8443/,
    http://127.0.0.1:9443/).
  - `./k15 publish SITE HOST -n NAME [pack's options] [--rescue 'COMMAND'] [--boot
    'COMMAND'] [--disk DEVICE] [--first] [--if-due] [--days N] [--email ADDRESS]
    [--staging]`: all of it in one step, with nothing kept here. The machine goes into
    its rescue system, shows the key of the certificate the site was serving, hands
    over key and certificate from the end of its disk (a new pair from Let's Encrypt if
    there is none, or it ends within N days (30), or lacks a name), SITE is packed,
    written over the disk and started. `--if-due`: nothing at all while the site is up
    with a certificate good for more than N days, so a workflow may run it daily
    (`ci/publish.yml`). `--first`: a machine that has nothing to show yet.
  - `./k15 deploy HOST [OUT] [--rescue 'COMMAND'] [--boot 'COMMAND'] [--disk DEVICE]
    [--first]`: the same last steps for an image packed here. The machine is held to
    the key that goes with OUT.
  - `./k15 deploy HOST [OUT] --grub [--persist] [--reset 'COMMAND']`: OUT/os.bin beside
    the Linux of a server that keeps one, started by GRUB (docs/server.md, "Beside a
    Linux").
  - `./k15 renew HOST [OUT] [--rescue 'COMMAND' ... | --grub --reset 'COMMAND'] [--days
    N] [--force] [--dry-run] [--email ADDRESS] [--staging]`: a new certificate from
    Let's Encrypt when the one OUT was packed with ends within N days (30), and nothing
    at all before that, so cron may run it daily. When it is time: a new key and a
    request are made here, certbot answers the challenge on port 80 of the rescue
    system (or of the server's Linux), OUT is packed again as OUT/pack.conf says, and
    started. If no certificate comes, the image as it was is started again. `--force`
    for the first one (the private CA's lasts until 2049); `--staging` for Let's
    Encrypt's test server (nobody trusts its certificate, so "did not answer" is then
    the expected last line).
  The key is never on a server but inside the image, and in the last 64 KiB of the disk
  of a machine that is k15's alone. Everything `./k15` makes is for its owner's eyes
  only (umask 077), and /boot/k15.bin on a server with Linux for root's.
- `make` assembles `src/os.asm` (and the files of `src/` it includes) into `build/os.bin`
  and `build/disk.img` (`src/boot.asm` + the image; what the tests boot), with the site of
  `www/` in it. It assembles twice: once to see where the code ends (`build/os.sizing`,
  which is emptied again: it is an image), and then for an image that is loaded so many
  bytes above 1 MiB (`build/delta`, a `-DDELTA=n`) that its code ends where a page does
  (docs/internals.md, "Memory"). By hand, `nasm` wants that define, and refuses any other
  number. `make B=dir CERT=dir NAME=n IP=a.b.c.d IP6=addr SITE=folder P80=redirect
  HSTS=seconds CACHE=seconds HEADERS='Name: value' COMPRESS=0` builds another
  image: its identity, the name in a generated certificate (`SAN='a b'`: its further
  names), the address it answers on (without `IP`: the one it is given where it boots;
  `IP6`: an IPv6 address beside it), what it serves, what port 80 does, the headers every
  file gets, and whether files are packed compressed too. The scripts take `B` from the environment. Only the address, the names,
  the site and its settings are tracked: after changing another setting, `make -B`.
- `python3 tools/sizes.py build/os.lst` = bytes per routine. Of the system's 14,552
  with an address of its own, about: boot, clock calibration, page tables, driver and
  the other processors 2,710; network 4,390 with the timers; requests and the forms of
  a file 740; TLS handshake and key schedule 1,650; SHA-256 450; curves 3,450 with
  their programs and constants; the cipher 1,000; certificate 230; among them 70 of
  padding in front of the routines a handshake spends its time in (HOT in "How the
  curve code works"). With the DHCP client (the default) it is 15,066, and with IPv6
  as well 15,786: 520 and 731 bytes of code more, and 64 and 53 of that padding,
  which goes by what happens to lie in front of those routines. Whose segment it is costs 26 bytes, zeroing what loaders left where code
  can run 7, the ChangeCipherSpec in our flight 10, and what the audit's 4 to 7, 11
  and 13 asked for 55: a ClientHello's type, length and compression methods 36, the
  ServerHello's own version 12, a small MSS refused 8, a record without a content
  type 4, jumps that got longer 6, and any word for a method 11 fewer than a word in
  capitals did. The 400 for a request without Host costs 38, the inversion's addition
  chain 97 (64 of code, the chain 25, its counts of squarings 8), and what else the
  key exchange got to be faster 352: an add and subtract of its own for 2^255 - 19
  96, a squaring 170, a multiplication by a number of one limb 55, and the two as
  operations of `vm` 24, with the padding they moved. That nothing but code
  can be executed costs no padding.
- **Is an image what this source makes?** Every build writes `OUT/made`: the commit, the
  assembler, what the assembler was told (the defines, `DELTA` among them; the ten
  numbers of site.inc; the certificate chain's hash), how the site was packed and with
  what, and three
  hashes of the image **without its key**: of the system, of the site, of both. No
  secret is in it; `./k15 pack` prints the hashes. `make KEYLESS=1` (or `KEYLESS=1
  ./k15 pack ... -c DIR`, DIR holding server.pem alone) makes that image from the
  certificates: the same bytes as the one with the key, but for the key's 32, and it
  cannot sign. `tools/repro.sh system MADE CHAIN.pem` makes the system part of
  somebody else's image again from this checkout, their `made` and the certificates
  their server shows (`openssl s_client -showcerts`), and says whether it is the same
  bytes: the site is not needed for that, nor what compressed it; the assembler has to
  be the one `made` names (NASM 3.01 here: whether another version makes the same
  bytes has not been tried). `tools/repro.sh` alone (seconds; the suite's `repro`)
  checks that this holds: an image made twice (another folder, umask, time zone,
  language, order of files) is the same bytes; made without the key it differs in
  those 32 bytes and nowhere else; and its system part made from `made` and the
  certificate alone is the same again.
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
  has but Cache-Control; a folder's redirect, the 405 and the 400 have the HSTS one; port 80
  has none (a browser may not believe it there). OUT/site.json says what each path must
  return (for the tests), OUT/page80.bin what port 80 says.
- `tools/suite.sh [JOBS] [name...]`: everything below, a few at a time, one line each
  (85 runs, twenty minutes; the logs in `$LOGS`, which its last line names). `SMP=1` or
  `SMP=4` in front for other machines than the default of 2 processors. Its verdict is strict: one failed connection is a FAIL. Under
  a loaded host a run that overflows rings on purpose (`raw1m_20k`) can time out a few
  hundred of a million (on 4 processors it does every time the suite runs five at once):
  run it alone before believing it. Don't edit a script the suite is running (`docs/pitfalls.md`).
- `tools/sitetest.sh [quick]`, and over tap `unshare -Urn tools/sitetest.sh tap [quick]`
  with `LOSS=3`, `REORDER=25`, `MTU=600`, `SMP=n` in front: an image with the site of
  `tools/mksite.py` in it (80 files: sizes on and around every boundary a record can
  have, names that need escaping, a folder, one file of 1.5 MiB, so the image is over
  1 MiB and everything else lies higher) must serve every path as pack.py made it, to
  every kind of client `tools/sitecheck.py` plays: one connection or many, GET and HEAD,
  clients that take small segments, that read slowly, 16 at once, curl,
  clients that take gzip or brotli (in every spelling of Accept-Encoding the checker
  knows, "q=0" among them), clients that have a file (each form by its own ETag: alone,
  in a list, weak, in small letters; and other headers with an ETag in them),
  unknown paths, other methods, requests without Host, records that are no requests,
  requests in pieces, of 3 KB, of over 4 KB, two at once, a client that closes its side,
  clients that go away.
  Over tap the card cuts our frames (TSO), through QEMU's own network it does not:
  `NOTSO=1` in front builds an image that never asks it to (the suite's
  `site_notso_loss3`). `SUITES=...` in front makes the checker's clients offer those
  suites alone (by themselves they offer OpenSSL's three, and get AES-128-GCM).
  `ONLY=text` runs the checks with that in their name; `BIG=n`: the large file has n
  MiB; `NOBUILD=1`: the image is there already. `HOST=a.b.c.d PORT=443
  B=build-hz python3 tools/sitecheck.py quick` is the same against the server.
  `GONE=1` in front (over tap; the suite's `site_gone`, three minutes) adds a client that
  vanishes in the middle of a file: what it sends is dropped on its way out (`ip rule
  add blackhole from` its address), the server's reset for it must be seen on the wire
  between 50 and 170 s later, and a second client, which only stopped reading, must
  still get its file after that.
- Test images (make variables, each for its test): `ISNTOP=n ISNBITS=b` forces the top b
  bits (12) of every initial sequence number, so that what we send crosses 2^31 or 2^32
  (the suite's `*isn*` and `site_wrap*` runs); `KEYLIFE=n` and `STLIFE=n`: a connection's
  key seals 2^n records and a client sends 2^n records (`site_keylife`); `WXTEST=n`: do
  one thing that must be the machine's end (`tools/wxtest.sh`, the suite's `wx`: 1 to 5
  and 9 to 11 what the page tables forbid: writing to the code or the site, running the
  stack, the site's first and last byte that says "return", a packet buffer, what lies
  right behind the code, and what a loader left in front of it; 12: nothing is left of
  what the boot sector read through the page the other processors start in; 6 and 7 a
  fault while the frame in hand reads as an interrupt gate to our own code, on the
  first processor and on another; 8 a random number generator that says the same
  twice), and with it `WXOPEN=1`, that test's control: the first page behind the code
  can be executed and what loaders left is left, so that what is run there comes back
  (`WXPAD=1`: 64 bytes more of code, for a test image that would lie at 1 MiB exactly);
  `WIN=n`: so many segments may
  be on their way to begin with (10); `NOTSO=1`: a segment a frame, whatever the card
  offers; `BIGSH=n`: 2^n buffers a processor for the frames the card cuts (3; with 0 or
  1 a frame waits for the device to have sent the one before: the way to test that);
  `RACE=n`: what two processors can do to each other in a nanosecond, held still or done
  on purpose (`tools/racetest.sh`).
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
  verified, fresh connections + keep-alive, AES-128-GCM wherever a client names it and
  "handshake failure" for one that offers ChaCha20-Poly1305 or AES-256-GCM alone, a client
  whose key share is for P-256, port 80, an unknown path, HEAD, and a check that curl
  refuses without our CA) and runs `tools/abuse.py` (forged, replayed, truncated records
  and bad ClientHellos, also in place of the second one after a HelloRetryRequest, must
  be ignored and leave real connections working; what a ClientHello has to be, and
  the alert for each thing it is not; any method but GET and HEAD, in whatever
  letters, gets the 405; a record of zeros with no content type ends its connection;
  requests in pieces and pipelined on port 80). Ten seconds with KVM. Through slirp the guest's 443 is 127.0.0.1:`PORT`
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
  `TIMEOUT=10` makes a hung connection fail fast instead of after 60 s, `SUITES=...`
  picks the suites the clients offer (OpenSSL's own order gets AES-128-GCM),
  `NOMARK=1` leaves out the fetches on the way (then `open_s` is the handshakes alone:
  the rate), `PLAIN=1 INFLIGHT=64` runs the same over plain HTTP to port 80, `SMP=n` and
  `MEM=n` shape the VM (default 2 processors, 256 MiB), `KEX=P-256:X25519` makes the
  clients offer a key share we don't take (a HelloRetryRequest each). The guest is
  10.0.2.15: by its image, or because `tools/dhcpd.py`, which tap.sh starts, gives it
  that (`DHCPD='COMMAND'`: another DHCP server; `DHCPD=none`: none, and COMMAND is not
  kept waiting for the guest, unless `STATIC=1` says the image has its address). W can
  be up to 32
  (10.0.2.32-63: the second 16 share their low nibble with the first).
- Also in front of tap.sh: `DELAY=20` (what goes to the guest takes 20 ms: a round trip
  of that length; `curl -w %{time_total}` then shows what the window does) and
  `MON=path` (QEMU's monitor on a unix socket, with a short path: `info registers` and
  `xp /16xw ADDRESS` say where a guest that hangs is and what its memory holds).
  `tools/pcap.py FILE CLIENT_IP [PORT]`: one connection out of a capture, a line a
  packet.
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
  is (`bench/busy.sh`). With `DEBUG=3` they are, on the first processor, how often it
  asked DHCP for an address or to keep its own, and how often a yes was taken: a lease
  renewed is one more of each. `DHMAX=n` beside it (a trial) lets no lease count as longer
  than n seconds, so that is seen after n/2 and not after half a day. Not for images that
  are measured or kept running (and rawc, tapc and measure.sh's check of port 80 don't
  know its page).
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
  X25519 (all 518), AES-128-GCM (those with our sizes of key,
  nonce and tag: opened, and sealed), HMAC-SHA256, against RFC 6979's two signatures
  for P-256 with SHA-256, and against OpenSSL's point multiplication for nonces and
  hashes on the edges (`test/outside.py`, which says what each takes for granted).
  `make ct` (ten seconds): the host build under Valgrind's memcheck with every secret
  marked as undefined memory: a jump decided by one, or an address made of one, is an
  error. Six runs with such a jump or address planted must each be found
  (`test/ct.c`).
  `unshare -Urn tools/tlsfuzz.sh [NAME...]` (three minutes): 30 of tlsfuzzer's scripts
  for TLS 1.3 against the image in `build/`, over tap: 1,300 conversations, most of
  them wrong in one place. The server must still serve after each script; a
  conversation may fail only if the script's line in `tools/tlsfuzz.sh` names it, with
  the shortcut of ours that is the reason. `tools/tlsfuzz.py SCRIPT -h HOST -p PORT`
  is one script by itself, and says what it does to make the scripts fit us.
  `unshare -Urn ./tap.sh python3 tools/hellofuzz.py [N] [SEED]` (a minute; the suite's
  `hellofuzz`): 20,000 ClientHellos as OpenSSL makes them, each with bytes changed,
  lengths set wrong, parts cut, grown or copied about at random. The server must
  answer or not, and go on serving: a real client is sent in after every 500.
  `unshare -Urn ./tap.sh python3 tools/rawtest.py [SEED]` (seconds; the suite's
  `rawframes`): 3,200 frames that are wrong below TCP, as only a sender on the same
  link can make them: IP total lengths of less than the headers, frames that end in
  their headers, headers of other lengths than they say. The machine must still be
  there.
  `unshare -Urn ./tap.sh python3 tools/acktest.py` (seconds; the suite's `ack`):
  segments in a client's name that are not the client's. Frame by frame on ports 80
  and 443: a SYN whose client takes less than 216 bytes in a segment gets a RST, one
  that takes 216 its answer; a request, a FIN or bytes whose ack is for what we never sent, or older
  than anything can be, get a bare ack and nothing of them is taken, also after a SYN
  has come again for the connection; one whose ack is merely old is answered; a
  client that comes again from the same port, with sequence numbers far from its old
  ones or among them, is a new connection in the old one's place; an ack for all we
  sent, with a sequence number a megabyte from the client's, lets nothing go of what
  waits for it, and the client's does; a RST ends a connection at the number our acks
  have said and at no other (a byte before, a byte behind; and, while a long answer's
  segments hold the client's last byte back, not where the client's own numbers are).
  And a real client's connection, into which 21 such segments are sent, fetches the
  page again. (Against the image before these rules 15 of those 29 checks fail; without
  the sequence number's check 3, without the ack's 10, with a RST taken at the next
  number we expect 2; and each of the two clients that come again gets nowhere if its
  way to a new connection is cut.)
- `unshare -Urn tools/dhcptest.sh` (a minute; the suite's `dhcp`, and `dhcp_smp4`): the
  image's DHCP client against a server that does what the test wants
  (`tools/dhcptest.py`, made of `tools/dhcpd.py`). It must ask again when nobody
  answers, each time with a new number; take no notice of what is not a server's
  answer to the question it is asking (another number, an earlier question's, a wrong
  checksum, other ports, a message cut short, options longer than the message, an
  answer when it asks nothing); ask the server that offered for the address offered,
  and no second server; take a yes only to that address, and serve on it and on no
  other; ask to keep it at half its time; take an answer without a UDP checksum; give
  the address up when told no, ask anew and serve on the new one; and be there after
  13,000 answers damaged at random. `... dhcptest.sh real` (80 s; `dhcp_dnsmasq`) is
  the same image against dnsmasq: an address, and a minute later the renewal. The
  suite's `static_*` runs are an image built with `IP=10.0.2.15`, over tap without any
  DHCP server.
- `unshare -Urn tools/racetest.sh 1` (and `2`; the suite's `race1` and `race2`, three
  minutes each): an image built `RACE=n IDLE=1 CAP=32`, in which the timer of a
  connection that may be taken stops for up to 30 s, before it has said "in use" (1) or
  after (2), and a new connection that finds no room. Whoever is second must get
  nothing (`tools/racetest.py`). `... racetest.sh 3` (`race3`, five seconds): an image
  built `RACE=3 CAP=16`, in which the one free slot of a bucket is somebody else's
  between being counted and being taken; the connection must then not be made anywhere
  else.
- `B=build-site6 unshare -Urn ./tap.sh python3 tools/v6test.py` (seconds; the suite's
  `v6`): an image built with `IP6=fd00:15::15`, frame by frame: the neighbour
  advertisement for whoever asks for our address, and nothing for six kinds of other
  question; a SYN-ACK from our address and none for five kinds of SYN that are not for
  us or not as we take them; a file in records of 1,220 bytes; 3,000 frames with wrong
  lengths. The tap has fd00:15::2 and ::32 to ::63 when the image has such an address,
  and `V6=1` in front of `taprunc.sh` and `tools/sitetest.sh tap` makes their clients
  come that way (the suite's `tls6*`, `plain6*`, `real6*`, `hrr6*`, `site6*`; `small6`:
  four addresses with the same ports into 1,024 slots, which shows whether clients are
  told apart; `v6_tls4_loss3`, `site4_v6_loss3`: the same images over IPv4).
- `B=build-site DELAY=300 unshare -Urn ./tap.sh python3 tools/rtttest.py` (a quarter of
  a minute; the suite's `rtt`): over a round trip of 300 ms, with nothing lost, no
  segment of a response may go twice (a page of one segment on a connection that
  stays, a file of 200 KB). A timer of a quarter second for everybody sends 26 twice.
- `unshare -Urn tools/hosttest.sh` (a minute; the suite's `host`): `./k15 publish`,
  `deploy` and `renew` against a machine that is made up: its disk a file, its rescue
  system this shell with `lsblk`, `blockdev`, `blkdiscard`, `reboot`, `apt-get` and
  `certbot` replaced (the last by a certificate authority of the test's own), ssh a
  script (`K15_SSH`), and "start from the disk" a QEMU on that file whose ports are
  127.0.0.1's in an otherwise empty network. 24 checks, from "a machine with a Linux
  on its disk is not written to" to "a machine whose key file has the site's public
  half and another secret is sent nothing"; `V=1` in front shows what the tool says.
- `SMP=3 MON=/tmp/k15mon unshare -Urn ./tap.sh python3 tools/cputest.py` (the suite's
  `cpus3`): asks QEMU's monitor which processors are halted. Those that take no frames
  must be (the third of three; the fifth and on), and no other.
- `make test` checks the asm crypto (`src/os.asm` built with `-DHOST`, driven by
  `test/test_asm.c` and `test/test_crypto.py`) against pyca/cryptography (hashes, AES-128-GCM, X25519 with edge
  scalars, 70 signatures) and against the model (every pair of 22 edge numbers through
  add, subtract and multiply in each of the three fields), and runs `tools/ec.py`, the
  Python model of the curve code. `make bench` times the same object natively, down to
  one multiplication, and a record of a small page and of a full segment.
- KVM is used when /dev/kvm is there; `KVM=0` emulates. `tools/vm.sh` reads `KVM` when it
  is sourced, not when `boot` runs.
