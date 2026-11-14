# k15 next to nginx and Caddy

What k15 does on its server, and what nginx (with BoringSSL and with OpenSSL) and Caddy do
on the same server with the same page, key and certificate. Measured in the night of
2026-11-11 to 12. Short version:

| on a 2-vCPU cloud server | k15 | nginx + BoringSSL | nginx + OpenSSL 3.5 | Caddy 2.6 |
|---|---|---|---|---|
| new TLS 1.3 connections a second (full handshake) | 8,800 - 9,100 | 3,900 - 4,100 | 2,100 - 2,200 | 1,700 - 1,850 |
| HTTPS requests a second, connections kept | 109,000 - 122,000 (1) | 47,000 - 48,000 | 37,000 - 40,000 | 9,000 - 12,000 |
| new plain HTTP connections a second | 30,000 - 35,000 (1) | 17,000 - 22,000 | 16,000 - 22,000 | 7,000 - 8,000 |
| HTTP requests a second, connections kept | 110,000 - 128,000 (1) | 60,000 - 71,000 | 58,000 - 68,000 | 14,000 |
| memory for a connection that is held: plain, TLS | 20 bytes, 128 bytes | 3.2 KiB, 7.1 KiB | 4.0 KiB, 25.8 KiB | not measured |
| what has to be on the disk | 11,094 bytes | 3.6 MB + a kernel (17 MB) | 9.1 MB + a kernel | 39 MB + a kernel |

(1) Not k15's limit: the server's network path carries about 130,000 frames a second each
way and k15's processors are 80 to 89% idle at that point (see "What limits whom"). The
other servers' numbers, and k15's new TLS connections, are what their processors can do.

## The machines
- The server: Hetzner cx23 in Nuremberg: 2 shared vCPUs (Xeon Skylake, 2.1 GHz), 4 GB,
  one virtio-net queue. For k15 it boots the image (GRUB, multiboot); for the others it
  runs Ubuntu 26.04 (kernel 7.0.0-30).
- The load generator: a ccx33 in the same location (8 dedicated vCPUs, Ubuntu 26.04),
  0.4 ms away (ping: 0.41 ms at best, 0.8 on average). A second one (cpx42) was added for
  one experiment.
- Shared vCPUs: the same row measured again differs by 10%, sometimes 15 (k15, new TLS
  connections: 64 in flight 7,561, 7,563 and 8,902 in three runs, 512 in flight 8,109 to
  9,471 in six; nginx + OpenSSL, 512 in flight: 1,926, 2,086 and 2,192).

## The client: `tools/bench.c`
8 processes, each with W connections "in flight": a connection is made, does the TLS 1.3
handshake (X25519, TLS_AES_128_GCM_SHA256, no session to resume: a full handshake every
time), fetches the page, is closed with a reset and made again. With `KA=1000000` it
stays and fetches again and again. The certificate is not verified in these runs (that is
the client's time; `tools/tapc.c`, which holds connections, verifies chain and name on
every one). It reports connections and requests a second and how long one took, from
`connect()` to the last byte of the response (or, on a kept connection, from the request).
"Timeouts" are connections that took more than 10 s.

Its ClientHello is small (one key share, 250 bytes). Browsers and OpenSSL 3.5 send two
key shares, a post-quantum one in front: 1.5 KB in two segments. One row asks that way
(`KEX='*X25519MLKEM768:*X25519'`).

`bench/run.sh IP` is the eleven rows below: 15 s each after a second of warm-up.

## The servers
All serve `www/index.html` (27 bytes) with the certificate and key of `cert-hz/` (ECDSA
P-256, the generated leaf and CA), TLS 1.3 only, X25519, no session tickets and no session
cache, on ports 443 and 80, logging nothing.
- k15: the image of commit "The key share is found by walking the ClientHello" (11,094
  bytes), built without `DEBUG`, `KNOCK` and `LIFE`.
- nginx 1.28.3 with OpenSSL 3.5.5, as Ubuntu packages them (`nginx-light`), with
  `bench/nginx.conf`: a worker per processor, `reuseport`, a backlog of 65,535, and
  `bench/setup-nginx.sh` for the kernel (the limits on queues and files raised, and
  receive packet steering on, so that both processors take packets from the one queue as
  they do under k15).
- nginx 1.28.3 built from nginx.org's source against BoringSSL (the commit of 2026-11-11,
  `-DCMAKE_BUILD_TYPE=Release`; `bench/build-nginx-boring.sh`), same configuration file.
- Caddy 2.6.2 (Ubuntu's package, not a recent Caddy; Go's crypto/tls) with
  `bench/Caddyfile`.

## Results
Connections or requests a second; then, in ms, the median and the 99th percentile.
"In flight" is how many connections the client keeps going at once (8 x W).

| | in flight | k15 | nginx + BoringSSL | nginx + OpenSSL | Caddy |
|---|---|---|---|---|---|
| HTTPS, a new connection each | 64 | 8,902 (6.8, 15.3) | 3,884 (15.0, 42.2) | 2,229 (26.5, 70.6) | 1,836 (34.1, 66.4) |
| | 512 | 8,832 (51.7, 140) | 3,887 (102, 347) | 2,086 (208, 571) | 1,846 (266, 508) |
| | 4,096 | 9,147 (430, 1,364) | 4,114 (850, over 2,000) | 2,199 (1,811, over 2,000) | 1,743 (over 2,000) |
| the same, asked as a browser asks (two key shares) | 512 | 9,101 (52.7, 133) | 3,817 (132, 337) | 2,477 (205, 460) | |
| HTTPS, connections kept | 64 | 109,360 (0.55, 1.24) | 46,906 (1.27, 3.11) | 39,572 (1.54, 3.48) | 12,336 (4.36, 17.3) |
| | 512 | 122,357 (4.02, 6.43) | 48,247 (10.3, 18.4) | 36,842 (13.7, 21.3) | 8,800 (53.8, 145) |
| HTTP, a new connection each | 64 | 29,938 (1.94, 4.93) | 17,487 (3.16, 9.88) | 15,550 (3.47, 11.6) | 6,808 (9.09, 20.9) |
| | 512 | 35,428 (13.8, 19.7) | 22,281 (18.1, 61.5) | 21,148 (19.6, 65.6) | 7,283 (70.5, 129) |
| | 4,096 | 34,455 (62.7, 1,110) | 21,706 (102, 1,323) | 21,940 (48.1, 1,320) | 7,780 (529, 1,441) |
| HTTP, connections kept | 64 | 110,280 (0.55, 1.22) | 59,815 (1.01, 2.67) | 58,370 (1.02, 2.57) | 14,084 (3.81, 15.3) |
| | 512 | 128,404 (3.86, 5.38) | 70,560 (6.64, 16.0) | 67,621 (7.09, 16.6) | 14,427 (34.3, 69.9) |

No errors anywhere. Timeouts (over 10 s): none, except for k15 in the 4,096 row of plain
HTTP: 83 of 517,000 connections in this run, and 1, 4 and 6 in three earlier ones (see
"With more in flight"). The HTTP rows of the two nginx columns are the same nginx version
doing the same work, the TLS library not involved: they show how much a row moves between
runs.

Per new TLS connection that is, of both processors' time: k15 460,000 cycles, nginx with
BoringSSL 1.0 million, with OpenSSL 1.9 million, Caddy 2.3 million. The curve arithmetic
is not where k15 gains. On the development machine, where both were timed (`make bench`,
`openssl speed`), OpenSSL signs with ECDSA P-256 in 71,000 cycles and does an X25519
multiplication in 113,000; k15 signs in 89,000 (2,000 when it made the nonce while idle)
and needs 209,000 for its key share and the shared secret together. (On the server
OpenSSL's two take 77,000 and 120,000.) k15 gains on everything around the arithmetic:
there is no kernel under it and no socket between the two, and a connection is 128 bytes.

### What limits whom
- nginx and Caddy: their processors (`vmstat` on the server: 0 to 6% idle in every row).
- k15, new TLS connections: its processors (2 to 5% idle; a `DEBUG=2` image and
  `bench/busy.sh`).
- k15, everything else: the path to it. With connections kept it levels off at about
  130,000 requests a second, with new plain connections at 35,000 (140,000 frames a
  second in), and at that point its processors are 80 to 89% idle. Two load generators at
  once get the same total (59,900 + 64,700 requests a second); k15 with one processor gets
  the same (133,000 HTTP requests a second at 15% busy, 126,000 HTTPS at 28%: 2,400 and
  4,800 cycles a request, the driver included). The load generator was not the limit
  either (its processes 80% idle, its one receive queue's processor half idle). What it
  is on the host's side could not be seen from inside the guest.
- So the three rows marked (1) say less than they could: on a path that carried more,
  k15 would do several times as much, and the others would not.

### With more in flight than can be served
4,096 connections in flight is more than any of the four can serve in less than half a
second. What happens then:
- k15 lets the frames wait (rings of 16,384 frames per processor). New TLS connections at
  4,096 in flight: 0.43 s at the median and 99% within 1.4 s in the run above; over six
  runs the median was 0.33 to 0.53 s and the 99th percentile 0.8 to 1.6 s; none took over
  10 s, and an image that counts found no frame lost. (With rings of 4,096, as they were
  when the night began, 3% of the frames were lost there and 177 connections of 120,000
  took over 10 s. With 16,384 in flight the rings overflow again: 245 of 100,000 over
  10 s, median 1.6 s.)
- nginx lets them wait in the kernel's queues: median 0.85 s (BoringSSL) and 1.8 s
  (OpenSSL), no connection over 10 s.
- On port 80, at 4,096 in flight, 1% of the connections take a second longer with every
  server: a SYN lost on the way (the client's own counters say so: `nstat`,
  TcpExtTCPSynRetrans). k15 at that point asks more of the path than it carries, nginx
  does not get that far; so k15 has the connections that lose their SYN four times running
  and take over 10 s (0.02% in the worst run), and nginx has none. An image that counts
  showed no frame lost in k15's own rings there. Where on the path they go was not found.

## The image that serves files (2026-11-12, afternoon)
Since the night k15 has become what it is meant to be: it serves the files of a site by
their paths (`tools/pack.py`), with headers as other servers send them, reads requests
of up to 4 KB, sends a file a record to a segment with congestion control and a timer,
asks a client for an x25519 key share if it sent another, and executes nothing that can
be written. 13,933 bytes with the page of `www/` (13,243 of system; 13,371 since it
also tells a client it can't serve why not, which these runs did not have), built as
`./k15 pack www -n IP -i IP -c cert-hz --plain80`.

The server was not the same machine as in the night (see "The machines": shared
processors, and a network path that carried a third more plain connections now), so the
night's image was run again, in turn with the new one (`./k15 deploy` each time):

| | the afternoon's image | the night's image, the same afternoon |
|---|---|---|
| new TLS connections a second, 64 in flight (4 runs each of 12 s) | 7,365 to 7,717 | 7,260 to 8,022 |
| the same, 512 in flight (4 runs each) | 7,668 to 8,288 | 7,669 to 8,611 |
| mean of the 8 | 7,816 | 7,880 |
| https, connections kept, 64 and 512 | 104,206 and 114,772 requests a second | 105,605 and 111,939 |
| http, new connections, 64, 512, 4096 | 43,472, 45,529, 43,007 (353 over 10 s) | 42,436, 46,546, 46,266 (155 over 10 s) |
| http, connections kept, 64 and 512 | 103,341 and 111,233 | 110,657 and 116,165 |
| https, new connections, 4096 in flight | 8,533 a second; median 0.47 s, 99% 1.5 s | 7,804 |
| https, new, two key shares, 512 | 8,253 | 7,447 |

So it does more for every request (the request is decrypted and looked up, the response
has six headers instead of one, a timer is set) and is as fast. Before its hot loops
were placed (below) it was 6% slower at new TLS connections: 7,591 against 8,077 (8 runs
each), in every pair of runs.

**Where a jump lies.** The server's processor (Skylake) decodes a jump again every time
it meets it, if the jump crosses a 32-byte boundary or ends on one (a microcode fix for
an erratum; all that shares the 32 bytes with it is decoded again too). The new code
had moved the SHA-256 round loop, the curve machine's dispatch and the field addition so
that each had such a jump. On the development machine (Zen 2) the two images were equal.
The routines a handshake spends its time in now each begin where none of their jumps
lies so (`HOT` in src/os.asm, `tools/jcc.py`), at the price of 320 bytes of padding
(35 since 2026-11-14: "Four blocks at a time", below).

**Files** (the site of `tools/mksite.py`; `wrk`, 8 s a row, from the same generator;
nginx 1.28.3 with OpenSSL 3.5.5 and `bench/nginx.conf` on the same server with the same
files and certificate):

| 64 connections that stay | k15 | nginx + OpenSSL |
|---|---|---|
| the page (167 bytes), requests a second | 105,247 (512 connections: 113,931) | 30,302 (512: 31,229) |
| a file of 14,000 bytes | 10,939 a second, 148 MB/s | 22,128 a second, 300 MB/s |
| a file of 1.5 MiB | 108 a second, 166 MB/s (8 connections: 162 MB/s) | 494 a second, 742 MB/s (8: 757 MB/s) |
| one fetch of the 1.5 MiB, connection included | 22 to 28 ms | 9 to 15 ms |

k15's 166 MB/s is 115,000 segments a second: the same ceiling of frames as everywhere
else in this comparison, with its processors mostly idle. nginx is not under that
ceiling here because Linux gives the card 64 KB at a time and lets it cut the segments
(TSO). k15 sends a segment a frame. For large files nginx is four and a half times as
fast on this server; for the pages and small files a site is mostly made of, k15 three
times.

Over a distance (the developer's connection, 11 ms away): the 1.5 MiB take 0.3 s. Over
a round trip of 20 ms and of 100 ms (emulated: `DELAY=n` in front of tap.sh): 0.6 s and
2.9 s, a connection included. At most 64 KB are on their way (no window scaling), so a
large file goes at 64 KB a round trip.

Held, with the afternoon's image: 60,000 TLS connections, each with the chain verified,
and 60,000 plain ones; all opened, held and fetched over.

## Large files: many records to a frame (2026-11-12, night)
The image of the afternoon sent a segment a frame, and the path to it carries about
130,000 frames a second: 166 MB/s. Since then:
- **the card cuts the frames** (virtio's CSUM and HOST_TSO4, where it offers them): a
  frame of ours is up to 45 records of a response, sealed into a buffer of 64 KiB, each a
  segment once the card has cut it and summed it. What is lost on the way is still one
  record, made again from the image;
- **a record is sealed faster**: the key stream was xored on a byte at a time, which cost
  more than making it. 16 bytes at a time, and the AES counter kept in registers: a full
  record (1,418 bytes) takes 3,900 cycles under AES-128-GCM (it took 11,600) and 11,800
  under ChaCha20-Poly1305 (17,900), a small one (180 bytes) 940 and 2,200 (1,900 and
  3,000); `make bench`, on the development machine;
- **windows are scaled**, so more than 64 KB can be on their way (below);
- files that get shorter by it are **packed compressed as well** (gzip, brotli), and a
  client that has a file is told so (ETag, 304).

14,245 bytes of system, with the site of `tools/mksite.py` behind it, built as `./k15 pack
build-hzn/www -n IP -i IP -c cert-hz --plain80`. From the same generator, the same night,
one server after the other (`bench/files.sh`: wrk, 8 s a row, 64 connections that stay
unless it says otherwise). wrk's OpenSSL puts AES-256-GCM first, then ChaCha20-Poly1305,
then AES-128-GCM: nginx takes the first, k15 has no AES-256 and took the second
that night (since 2026-11-13 it takes the third: "Which cipher", below).
Browsers put AES-128-GCM first: the rows that say so were asked that way.

| | this image (22:02) | the afternoon's image (20:40) | nginx + OpenSSL 3.5 (20:50) |
|---|---|---|---|
| the page (167 bytes), requests a second | 108,685 (512 connections: 105,523) | 110,284 (117,966) | 33,880 (34,142) |
| 14,000 bytes, OpenSSL's order | 30,393 a second, 411 MB/s | 13,692, 185 MB/s | 26,654, 362 MB/s |
| 14,000 bytes, AES-128-GCM | 35,332 a second, 478 MB/s | 14,861, 201 MB/s | 23,851, 324 MB/s |
| 1.5 MiB, OpenSSL's order | 307 a second, 466 MB/s | 114, 177 MB/s | 611, 0.90 GB/s |
| the same, 8 connections | 292 a second, 439 MB/s | 113, 170 MB/s | 632, 0.93 GB/s |
| 1.5 MiB, AES-128-GCM | 624 a second, 0.92 GB/s | 108, 167 MB/s | 667, 0.98 GB/s |
| the same, 8 connections | 514 a second, 772 MB/s | 104, 157 MB/s | 689, 1.01 GB/s |
| the same, 1 connection | 97 to 107 a second, 145 to 160 MB/s | 43, 64 MB/s | 261, 392 MB/s |
| 200 KB of text, as it is | 4,673 a second, 0.89 GB/s | | |
| the same to a client that takes brotli (99 KB) | 10,189 a second | | |
| the page to a client that has it (304) | 111,756 a second | | |

No request failed or took over 2 s in any row. So:
- a file of 14 KB now goes faster than from nginx (it was half as fast), and so does
  anything smaller;
- a large file goes 5.5 times as fast as it did when browsers ask (AES-128-GCM), which
  is 94% of nginx's rate at 64 connections and three quarters at 8; and 2.6 times as
  fast under ChaCha20-Poly1305, which is half of what nginx does with AES-256-GCM;
- nginx itself was a third faster than in the afternoon (742 MB/s then): the same server
  is not the same machine from hour to hour.
What limits k15 now is, as far as can be told from outside, sealing: 0.92 GB/s are
650,000 records a second, which is all the time two processors of 2.1 GHz have at 6,500
cycles a record (a record under AES-128-GCM takes 3,900 on the development machine;
its frame, its acks and the hash of the tag come on top; how busy the processors were
was not measured). The next thing would be the ciphers again: AES four blocks abreast
and GHASH four at a time; ChaCha20 two or four blocks abreast, which wants AVX2. (Done
for AES-128-GCM on 2026-11-13, evening: a 1,418-byte record is down to 1,780 cycles on
the development machine, and large files went from 1.0 to 1.2 GB/s on the server: "Four
blocks at a time", below.)

The rows of `bench/run.sh`, this image and the afternoon's in turn (22:10; 10 s a row):

| | this image | the afternoon's |
|---|---|---|
| new TLS connections a second, 64 / 512 / 4,096 in flight | 7,717 / 7,705 / 8,791 | 7,434 / 6,524 / 7,233 |
| the same with two key shares, 512 | 7,478 | 7,350 |
| https, connections kept, 64 / 512 | 106,428 / 119,630 | 101,473 / 105,753 |

(A full run of this image at 22:07: 7,150, 7,479 and 7,939 new TLS connections a
second, 95,916 and 113,255 requests on kept ones; plain: 39,713, 45,439 and 43,930
new connections, 101,612 and 108,237 requests.)

**Which cipher (2026-11-13).** Until here a client that named both of our ciphers got
the one it named first, and OpenSSL names ChaCha20-Poly1305 before AES-128-GCM (its
order goes by the length of the key: AES-256, ChaCha20, AES-128). So wrk, curl and all
that is built on OpenSSL got the cipher k15 seals at a third of the speed. Now such a
client gets AES-128-GCM, unless ChaCha20-Poly1305 is the first suite of TLS 1.3 it
names: a client without AES in its processor puts it there. 14,277 bytes of system.
The same rows again, wrk as it is (00:16; nginx was not measured again):

| wrk, with OpenSSL's own order | with the rule | before it (above) |
|---|---|---|
| 14,000 bytes | 32,561 a second, 440 MB/s | 30,393, 411 MB/s |
| 1.5 MiB | 624 a second, 0.92 GB/s | 307, 466 MB/s |
| the same, 8 connections | 527 a second, 792 MB/s | 292, 439 MB/s |

(In the same run with AES-128-GCM alone: 35,830 a second of 14 KB; 632 a second, 0.93
GB/s, of 1.5 MiB; 469 a second, 705 MB/s, on 8 connections and 94, 142 MB/s, on one;
the page 106,864 and 107,301 a second. `bench/run.sh`'s first rows: 7,640, 8,060 and
8,372 new TLS connections a second, 7,251 with two key shares, 104,382 and 115,463
requests on kept ones.)

**Over a distance.** With windows scaled, more than 64 KB can be on their way. How much
more is the question: a window that doubles every round trip up to 367 KB brought 1.5
MiB over a round trip of 100 ms in 1.1 s (2.9 s before), and through a path that holds
less than that it lost 91 segments at once and took 23.6 s for 6 MiB where the old
image took 5.2: what is lost is found a segment a round trip without SACK, and what
SACK says can't be kept in a slot of 128 bytes (Linux, besides, says it once a
millisecond, not once a segment). So the window doubles up to 64 KB as before, grows by
a segment for every 64 KiB acknowledged beyond that, a response begins with 64 KB at
most, and a connection that has lost anything once stays at 64 KB. Several losses in
one window are mended a round trip each instead of a timer each. 6 MiB through emulated
paths (`tools/bneck.sh`; an image without TSO, so that a frame is a segment):

| the path | the afternoon's image | this one |
|---|---|---|
| 20 Mbit/s, a queue of 60 packets, 50 ms there and back | 5.2 s | 4.3 s |
| no limit, 100 ms | 10.2 s | 5.5 s |
| 100 Mbit/s, a queue of 100, 20 ms | 2.05 s | 1.2 s |
| 50 Mbit/s, a queue of 50, 10 ms | 1.12 s | 1.15 s |
| 5 Mbit/s, a queue of 30, 100 ms | 13.1 s | 12.4 s |
| 20 Mbit/s, a queue of 200, 1% lost | 21 to 24 s | 14 to 19 s |
| 20 Mbit/s, a queue of 10, 50 ms | 39 s | 34 s |

1.5 MiB with a connection, over a round trip of 20 ms and of 100 ms (`DELAY=n` in front
of tap.sh): 0.37 s and 1.8 s (0.6 s and 2.9 s). The last row is what neither does well:
a queue of ten packets and a sender that does not pace.

## Four blocks at a time, and where the hot routines lie (2026-11-14, 01:10 to 01:40)
Three images in turn on the server, each with the site of `tools/mksite.py`
(`./k15 pack ... --plain80`), from a new load generator of the same kind: the image of
2026-11-13, 00:27 ("Which cipher", above: 14,277 bytes of system), the one of that
evening (AES-128-GCM four blocks abreast and GHASH four at a time, the clock, the
fixes: 14,747), and the night's (14,364: the same code in 383 bytes less; the padding
in front of the hot routines is 35 bytes where it was 226: see `HOT` in src/os.asm).

Files (`bench/files.sh`: wrk, 64 connections that stay unless it says otherwise; two
runs where there are two numbers):

| | 2026-11-13, 00:27 | that evening's | the night's |
|---|---|---|---|
| 1.5 MiB, wrk as it is (it gets AES-128-GCM) | 1.02 and 0.95 GB/s | 1.22 GB/s | 1.24 and 1.19 GB/s |
| the same asked for with AES-128-GCM alone | 0.99 and 0.99 GB/s | 1.27 GB/s | 1.16 and 1.22 GB/s |
| the same, 8 connections | 819 and 595 MB/s | 0.97 GB/s | 0.88 and 0.92 GB/s |
| the same, 1 connection | 121 and 95 MB/s | 136 MB/s | 129 and 122 MB/s |
| 14,000 bytes (AES-128-GCM) | 37,626 and 36,001 a second | 34,255 | 36,254 and 36,888 |
| the page (167 bytes), 64 and 512 connections | 100,326 and 120,117 | 81,355 and 108,319 | 97,656 and 113,813 |
| 200 KB of text, as it is, and to who takes brotli | | | 6,099 a second (1.16 GB/s), 12,025 |
| requests of over 2 s (wrk's "timeout"), 1.5 MiB rows | 11, 4, 9 | none | none |

So sealing four blocks at a time is worth a fifth to a quarter for large files on this
server (1.2 GB/s where it was 1.0, and where nginx with OpenSSL did 0.90 to 0.98 two
nights before), nothing for small ones, which were never limited by it; and the
requests that waited over 2 s in the large rows are gone since the evening's fixes.

New TLS connections a second (`bench/run.sh`, 10 s a row; then the evening's image and
the night's in turn, twice each, two runs of 12 s at 64 and at 512 in flight after each
deploy):

| | 2026-11-13, 00:27 | that evening's | the night's |
|---|---|---|---|
| 64 / 512 / 4,096 in flight | 7,986 / 8,531 / 8,755 | 7,326 / 8,472 / 8,398 | 7,786 / 8,444 / 8,551 |
| two key shares, 512 | 8,467 | 8,188 | 8,100 |
| in turn, 64 in flight (4 runs each) | | 7,265 to 7,975, mean 7,683 | 7,340 to 7,693, mean 7,504 |
| in turn, 512 in flight (4 runs each) | | 7,180 to 8,762, mean 8,210 | 8,108 to 8,415, mean 8,292 |
| https, connections kept, 64 / 512 | 97,692 / 120,155 | 101,060 / 117,733 | 100,844 / 114,575 |
| http, new connections, 64 / 512 / 4,096 | 30,923 / 34,757 / 34,448 | 31,512 / 34,527 / 33,787 | 31,090 / 34,579 / 34,375 |
| http, connections kept, 64 / 512 | 103,260 / 115,988 | 100,341 / 121,057 | 100,452 / 111,806 |

No errors; of the connections over 10 s, 3, 1 and 1 in the plain row with 4,096 in
flight, as ever. The three images make as many connections as each other, within what
a row moves between two runs here: so the hot routines need not begin on a 32-byte
boundary to keep their jumps off one. It is enough that each begins at one of the
places where none of its jumps lies on a boundary (most have ten or twenty such places
in 32), and that is what `HOT` now pads to.

## Held connections
`tools/tapc.c` from the load generator (`bench/hold.sh`; 60,000 from one address is what
the ports allow):
- k15: 60,000 TLS connections opened (256 at a time, 28 s: that is the client), each with
  the chain and the name verified, all held, then the page fetched over each. 30 runs of
  that with the image above, each after a burst of new connections: 1.8 million
  connections, every one opened, verified and served but for one that the client could
  not start (its port was taken). The same with 60,000 plain connections. (Some 17 such
  runs earlier in the night had two failed handshakes between them: that is how the bug in
  finding the key share was found, see docs/pitfalls.md.)
- A held connection costs k15 20 bytes on port 80 and 128 bytes on 443, by construction:
  on this server there is room for 172 million and 3.8 million.
- nginx: the same 60,000, and what the server's `MemAvailable` loses while they are held:
  4.0 KiB a plain connection; 25.8 KiB a TLS connection with OpenSSL (22 KiB of it in the
  workers), 7.1 KiB with BoringSSL. In the 3 GiB this server has free under Linux that is
  room for roughly 120,000 TLS connections with OpenSSL and 440,000 with BoringSSL (not
  tried).

## Size
- k15: 11,094 bytes, all of it: boot code, driver, TCP, TLS, the two curves, the page.
  (The afternoon's image: 13,243 bytes and the site.)
- nginx + OpenSSL: nginx 1.6 MB, libssl 1.1 MB, libcrypto 6.4 MB; under them the kernel
  (vmlinuz, compressed: 17.3 MB) and the rest of a Linux system.
- nginx + BoringSSL: one binary of 3.6 MB (stripped), and the kernel.
- Caddy: 39.2 MB, and the kernel.

By the project's own measure, connections that can be held per KiB of what has to be on
the disk (kernel included, the rest of the system not), TLS: k15 about 350,000 (3.8 million
slots, 10.8 KiB); nginx + BoringSSL about 20; nginx + OpenSSL about 5.

## What this does not say
- nginx and Caddy are web servers: any file, any header, virtual hosts, HTTP/2, logs,
  reloads, every cipher and curve a client may want, session resumption. In the night k15
  served one page of one segment to clients that speak TLS 1.3 with an X25519 share, and
  nothing else: its response was 59 bytes (a status line and one header), nginx's 256 (a
  status line and eight). The afternoon's image serves a site's files with six headers
  (179 bytes for that page), and still nothing but GET and HEAD of what was packed into
  it.
- Large files: see "Large files: many records to a frame".
- No resumption was measured, because k15 has none: every connection here is a full
  handshake. A server with session tickets does a returning client's handshake for less;
  how nginx then compares with k15's full handshake was not measured.
- One server, one location, one night, shared vCPUs. Not measured: other instance types,
  dedicated cores, more than two processors on a real machine, anything over a real
  distance.
- The rate client asks for the cheapest thing a TLS server can be asked for (AES-128-GCM,
  a 27-byte page) and does not verify certificates. A different mix moves all four.
- Unikraft and F-Stack were not measured. Unikraft needs a hypervisor of its own (these
  cloud servers don't offer nested virtualisation; on the development machine it could be
  run next to k15 under QEMU, which nobody has set up yet). F-Stack needs DPDK to take the
  network card away from Linux, which on a server with one card takes away ssh as well.
- BoringSSL was measured inside nginx only, not by itself.

## Doing it again
1. A load generator next to the server (docs/server.md). On it:
   `apt-get install -y gcc libssl-dev`, a directory with `tools/bench.c`, `tools/tapc.c`,
   `www/`, `bench/run.sh`, `bench/busy.sh`, `bench/hold.sh`, and in `build/` the server's
   `ca.pem` and `name` (from `build-hz/`); `gcc -O2 -o build/bench tools/bench.c -lssl
   -lcrypto` (tapc the same).
2. k15: build without `KNOCK`, `tools/deploy.sh`, then on the generator `./run.sh IP`.
   `hcloud server reset k3` brings Linux back.
3. nginx: copy `bench/nginx.conf`, `www/index.html` and `cert-hz/server.pem` and
   `server.key` to `/root/k15bench/` on the server, `ssh root@server 'bash -s' <
   bench/setup-nginx.sh`, then `./run.sh IP`. With BoringSSL: `bench/build-nginx-boring.sh`
   on the generator, the binary to the server, started as that script's first lines say.
   Caddy: its package, `bench/Caddyfile`.
4. Held connections: `./hold.sh tls 60000 IP` on the generator, and when it says "all
   open", `touch /tmp/bar/go` (before that is the time to read the server's
   `/proc/meminfo`).
5. How busy k15 is: an image with `DEBUG=2`, then `./busy.sh IP PLAIN=1 DST=IP:80 P=8 W=64
   KA=1000000` and the like.
6. Afterwards: the server's key is on its disk in `/root/k15bench` and `/etc/nginx/k15bench`
   (remove both, and the packages), and the generator costs by the hour (`hcloud server
   delete`). On 2026-11-12 the server was left as it was found: Ubuntu, nothing of this
   on it but `/boot/k15.bin` and its GRUB entry.
7. Two images of k15 in turn: `./k15 deploy IP DIR --reset 'hcloud server reset k3'` for
   each, and the rows that matter between (the afternoon used the first two of run.sh,
   twice, 12 s each). Files: `./files.sh IP [all]` on the generator (`apt-get install
   wrk`; `bench/files.sh` beside run.sh); for nginx the site's folder goes to
   `/var/www/k15bench`. While 15kb.org lives on the server, every such deploy takes it
   down: `./k15 deploy IP build-15kb.org --persist --reset ...` puts it back.
