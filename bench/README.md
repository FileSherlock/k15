# k3 next to nginx and Caddy

What k3 does on its server, and what nginx (with BoringSSL and with OpenSSL) and Caddy do
on the same server with the same page, key and certificate. Measured in the night of
2026-11-11 to 12. Short version:

| on a 2-vCPU cloud server | k3 | nginx + BoringSSL | nginx + OpenSSL 3.5 | Caddy 2.6 |
|---|---|---|---|---|
| new TLS 1.3 connections a second (full handshake) | 8,800 - 9,100 | 3,900 - 4,100 | 2,100 - 2,200 | 1,700 - 1,850 |
| HTTPS requests a second, connections kept | 109,000 - 122,000 (1) | 47,000 - 48,000 | 37,000 - 40,000 | 9,000 - 12,000 |
| new plain HTTP connections a second | 30,000 - 35,000 (1) | 17,000 - 22,000 | 16,000 - 22,000 | 7,000 - 8,000 |
| HTTP requests a second, connections kept | 110,000 - 128,000 (1) | 60,000 - 71,000 | 58,000 - 68,000 | 14,000 |
| memory for a connection that is held: plain, TLS | 20 bytes, 128 bytes | 3.2 KiB, 7.1 KiB | 4.0 KiB, 25.8 KiB | not measured |
| what has to be on the disk | 11,094 bytes | 3.6 MB + a kernel (17 MB) | 9.1 MB + a kernel | 39 MB + a kernel |

(1) Not k3's limit: the server's network path carries about 130,000 frames a second each
way and k3's processors are 80 to 89% idle at that point (see "What limits whom"). The
other servers' numbers, and k3's new TLS connections, are what their processors can do.

## The machines
- The server: Hetzner cx23 in Nuremberg: 2 shared vCPUs (Xeon Skylake, 2.1 GHz), 4 GB,
  one virtio-net queue. For k3 it boots the image (GRUB, multiboot); for the others it
  runs Ubuntu 26.04 (kernel 7.0.0-30).
- The load generator: a ccx33 in the same location (8 dedicated vCPUs, Ubuntu 26.04),
  0.4 ms away (ping: 0.41 ms at best, 0.8 on average). A second one (cpx42) was added for
  one experiment.
- Shared vCPUs: the same row measured again differs by 10%, sometimes 15 (k3, new TLS
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
- k3: the image of commit "The key share is found by walking the ClientHello" (11,094
  bytes), built without `DEBUG`, `KNOCK` and `LIFE`.
- nginx 1.28.3 with OpenSSL 3.5.5, as Ubuntu packages them (`nginx-light`), with
  `bench/nginx.conf`: a worker per processor, `reuseport`, a backlog of 65,535, and
  `bench/setup-nginx.sh` for the kernel (the limits on queues and files raised, and
  receive packet steering on, so that both processors take packets from the one queue as
  they do under k3).
- nginx 1.28.3 built from nginx.org's source against BoringSSL (the commit of 2026-11-11,
  `-DCMAKE_BUILD_TYPE=Release`; `bench/build-nginx-boring.sh`), same configuration file.
- Caddy 2.6.2 (Ubuntu's package, not a recent Caddy; Go's crypto/tls) with
  `bench/Caddyfile`.

## Results
Connections or requests a second; then, in ms, the median and the 99th percentile.
"In flight" is how many connections the client keeps going at once (8 x W).

| | in flight | k3 | nginx + BoringSSL | nginx + OpenSSL | Caddy |
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

No errors anywhere. Timeouts (over 10 s): none, except for k3 in the 4,096 row of plain
HTTP: 83 of 517,000 connections in this run, and 1, 4 and 6 in three earlier ones (see
"With more in flight"). The HTTP rows of the two nginx columns are the same nginx version
doing the same work, the TLS library not involved: they show how much a row moves between
runs.

Per new TLS connection that is, of both processors' time: k3 460,000 cycles, nginx with
BoringSSL 1.0 million, with OpenSSL 1.9 million, Caddy 2.3 million. The curve arithmetic
is not where k3 gains. On the development machine, where both were timed (`make bench`,
`openssl speed`), OpenSSL signs with ECDSA P-256 in 71,000 cycles and does an X25519
multiplication in 113,000; k3 signs in 89,000 (2,000 when it made the nonce while idle)
and needs 209,000 for its key share and the shared secret together. (On the server
OpenSSL's two take 77,000 and 120,000.) k3 gains on everything around the arithmetic:
there is no kernel under it and no socket between the two, and a connection is 128 bytes.

### What limits whom
- nginx and Caddy: their processors (`vmstat` on the server: 0 to 6% idle in every row).
- k3, new TLS connections: its processors (2 to 5% idle; a `DEBUG=2` image and
  `bench/busy.sh`).
- k3, everything else: the path to it. With connections kept it levels off at about
  130,000 requests a second, with new plain connections at 35,000 (140,000 frames a
  second in), and at that point its processors are 80 to 89% idle. Two load generators at
  once get the same total (59,900 + 64,700 requests a second); k3 with one processor gets
  the same (133,000 HTTP requests a second at 15% busy, 126,000 HTTPS at 28%: 2,400 and
  4,800 cycles a request, the driver included). The load generator was not the limit
  either (its processes 80% idle, its one receive queue's processor half idle). What it
  is on the host's side could not be seen from inside the guest.
- So the three rows marked (1) say less than they could: on a path that carried more,
  k3 would do several times as much, and the others would not.

### With more in flight than can be served
4,096 connections in flight is more than any of the four can serve in less than half a
second. What happens then:
- k3 lets the frames wait (rings of 16,384 frames per processor). New TLS connections at
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
  TcpExtTCPSynRetrans). k3 at that point asks more of the path than it carries, nginx
  does not get that far; so k3 has the connections that lose their SYN four times running
  and take over 10 s (0.02% in the worst run), and nginx has none. An image that counts
  showed no frame lost in k3's own rings there. Where on the path they go was not found.

## Held connections
`tools/tapc.c` from the load generator (`bench/hold.sh`; 60,000 from one address is what
the ports allow):
- k3: 60,000 TLS connections opened (256 at a time, 28 s: that is the client), each with
  the chain and the name verified, all held, then the page fetched over each. 30 runs of
  that with the image above, each after a burst of new connections: 1.8 million
  connections, every one opened, verified and served but for one that the client could
  not start (its port was taken). The same with 60,000 plain connections. (Some 17 such
  runs earlier in the night had two failed handshakes between them: that is how the bug in
  finding the key share was found, see CLAUDE.md, "Learned the hard way".)
- A held connection costs k3 20 bytes on port 80 and 128 bytes on 443, by construction:
  on this server there is room for 172 million and 3.8 million.
- nginx: the same 60,000, and what the server's `MemAvailable` loses while they are held:
  4.0 KiB a plain connection; 25.8 KiB a TLS connection with OpenSSL (22 KiB of it in the
  workers), 7.1 KiB with BoringSSL. In the 3 GiB this server has free under Linux that is
  room for roughly 120,000 TLS connections with OpenSSL and 440,000 with BoringSSL (not
  tried).

## Size
- k3: 11,094 bytes, all of it: boot code, driver, TCP, TLS, the two curves, the page.
- nginx + OpenSSL: nginx 1.6 MB, libssl 1.1 MB, libcrypto 6.4 MB; under them the kernel
  (vmlinuz, compressed: 17.3 MB) and the rest of a Linux system.
- nginx + BoringSSL: one binary of 3.6 MB (stripped), and the kernel.
- Caddy: 39.2 MB, and the kernel.

By the project's own measure, connections that can be held per KiB of what has to be on
the disk (kernel included, the rest of the system not), TLS: k3 about 350,000 (3.8 million
slots, 10.8 KiB); nginx + BoringSSL about 20; nginx + OpenSSL about 5.

## What this does not say
- nginx and Caddy are web servers: any file, any header, virtual hosts, HTTP/2, logs,
  reloads, every cipher and curve a client may want, session resumption. k3 serves one
  page of one segment to clients that speak TLS 1.3 with an X25519 share, and nothing
  else. Its response is 59 bytes (a status line and one header); nginx's is 256 (a status
  line and eight).
- No resumption was measured, because k3 has none: every connection here is a full
  handshake. A server with session tickets does a returning client's handshake for less;
  how nginx then compares with k3's full handshake was not measured.
- One server, one location, one night, shared vCPUs. Not measured: other instance types,
  dedicated cores, more than two processors on a real machine, anything over a real
  distance.
- The rate client asks for the cheapest thing a TLS server can be asked for (AES-128-GCM,
  a 27-byte page) and does not verify certificates. A different mix moves all four.
- Unikraft and F-Stack were not measured. Unikraft needs a hypervisor of its own (these
  cloud servers don't offer nested virtualisation; on the development machine it could be
  run next to k3 under QEMU, which nobody has set up yet). F-Stack needs DPDK to take the
  network card away from Linux, which on a server with one card takes away ssh as well.
- BoringSSL was measured inside nginx only, not by itself.

## Doing it again
1. A load generator next to the server (CLAUDE.md, "Running it on the server"). On it:
   `apt-get install -y gcc libssl-dev`, a directory with `tools/bench.c`, `tools/tapc.c`,
   `www/`, `bench/run.sh`, `bench/busy.sh`, `bench/hold.sh`, and in `build/` the server's
   `ca.pem` and `name` (from `build-hz/`); `gcc -O2 -o build/bench tools/bench.c -lssl
   -lcrypto` (tapc the same).
2. k3: build without `KNOCK`, `tools/deploy.sh`, then on the generator `./run.sh IP`.
   `hcloud server reset k3` brings Linux back.
3. nginx: copy `bench/nginx.conf`, `www/index.html` and `cert-hz/server.pem` and
   `server.key` to `/root/k3bench/` on the server, `ssh root@server 'bash -s' <
   bench/setup-nginx.sh`, then `./run.sh IP`. With BoringSSL: `bench/build-nginx-boring.sh`
   on the generator, the binary to the server, started as that script's first lines say.
   Caddy: its package, `bench/Caddyfile`.
4. Held connections: `./hold.sh tls 60000 IP` on the generator, and when it says "all
   open", `touch /tmp/bar/go` (before that is the time to read the server's
   `/proc/meminfo`).
5. How busy k3 is: an image with `DEBUG=2`, then `./busy.sh IP PLAIN=1 DST=IP:80 P=8 W=64
   KA=1000000` and the like.
6. Afterwards: the server's key is on its disk in `/root/k3bench` and `/etc/nginx/k3bench`
   (remove both, and the packages), and the generator costs by the hour (`hcloud server
   delete`). On 2026-11-12 the server was left as it was found: Ubuntu, nothing of this
   on it but `/boot/k3.bin` and its GRUB entry.
