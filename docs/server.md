# The server, the test machine, the certificate

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

SeaBIOS won't boot a disk of a few KiB: `disk.img` is 8 MiB, sparse. A cx23 boots `disk.img`
written over the whole of /dev/sda from the rescue system, and again after a reset
(2026-11-14, on a second server; that is how `tools/bounty_ceremony.sh` deploys).

## Running it on the server
`ssh root@2.28.113.14` works from the user's machine while the server runs Linux.
- `./k15 pack FOLDER -n 2.28.113.14 -i 2.28.113.14 -c cert-hz -o build-hz` (for the
  comparison's page: `./k15 pack www ... -o build-hzb --plain80`), then
  `./k15 deploy 2.28.113.14 build-hz --reset 'hcloud server reset k3'`: if Linux does not
  answer ssh (k15 is running), the server is reset; then the image is copied to
  /boot/k15.bin and the server reboots into it ONCE through a GRUB entry ("k15" in
  /etc/grub.d/40_custom, loaded with `multiboot`), and the command waits for a verified
  fetch. Ubuntu stays installed and is what any later reset boots. Up 4 s after the
  reboot (all 4 GiB are zeroed, and the curve tables take 25 ms).
- With `--persist`, Linux gets a unit (`k15-chain.service`) that starts k15 a minute after
  Linux has come up, unless /run/k15.hold exists: so k15 comes back by itself after a reset
  (90 s, measured), and `./k15 deploy`, which touches that file as soon as ssh answers,
  still gets in. Without `--persist` the next deploy takes the unit out again. The
  server runs 15kb.org with it since 2026-11-12 (`build-15kb.org`, `cert-15kb.org`;
  packed as `./k15 pack site -n 15kb.org --san www.15kb.org -i 2.28.113.14 -c
  cert-15kb.org -o build-15kb.org --hsts 31536000`, which is what its pack.conf says):
  a deploy of anything else takes the site down, so put it back afterwards (`./k15
  deploy 2.28.113.14 build-15kb.org --persist --reset 'hcloud server reset k3'`).
  `build-15kb.org` must stay where it is: the renewal timer packs from its pack.conf,
  and fails without it (`~/.local/bin/15kb-renew --dry-run` says whether it would run).
  On its Linux: /boot/k15.bin, the GRUB entry, the unit, certbot and its account
  (/etc/letsencrypt: no key of the site's).
- The name: 15kb.org is the user's, at Namecheap, with Namecheap's name servers; `@` and
  `www` are A records for 2.28.113.14 (TTL 300), and `@` has two CAA records, `0 issue
  "letsencrypt.org"` and `0 issuewild ";"` (since 2026-11-12, late), set through Namecheap's API with the
  settings of `~/.namecheap.env` (`namecheap.domains.dns.setHosts` replaces all records
  at once: read them first with `getHosts`). This machine's resolver kept the old answer
  for its 30 minutes: `curl --resolve 15kb.org:443:2.28.113.14`, or Chrome with
  `--host-resolver-rules="MAP 15kb.org 2.28.113.14"`, until it forgets.
- Renewal: a systemd user timer on the user's machine (`15kb-renew.timer`, since
  2026-11-12: daily at 04:30, and after a day the machine was off as soon as it is on)
  runs `~/.local/bin/15kb-renew`, which is `./k15 renew 2.28.113.14 build-15kb.org
  --reset 'hcloud server reset k3'` in `~/Desktop/k15`. It does nothing before 2027-01-12 (the
  certificate ends on 2027-02-10), then gets a new one: the site away for a minute.
  ssh to the server takes the key in the desktop's keyring agent, so the timer runs
  while the user is logged in (a user unit, no linger), and the script starts nothing
  when the agent holds no key (a reset that can't get in costs the site 90 s a day
  for nothing). A failure shows on the desktop (notify-send) and in `journalctl
  --user -u 15kb-renew`. Not cron: `crontab` can't be written from Claude's shell
  (NoNewPrivs: its setgid is refused, "fopen: Permission denied").
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
  reset and delete servers with it): `hcloud server reset k3` is the reset button (the
  server is called k3 at Hetzner: the project's first name), and
  boots Linux (GRUB's default) whatever the image does. So an image that is measured
  needs no knock: build it without `KNOCK=`, deploy, measure, `hcloud server reset k3`.
- A load generator is a second server next to it, for an hour: `hcloud server create
  --name k15-load --type ccx33 --image ubuntu-26.04 --location nbg1 --ssh-key KEY --label
  purpose=k15-bench` (KEY from `hcloud ssh-key list`; the account's limit on dedicated
  cores allows one ccx33, a second generator has to be a shared type such as cpx42), then
  `bench/README.md`. It costs by the hour: `hcloud server delete k15-load` when done, and
  `hcloud server list` to see that nothing is left.
- The image never answers ping; the user's reset button in the Hetzner console is the
  fallback if a build doesn't come up or the knock doesn't work. A fault resets the
  machine by itself (nobody handles it: `GDT`), which boots Linux again; a hang does not.
- Be modest with load from the user's home connection: load comes from a generator next
  to the server (above). From here, for a look: `B=build-hz DST=2.28.113.14:443 build/tapc
  0.0.0.0 20000 400 www/index.html`, and with `PLAIN=1 INFLIGHT=32` and `DST=...:80` for
  port 80. Base ports below 32768.
- A browser against the server: `tools/nssdb.py DIR/.pki/nssdb build-hz/ca.pem`, then
  `HOME=DIR google-chrome --headless=new --no-sandbox --user-data-dir=DIR/c --dump-dom
  https://2.28.113.14/`; `tools/ffcheck.py https://2.28.113.14/ build-hz/ca.pem "Hello"`.
  Against a real name with a real certificate: Chrome as it is, and `REALDNS=1
  tools/ffcheck.py https://15kb.org/ EMPTYFILE "served by"` (no CA to add; without
  REALDNS it looks every name up as 127.0.0.1, where the tests' servers are).
- SSL Labs: https://www.ssllabs.com/ssltest/analyze.html?d=15kb.org&hideResults=on&latest
  in a browser (a minute; `hideResults` keeps it off the boards of recent results).

## The certificate (`tools/gen.py`, `cert/`)
- `cert/server.key` (ECDSA P-256) and `cert/server.pem` (leaf, then intermediates) are the
  identity that gets baked in. Nothing renews by itself: `./k15 renew` is the command to
  run from cron (Commands; a minute or two without a server when it is time, nothing
  before). To use a certificate from elsewhere, put those two files there (and no
  `ca.pem`); `tools/mkchain.py DIR` makes a realistic test chain.
- If they are missing, gen.py makes a 210-byte leaf for `NAME` (default 127.0.0.1; an IP
  address or a DNS name; and for the names of `SAN`, 2 bytes and its length each) and
  its CA, `cert/ca.pem`. There is no CA key: the leaf's signature
  is chosen first (r = 5, s = 1) and the CA's public key is solved from the verification
  equation. Nobody knows that key's private half, so trusting this CA is harmless.
- gen.py also writes `build/ca.pem` (what tests trust; empty for a real chain) and
  `build/name` (the name tests ask for; they always connect to 127.0.0.1 or the tap;
  and where port 80 sends everybody): `NAME` if the certificate is for it, else the
  certificate's first name. Let's Encrypt sorts a certificate's names: without that
  rule `www.example.org` beside `example.org` would be fine and `api.` would win.
- A chain over ~1.1 KB makes the handshake reply longer than one TCP segment
  (`tools/mkchain.py cert-real`, `make B=build-real CERT=cert-real`: a flight of 1,909
  bytes; run the loss and reorder tests with it after touching `.resend` or `tcp_send`).
  A handshake buffer is 4 KiB, or the next power of two that holds the chain.
