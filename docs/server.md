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

`tap.sh` gives the guest its address as a network would: `tools/dhcpd.py` answers its
DHCP on the tap (10.0.2.15, an hour at a time), and through QEMU's own network QEMU's
server does. An image without an address has not been on a real machine yet
(2026-11-21): what Hetzner's DHCP says to it, and how long its leases are, is still to
be seen there.

SeaBIOS won't boot a disk of a few KiB: `disk.img` is 8 MiB, sparse. A cx23 boots `disk.img`
written over the whole of /dev/sda from the rescue system, and again after a reset
(2026-11-14, on a second server; that is how `tools/bounty_ceremony.sh` deploys).

## Onto a machine that is k15's alone
The image needs nothing on a machine's disk but itself: `disk.img`, written over the
whole disk. What writes it is the host's rescue system: a Linux that the host starts
from memory and that ssh reaches. Every host has one, or something that does for one;
how it is started and how it is left is all that differs between them, and is what
`./k15 publish`, `./k15 deploy` and `./k15 renew` are told:
- `--rescue 'COMMAND'`: what puts the machine into its rescue system with a key of
  yours in it. It is run only if the machine is not there already: where it takes a
  console to get there, get it there by hand and leave `--rescue` out.
- `--boot 'COMMAND'`: what starts the machine from its disk again, where saying
  `reboot` in the rescue system does not (a host on which a machine stays in its rescue
  system until told otherwise).
- `--disk DEVICE`: the machine's disk, where the rescue system sees more than one (its
  own, say).
What happens, in this order (`k15`: `live`, `rescue`, `itself`, `write`, `up`):
1. `publish`: before the machine leaves, the certificate the site shows is fetched and
   checked as a browser would check it (but for its dates). If it shows none (three
   tries), the machine is not touched: nothing would vouch for it afterwards.
2. The machine goes into its rescue system. What answers ssh there has host keys
   nobody has seen before (a rescue system makes new ones every time), so it has to say
   that it is the machine another way: **the last 64 KiB of its disk hold its key and
   certificate** (where the deploy before this one put them: `idput`), and with that
   key it must be able to sign for a certificate we know to be the machine's: the one
   from step 1 (`publish`), or the one in the folder the image was packed from
   (`deploy`, `renew`: the machine is then sent nothing it has not got). It is a
   signature that is asked for (`proves`), not which key the file says it is about: a
   certificate where the key should be, or a key file with the site's public half
   pasted in, say the right thing to that question, and the first version of this took
   them (found by the review of 2026-11-21; `tools/hosttest.sh` has both). A machine
   that cannot show it is sent nothing and started as it was. `--first` is for one that
   has nothing to show yet (its first image; an image from before this; a site that is
   down; a machine already in its rescue system when `publish` begins): then the route
   to it is all that vouches for it, as it is for any first ssh to a new server.
3. `publish` takes key and certificate from there (it keeps nothing here), and gets a
   new pair if the certificate ends within `--days` (30) or lacks a name: a new key
   made here, and certbot on the rescue system answering Let's Encrypt on port 80 for
   the request (installed there with apt if it is not there). What comes back has to
   be a certificate for that key that this machine believes, or it is as if none had
   come. `deploy` and `renew` have theirs in the folders `k15 pack` made.
4. The disk is discarded (or its first 128 MiB zeroed), the image written, what the
   machine is put at its end, the image read back and compared; then the machine is
   started from the disk, and the command waits for a verified fetch.
If no certificate comes, or the site cannot be packed, nothing has been written, and
the machine is started as it was (`renew` then also puts the old key and certificate
back in their folder). If writing fails half way, the machine stays in its rescue
system and the command says so: its disk no longer says who it is, and the next try
needs `--first`. A minute or two without a server each time: what the rescue system
takes to come up, mostly.

`tools/hosttest.sh` runs all of that against a machine that is made up (its disk a
file, its rescue system a shell with six commands replaced, "start from the disk" a
QEMU). **On a real host `k15 publish` has not run yet** (2026-11-21: no token for one
here). The same commands on the far side (`blkdiscard`, `dd`, `reboot`, certbot with a
request) are what `tools/bounty_ceremony.sh` ran in Hetzner's rescue system on
2026-11-14 and 20.

### Hosts
What the image needs of one: a BIOS that starts the first sector of the disk (not
UEFI alone), a virtio network card, an IPv4 address by DHCP (or `-i`), and a processor
as the README says.
- **Hetzner Cloud** (tried with an image that had its address; the bounty runs so):
  `--rescue 'hcloud server enable-rescue --ssh-key KEY NAME && hcloud server reset
  NAME'`. The rescue system is for one start: `reboot` in it starts the disk, so no
  `--boot`. One disk, /dev/sda. Their documentation: "By default, cloud servers obtain
  their Primary IPv4 address via DHCP"; IPv6 is "statically configured", gateway
  fe80::1.
- **Linode (Akamai)**, from their documentation, not tried: `linode-cli linodes rescue
  ID --devices.sda.disk_id DISK` starts the rescue system (Finnix), but "you need to use
  Lish at least once in order to start SSH": by hand, then without `--rescue`, and with
  `--boot 'linode-cli linodes reboot ID'`. The machine's configuration has to start the
  disk's first sector (kernel "Direct Disk"). VirtIO net; DHCP gives one IPv4 address;
  IPv6 by SLAAC.
- **OVHcloud Public Cloud**, from their documentation, not tried: `--rescue 'ovhcloud
  cloud instance reboot-rescue ID --wait'` (or `nova rescue ID`); one logs in with a
  password (shown in the console, or returned by the API), so a key has to be put there
  by hand first; `--disk /dev/sdb` ("sda is the rescue mode disk"); `--boot 'nova
  unrescue ID'`. Whether it starts a BIOS boot sector, and gives the address by DHCP,
  their documentation does not say.
- Not this way: Scaleway ("Legacy BIOS is not compatible with Scaleway Instances");
  Vultr and DigitalOcean (their rescue is an ISO and a console in the browser; both take
  an image by URL instead: `vultr-cli snapshot create-url`, `doctl compute image
  create`, the latter only with a partition table and cloud-init in it); UpCloud (no
  rescue system: a second server writes the disk).

### A push publishes
`ci/publish.yml` is a GitHub workflow for the repository that holds a site (its head
says what to tell it: five variables, two secrets). A push to `main` runs `./k15
publish`; once a day it runs with `--if-due --days 45`, which looks at the certificate
the site shows and does nothing else until that has 45 days left; by hand it can be
run with "first" for a machine's first image. So renewal needs no machine of the
user's, and the site's key is in no repository and no secret: it is made on the
runner, lives on the machine's disk, and is fetched from there by the next run.
- Who can publish: whoever can push to that branch, and whoever has the two secrets
  (the host's token and the ssh key for its rescue system). The token can do whatever
  its owner can in its project: a project for that machine alone.
- GitHub switches a scheduled workflow off in a public repository after 60 days in
  which nothing happened there (and writes to its owner first). The workflow's last
  step asks for it to stay on, the way others' tools for this do (enabling the
  workflow through the API); that this resets those 60 days is what they say, not
  something tried here. 45 days, not 30, so that a run that did something comes
  before the 60 are over.
- Not run on GitHub yet: what it does is `k15 publish`, which `tools/hosttest.sh`
  runs; the file itself has only been read by a YAML parser.

## Running it beside a Linux (`--grub`)
The way before 2026-11-21, still there for a server that keeps its Linux (for
measuring: a reset brings Linux back in 25 s, and ssh with it).
`ssh root@2.28.113.14` works from the user's machine while the server runs Linux.
- `./k15 pack FOLDER -n 2.28.113.14 -i 2.28.113.14 -c cert-hz -o build-hz` (for the
  comparison's page: `./k15 pack www ... -o build-hzb --plain80`), then
  `./k15 deploy 2.28.113.14 build-hz --grub --reset 'hcloud server reset k3'`: if Linux does not
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
  (That was until 2026-11-20: since then its disk holds the bounty's image and no
  Linux, see CLAUDE.md.)
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
  before), and `./k15 publish --if-due` the one for a workflow ("A push publishes"). To use a certificate from elsewhere, put those two files there (and no
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
