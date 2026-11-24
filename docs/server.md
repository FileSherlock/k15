# The server, the test machine, the certificate

## The test machine and the server
`tools/vm.sh` and `tap.sh` boot the server's shape: `-machine q35`, 2 processors, a
modern-only virtio-net (`disable-legacy=on`) behind a PCIe root port, the disk on virtio
SCSI, 256 MiB (`MEM=4096` in front of tap.sh for the server's 4 GiB: RAM above 4 GiB, and
SeaBIOS then puts the card's registers far above 4 GiB too; both are tested that way).
`tap.sh` gives the guest its address as a network would: `tools/dhcpd.py` answers its
DHCP on the tap (10.0.2.15, an hour at a time); through QEMU's own network QEMU's server
does.

The server (a Hetzner cx23, seen over ssh while it had a Linux): "Hetzner vServer/Standard
PC (Q35 + ICH9)", SeaBIOS (no UEFI),
2 vCPUs, 4 GB, "Intel Xeon Processor (Skylake, IBRS, no TSX)" at 2,100 MHz with rdrand,
aes, pclmulqdq, ssse3, sse4.1, adx, bmi2 (all needed), pdpe1gb, x2apic, avx512f/bw/vl, no
sha_ni, no avx512ifma. RAM: 1 MiB to 0x7ffdc000 below 4 GiB, another 1,952 MiB above (to
0x17a000000).
Network: 1af4:1041 at 01:00.0, BAR 4 at 0xfd000000 (64-bit, but below 4 GiB),
common/ISR/device/notify structures at +0/+0x1000/+0x2000/+0x3000, notify multiplier 4,
rings of 256, **one queue pair** (no multiqueue on offer; it offers CSUM, GUEST_CSUM, TSO,
MRG_RXBUF, CTRL_VQ, EVENT_IDX, INDIRECT_DESC). Its address a /32, everything through
the gateway 172.31.1.1 (d2:74:7f:6e:37:e3). Disk: 38 GB
on virtio SCSI (1af4:1048), /dev/sda in the rescue system.

SeaBIOS won't boot a disk of a few KiB: `disk.img` is 8 MiB, sparse. A cx23 boots
`disk.img` written over the whole of /dev/sda, and again after a reset.

**What has been on a real machine and what has not.** On Hetzner Cloud (cx23; the
second one tried had an "AMD EPYC-Rome Processor", GRUB 2.14 and a BIOS): an image
that asks for its address, with an IPv6 address as well, started by GRUB beside a
Linux (`./k15 deploy --grub`) and from the raw disk (`./k15 deploy --rescue`: with
`--first` 54 s from the command to a verified fetch; then without, the machine showing
the key at the end of its disk); it serves over both, and is back within seconds of a
reset. An image with a Content-Security-Policy among its headers (`--header`, quotes
and all) and the machine's IPv6 address as its second name, from the rescue system in
58 s: the header as it was given over both addresses, the last fetch at
`https://[address]/`. Every image lies a little above 1 MiB (docs/internals.md, "Memory"): GRUB on a
BIOS machine puts it there, and so does the boot sector. What Hetzner's DHCP says: the
address with a mask of /32, the router 172.31.1.1 (also as a classless route), a lease
of a day, T1 12 h, T2 21 h. With Let's Encrypt's test server (`--staging`, no
`--email`, a name of sslip.io's for the address): `./k15 publish --first` from a new
server to the site served under its certificate in 1 min 39 s (a certificate for 63
days, and an image of 17,939 bytes of system with its chain), and `./k15 renew --force
--rescue` on an image deployed with a private CA's certificate in 1 min 34 s, the
machine showing the old key first. (A second `publish` stops there, as it should: the
machine is held to the certificate the site shows, which has to be one the world
believes. With `--first` and without `--staging` it goes on, and puts Let's Encrypt's
own in the place of the test server's: 1 min 27 s; the `publish` after that keeps it,
58 s.) With Let's Encrypt itself: `publish --first`, then `--if-due` (nothing to
do, nothing touched), then `publish` again in 55 s, the machine showing the key of the
certificate the site had shown and keeping it, then with `--days 90` a new key and
certificate the same way; curl believes each. A lease renewed: an image that counts
what it asks of DHCP (`DEBUG=3`, docs/commands.md) had asked once and been told yes
once for twelve hours, and twice at the next look, ten minutes later (due 12 h 0 min 1 s
after the first yes), serving all the while; with the lease cut to two minutes
(`DHMAX=120`) every question, one a minute, got its yes. So Hetzner's server answers a
REQUEST that is sent to everybody. Not yet, anywhere: `renew --grub` with Let's
Encrypt (with `--staging` its last fetch no longer checks the certificate, as
`--rescue`'s never did: read, not run). The workflow on GitHub: "A push publishes", below.

On Linode (a Nanode in Frankfurt: "Linode Compute Instance/Standard PC (Q35 + ICH9)",
SeaBIOS, 1 vCPU, an "AMD EPYC 7713" with all that is needed and sha_ni, 1 GB: RAM from
1 MiB to 0x3ffdd000), with nothing changed for it: the image as `./k15 publish` makes
it, asking for its address, with the machine's IPv6 address as well, written from a
Linux on the machine's second disk ("Hosts", below) and started by "Direct Disk". Its
card is 1af4:1000 (the older number, with the modern structures: BAR 4 at 0xfe004000,
the same four offsets and multiplier, one queue pair) at 00:03.0, on the first bus and
behind no bridge; its disk virtio SCSI (1af4:1004), and 16 MiB smaller than asked for
(they go to its encryption: a disk of 64 MB is 48). `publish --first --staging` from
a new machine to the site in 2 min 14 s; `--first` again for Let's Encrypt's own
certificate, then `publish` with the machine showing its key: a verified fetch each
time, the site over both addresses (so Linode's network finds us over IPv6 too,
without being told that we listen), port 80's redirect over both. Each of those took
six minutes, and four once the Linux no longer waited for a swap disk: three of them
are Linode's reboot of a system that does not shut down when asked. Started from its
disk, k15 answers 60 s after the command. What Linode's DHCP says: the address with a
mask of /24, the router `.1` of that network (fe:ff:ff:ff:ff:ff), twenty name servers,
a lease of **30 minutes**, from a server (10.210.3.87) that is not on the network.
So a lease is renewed every 15 minutes there: an image that counts (`DEBUG=3`), up
for ten hours, had asked 41 times and been told yes 41 times, serving at the end. A
`linodes reboot` that names no configuration starts k15 again (the configuration last
started), in three and a half minutes. Not seen there: more than one processor, RAM
above 4 GiB, load.
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
  `reboot` in the rescue system does not.
- `--disk DEVICE`: the machine's disk, where the rescue system sees more than one.

What happens, in this order (`k15`: `live`, `rescue`, `itself`, `write`, `up`):
1. `publish`: before the machine leaves, the certificate the site shows is fetched and
   checked as a browser would check it (but for its dates). If it shows none (three
   tries), the machine is not touched: nothing would vouch for it afterwards.
2. The machine goes into its rescue system. What answers ssh there has host keys
   nobody has seen before, so it has to say that it is the machine another way: **the
   last 64 KiB of its disk hold its key and certificate** (where the deploy before
   this one put them: `idput`), and with that key it must sign for a certificate we
   know to be the machine's (`proves`): the one from step 1 (`publish`), or the one in
   the folder the image was packed from (`deploy`, `renew`: the machine is then sent
   nothing it has not got). A signature, not what a key file says of itself: a
   certificate where the key should be, or a key file with the site's public half
   pasted in, are refused. A machine that cannot show it is sent nothing and started
   as it was. `--first` is for one that has nothing to show yet (its first image; a
   site that is down; a machine already in its rescue system when `publish` begins):
   then the route to it is all that vouches for it, as for any first ssh to a new
   server.
3. `publish` takes key and certificate from there (it keeps nothing here), and gets a
   new pair if the certificate ends within `--days` (30), lacks a name, or is one
   this machine does not believe (a private CA's or the test server's, which an
   earlier image left there and `--first` let in; with `--staging` such a one is
   kept): a new key made here, and certbot on the rescue system answering Let's
   Encrypt on port 80 for the request (installed there with apt if it is not there).
   What comes back has to
   be a certificate for that key that this machine believes, or it is as if none had
   come. `deploy` and `renew` have theirs in the folders `k15 pack` made.
4. The disk is discarded (or its first 128 MiB zeroed), the image written, the key and
   certificate put at its end, the image read back and compared; then the machine is
   started from the disk, and the command waits for a verified fetch.

If no certificate comes, or the site cannot be packed, nothing has been written, and
the machine is started as it was (`renew` then also puts the old key and certificate
back in their folder). If writing fails half way, the machine stays in its rescue
system and the command says so: its disk no longer says who it is, and the next try
needs `--first`. A minute or two without a server each time: what the rescue system
takes to come up, mostly.

`tools/hosttest.sh` runs all of that against a machine that is made up: its disk a
file, its rescue system a shell with six commands replaced, "start from the disk" a
QEMU.

### Hosts
What the image needs of one: a BIOS that starts the first sector of the disk (not
UEFI alone), a virtio network card, an IPv4 address by DHCP (or `-i`), and a processor
as the README says. For IPv6 it has to be told the machine's address (`-6`): the one
the host shows for it (at Hetzner the first of the machine's /64, `...::1`, is the
custom; where addresses are made from the card's, the one made so).
- **Hetzner Cloud** (see above for what was tried; an address it gives out has been
  another machine's: with `--grub`, ssh has to know the new machine first):
  `--rescue 'hcloud server enable-rescue --ssh-key KEY NAME && hcloud server reset
  NAME'`. The rescue system is for one start: `reboot` in it starts the disk, so no
  `--boot`. One disk, /dev/sda. Their documentation: "By default, cloud servers obtain
  their Primary IPv4 address via DHCP"; IPv6 is "statically configured", gateway
  fe80::1.
- **Linode (Akamai)** (see above for what was tried). Its own rescue system (Finnix,
  `linode-cli linodes rescue`) wants a hand at the console first ("you need to use
  Lish at least once in order to start SSH": read, not tried). What does for one
  without a hand: a Linode has several disks and several configurations, and a small
  Linux on a second disk is the rescue system. Once:
  `linode-cli linodes create --type TYPE --region REGION --label NAME --booted false`
  (no image), then `linodes disk-create ID --size 3000 --image linode/debian13
  --root_pass ... --authorized_keys "$(cat KEY.pub)"` and `linodes disk-create ID --size
  64 --filesystem raw` (a disk is listed only once it is ready), then two
  configurations: `linodes config-create ID --label helper --kernel linode/grub2
  --devices.sda.disk_id LINUX --devices.sdb.disk_id RAW --root_device /dev/sda` and
  `linodes config-create ID --label k15 --kernel linode/direct-disk
  --devices.sda.disk_id RAW` (Direct Disk starts the disk's first sector). In the
  Linux, once: take the swap line out of /etc/fstab (the image expects a swap disk, and
  waits 90 s for it at every start). From then on `--disk /dev/sdb --rescue 'linode-cli
  linodes reboot ID --config_id HELPER' --boot 'linode-cli linodes reboot ID --config_id
  K15'`. The Linux is on the machine's disks but not running while k15 is; who can
  start it is who has the account's token, as with any rescue system. **Three minutes
  more without a server than elsewhere**: a reboot asks the running system to shut
  down, and takes three minutes over k15, which does not hear it. IPv6: the address is
  made from the card's (SLAAC), and `linodes view` shows it: `-6` with that.
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

### Is that machine running what the source makes?
Nobody can read a machine's disk from outside, and its image holds its key, so the
image cannot be handed round. What can be: `made`, which every build writes beside the
image (`./k15 publish` prints its hashes, so a workflow's log has them) and which
says what the image is without its key. Whoever has it, this source at the commit it
names, and the certificates the server shows, makes the system part again with
`tools/repro.sh system made chain.pem` and gets the same bytes or not: so "the 14 KB
are what the repository says" is something anybody can check, as far as the owner's
word that `made` is the running image's goes. (The site's part is the site, packed:
`KEYLESS=1 ./k15 pack` with the same folder and settings makes the whole image
without its key, the same bytes if gzip and brotli are the versions `made` names.)

### A push publishes
`ci/publish.yml` is a GitHub workflow for the repository that holds a site (its head
says what to tell it: seven variables, two secrets). A push to `main` runs `./k15
publish`; once a day it runs with `--if-due --days 45`, which looks at the certificate
the site shows and does nothing else until that has 45 days left; by hand it can be
run with "first" for a machine's first image. The site's key is in no repository and
no secret: it is made on the runner, lives on the machine's disk, and is fetched from
there by the next run. Renewal would need no machine of the user's, if GitHub started
the daily run: it has not been seen to (below), so until a run that says "schedule"
shows under Actions, a push, a run by hand or a cron job of one's own with `./k15
publish --if-due` has to come within the certificate's last 45 days.
- Who can publish: whoever can push to that branch, and whoever has the two secrets
  (the host's token and the ssh key for its rescue system). The token can do whatever
  its owner can in its project: a project for that machine alone.
- GitHub switches a scheduled workflow off in a public repository after 60 days in
  which nothing happened there. The workflow's last step asks for it to stay on
  (enabling the workflow through the API); that this resets those 60 days is what
  others' tools for it say, not something tried here. 45 days, not 30, so that a run
  that did something comes before the 60 are over.
- Run on GitHub, in a private repository made for it, against a Hetzner server and
  Let's Encrypt: the push that brings the workflow fails, as it should (nothing vouches
  for the machine yet, and it is left alone); by hand with "first", 2 min 8 s to the
  site under a new certificate; a push that changes the page, 1 min 34 s, the machine
  showing its key. The step that asks to stay on, run by hand in a copy that allows
  that, is let through with the workflow's own token.
- **Not seen: a run that the schedule starts.** Tried twice in private repositories of
  a free account two months old. First with the schedule at every ten and then every
  five minutes: none in three hours (the first commits there had an author GitHub
  knows nobody by; a later one that it does know changed nothing in 90 minutes). Then
  on 2026-11-23 in a new repository, every commit the account's own: at every ten
  minutes none in 49 minutes, then at minutes 7, 22, 37 and 52, away from the hour
  (a commit that changes the cron line is what GitHub's pages say sets a schedule
  going), none in 110 minutes more, seven of its times gone by. All that while the
  workflow was `active` on the default branch, Actions allowed everything, the account
  could be seen without a login, and both pushes ran within seconds (the second one
  published in 1 min 34 s and kept the certificate). GitHub's pages name no wait for a
  new schedule and no rule for private repositories or free accounts: only that
  scheduled runs are late or dropped under load. Not looked at: the account's billing
  page (the token used could not read it), a public repository, an older account. So
  the cause has no name, and the schedule is not to be counted on. What such a run
  does beyond the others is `--if-due`, seen on a real machine by hand.

## Beside a Linux (`--grub`)
For a server that keeps its Linux: one that is measured, where a reset brings Linux and
ssh back in 25 s. HOST is its address, NAME what the host calls it.
- `./k15 pack FOLDER -n HOST -i HOST -c cert-hz -o build-hz` (for the comparison's
  page: `./k15 pack www ... -o build-hzb --plain80`), then `./k15 deploy HOST build-hz
  --grub --reset 'hcloud server reset NAME'`: if Linux does not answer ssh (k15 is
  running), the server is reset; then the image is copied to /boot/k15.bin and the
  server reboots into it ONCE through a GRUB entry ("k15" in /etc/grub.d/40_custom,
  loaded with `multiboot`; where /boot is a file system of its own the entry says
  /k15.bin on that one, which no server here has had: not seen to boot), and the
  command waits for a verified fetch. Linux stays
  installed and is what any later reset boots. Up 4 s after the reboot (all 4 GiB are
  zeroed, and the curve tables take 25 ms).
- With `--persist`, Linux gets a unit (`k15-chain.service`) that starts k15 a minute after
  Linux has come up, unless /run/k15.hold exists: so k15 comes back by itself after a reset
  (90 s), and `./k15 deploy`, which touches that file as soon as ssh answers, still gets
  in. Without `--persist` the next deploy takes the unit out again. `./k15 renew HOST
  OUT --grub --reset '...'` renews such a server's certificate (certbot on its Linux).
- `curl --cacert build-hz/ca.pem https://HOST/` and `curl http://HOST/`
- The reset button is `hcloud server reset NAME`: it boots Linux (GRUB's default)
  whatever the image does. The image never answers ping. A fault resets the machine by
  itself (nobody handles it: `GDT`), which boots Linux again; a hang does not.
- By hand: `make B=build-hz CERT=cert-hz NAME=HOST IP=HOST` and `B=build-hz
  tools/deploy.sh root@HOST`.
- For a first look at anything new, add `DEBUG=1 LIFE=8` to that `make`: the page on
  port 80 then starts with how many processors take frames (less 1) and which one
  answered, and the machine resets itself after about 8 minutes whatever happens (a
  `LIFE` image is for nothing else). Without `LIFE`, an image whose network side does not
  work stays up until somebody presses reset.
- A load generator is a second server next to it, for an hour: `hcloud server create
  --name k15-load --type ccx33 --image ubuntu-26.04 --location nbg1 --ssh-key KEY --label
  purpose=k15-bench` (KEY from `hcloud ssh-key list`; the account's limit on dedicated
  cores allows one ccx33, a second generator has to be a shared type such as cpx42), then
  `bench/README.md`. It costs by the hour: `hcloud server delete k15-load` when done, and
  `hcloud server list` to see that nothing is left.
- Be modest with load from the user's home connection: load comes from a generator.
  From here, for a look: `B=build-hz DST=HOST:443 build/tapc 0.0.0.0 20000 400
  www/index.html`, and with `PLAIN=1 INFLIGHT=32` and `DST=...:80` for port 80. Base
  ports below 32768 (`docs/pitfalls.md`).
- A browser against the server: `tools/nssdb.py DIR/.pki/nssdb build-hz/ca.pem`, then
  `HOME=DIR google-chrome --headless=new --no-sandbox --user-data-dir=DIR/c --dump-dom
  https://HOST/`; `tools/ffcheck.py https://HOST/ build-hz/ca.pem "Hello"`.
  Against a real name with a real certificate: Chrome as it is, and `REALDNS=1
  tools/ffcheck.py https://NAME/ EMPTYFILE "TEXT"` (no CA to add; without
  REALDNS it looks every name up as 127.0.0.1, where the tests' servers are).
- SSL Labs: https://www.ssllabs.com/ssltest/analyze.html?d=NAME&hideResults=on&latest
  in a browser (a minute; `hideResults` keeps it off the boards of recent results).

## The certificate (`tools/gen.py`, `cert/`)
- `cert/server.key` (ECDSA P-256) and `cert/server.pem` (leaf, then intermediates) are the
  identity that gets baked in. Nothing renews by itself: `./k15 publish --if-due` is the
  command for a workflow ("A push publishes"), `./k15 renew` the one for cron (a minute
  or two without a server when it is time, nothing before). To use a certificate from
  elsewhere, put those two files there (and no `ca.pem`); `tools/mkchain.py DIR` makes a
  realistic test chain.
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
