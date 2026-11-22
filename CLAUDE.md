# k15: a folder of static files as a bootable, sealed HTTPS server

One assembly unit (`src/os.asm`, which includes the other files of `src/`, a subsystem
each) that boots an x86-64 cloud server and serves a static site over TLS 1.3, with the
site packed behind it in the same image. `./k15 pack FOLDER`
makes the image, `./k15 run` boots it in QEMU, `./k15 publish FOLDER HOST` puts a site
on a machine in one step (`./k15 deploy HOST`: an image packed here).
Public at https://github.com/FileSherlock/k15.

This file is rules and the present state, and it is kept short: no history, no
measurement series, no description of how a routine works. Those are in `docs/`, read
when needed:

- `docs/commands.md`: every command, script and make variable
- `docs/internals.md`: layout, memory, our address, IPv6, processors, TCP, the tables,
  curves, records, and the shortcuts that remain. Read the part you are about to change.
- `docs/server.md`: the server, how an image gets onto a machine, hosts, the certificate
- `docs/pitfalls.md`: what went wrong before and what was tried and rejected
- `bench/README.md`: the comparison with nginx and Caddy, method and numbers
- `tools/ec.py` (its docstring): the curve code's other half

## Decided with the user
- This checkout (/home/jaguarm/code/k15) is the branch `dev`: the project is developed
  further here, and stays minimalistic. The features of "Next" are added, each in the
  smallest form that does its job, and nothing beside them. `main` is the small system.
- **Security can never be lowered, only raised.** Everything behind TLS is in scope:
  anything a packet can make it do. Port 80 says one public thing to everyone.
- Bytes: on this branch a feature of the list is not stopped by what it costs, but it is
  built to cost few, and what it costs is said ("Where it stands", `docs/commands.md`).
  When the branch goes back to `main` the measure is connections per byte of image: a
  feature has to pay for its bytes.
- Scope: the best product in its niche, "a clunky, limited but fast and secure OS".
  A new image for every change of content or certificate is the point, not a defect.
- TLS 1.3 only, one cipher: AES-128-GCM, which every TLS 1.3 client has (no
  ChaCha20-Poly1305: what it cost in bytes bought nothing).
- Not to be built: session tickets, SACK, post-quantum key exchange, TLS 1.2 (so SSL
  Labs stays at A, not A+), ACME or a clock inside the image, a ClientHello in two
  records.
- The certificate chain stays at four certificates until the user says otherwise.
- Ask before removing any of the TLS shortcuts listed in `docs/internals.md`.
- Commit and push without asking: what has passed the tests below for its kind of change
  goes onto `dev` and is pushed. Nothing goes from here to another branch without the
  user's word.
- `hcloud` may be used to create, reset and delete servers (a load generator costs by
  the hour: delete it, then `hcloud server list`), in the project for trials only:
  every command with `HCLOUD_CONTEXT=k15-dev`.
- Tests run on 1 and 2 processors.

## Where it stands
- The system is 15,130 bytes. It asks for its address by DHCP; built with one (`IP=`,
  `-i`) it has no DHCP client and is 14,616. With an IPv6 address as well (`IP6=`, `-6`:
  it has to be told one) it is 15,850. (Between 43 and 60 of those bytes are padding
  in front of the hot routines, which goes by what lies before them: `HOT`.)
- It boots from a BIOS boot sector or GRUB, uses all the RAM and up to 4 processors,
  modern virtio-net, and serves GET and HEAD by path with compressed forms, ETag and
  304, keep-alive, a 400 without Host, and a redirect on port 80. The timer for what it sent goes by the
  connection's round trip.
- `./k15 publish`, `deploy` and `renew` write the raw disk from a host's rescue system
  (`--grub`: beside a Linux, for a server that is measured); `ci/publish.yml` publishes
  on a push and looks at the certificate once a day.
- Every build says what its image is without its key (`OUT/made`); the system part can
  be made again from the source, that file and the certificates (`tools/repro.sh`).
  With NASM 3.01.
- Memory per held connection: 24 bytes on port 80, 128 bytes for TLS.
- On the server (2 shared vCPUs) it does 7,300 to 8,800 new TLS connections a second
  and 100,000 to 120,000 requests a second on kept connections, two to three times
  nginx; large files at 1.2 GB/s, a quarter more than nginx did. Measured with `main`'s
  system; this branch's does the same within the spread of runs, on one server, side by
  side with `main`'s: `bench/README.md`.
- Tested from outside as well: Wycheproof's vectors, Valgrind with the secrets
  undefined, tlsfuzzer, real ClientHellos damaged at random. All pass. What tlsfuzzer's
  scripts miss in us is the shortcuts of `docs/internals.md` and nothing else; each is
  named in `tools/tlsfuzz.sh`.

## What "secure" means here
A validating client gets server authentication, confidentiality, integrity and forward
secrecy against a network attacker, and no packet makes the server leak its key:
- a fresh X25519 secret, ECDSA nonce and server random per handshake, from `rdrand`.
  Each draw is compared with the one before (`rand`); a stuck generator ends the machine
- ECDSA nonces are made 64 at a time per processor and each is used once (`stock`). A
  nonce used twice gives the key away: keep it that way
- the key exists only in the image and, on a machine written from its rescue system, in
  the last 64 KiB of that machine's disk. `build*/` and `cert*/` hold it, are not in
  git, and are for their owner's eyes only; so is /boot/k15.bin on a server with `--grub`
- a machine in its rescue system is sent nothing secret until it has signed with the key
  of a certificate known to be its own (`k15`: `proves`; `--first` says there is none)
- a client record is read only after its AEAD tag has verified, compared in constant time
- only code is executed and it is never written; nor is the site. A page that can be
  executed holds code and nothing else of the image (no constant, no key, no
  certificate, no byte of the site), and nothing a loader left. Everything a packet
  can fill is data the processor refuses to run
- of a segment nothing is used unless it is where its connection is (its sequence
  number) and its ack is one the client can have sent; a RST ends a connection at one
  number, the one our acks have said
- a fault is the machine's end on every processor: each has an empty interrupt table
- a connection's key seals 2^24 records (and takes at most 2^32 - 2 from the client),
  then the connection is closed
- nothing of a request is reflected in an answer
- nothing in the curve arithmetic, table lookups or ciphers branches on or indexes with
  a secret; an X25519 key share that makes the shared secret zero is refused
- attacker-controlled lengths and indices are bounded
- nothing is traded for forward secrecy: no reused key shares, no derived secrets
- an address is taken only from a DHCP answer to the question being asked, and from
  nobody while none is asked

## Workflow
Tests can't share the machine: run suites one after another and nothing beside them.
Don't change the source or a test script while a suite runs.
- After every change: `./measure.sh` (ten seconds).
- After touching crypto or `tools/ec.py`: `make test` (the model first, then the asm),
  `make outside` and `make ct` (`tools/outside.sh fetch` once, for what they run with).
- After touching the handshake, records, or what a bad packet gets:
  `unshare -Urn tools/tlsfuzz.sh` (three minutes).
- After touching whose segment a segment is (`tcp.est`, `.odd`, a RST's in `.slot`):
  `unshare -Urn ./tap.sh python3 tools/acktest.py` (seconds), and the lossy and
  reordered runs as below.
- After touching `dhask`, `dhsend`, `dhcp` or what `tcp` lets through to them:
  `unshare -Urn tools/dhcptest.sh` (a minute), a few times, and once with `real`.
- After touching `tcp6`, `nd`, `prf6`, `find`, `tcp_seg` or `drain`: `B=build-site6
  unshare -Urn ./tap.sh python3 tools/v6test.py`, and the suite's `*6*` runs.
- After touching `k15`: `tools/k15test.sh` and `unshare -Urn tools/hosttest.sh` (a
  minute: a machine that is made up; what a host does is not seen there).
- After touching `tools/gen.py`, `tools/pack.py`, `tools/made.py` or the Makefile:
  `tools/repro.sh` (seconds).
- After anything else: `tools/suite.sh` (85 runs, twenty minutes). Also with `SMP=1`
  after touching what processors share or how the machine starts.
- After touching boot or the polling loops: `measure.sh` with `DEBUG=1` and `LIFE=`
  images too (`DEBUG=1` fails at port 80's page: its page is the counters).
- After touching `start`, the page tables, `tramp`, `codend`, `src/boot.asm`,
  `tools/mkdisk.py` or how the Makefile finds `DELTA`: `tools/wxtest.sh` (half a
  minute: what must not run, with controls), and once through QEMU's own loader
  (`-kernel`).
- After touching `.resend`, `.tx`, `sendseg`, `tcp_send`, the timers, handshake buffers
  or cookie rules: the lossy runs many times over (16 runs of each kind, and the site
  test under loss a few times). What is wrong there is wrong once in thousands.
- After touching what lets segments go (`C_CW`, the window, what counts as lost):
  `tools/bneck.sh` over a few paths next to the last commit's image.
- make says if a hot routine has a jump on a 32-byte boundary: then
  `tools/jcc.py build/os.lst mask ROUTINE` and the new mask after `HOT`.
- Then a real machine, for anything that could behave differently there, and `bench/`
  from a load generator for anything that could change what it does under load: on a
  server made for it.
- A claim about the machine is checked on the machine (QEMU's monitor, a packet
  capture), not read from the docs. A new behaviour gets a test that fails without it.
