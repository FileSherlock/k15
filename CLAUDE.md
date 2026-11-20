# k15: a folder of static files as a bootable, sealed HTTPS server

One assembly file (`src/os.asm`) that boots an x86-64 cloud server and serves a static
site over TLS 1.3, with the site packed behind it in the same image. `./k15 pack FOLDER`
makes the image, `./k15 run` boots it in QEMU, `./k15 deploy HOST` puts it on a server.
Public at https://github.com/FileSherlock/k15. https://15kb.org/ is deployed from here.

This file is rules and the present state. It is kept short: nothing goes in here that
is history, a measurement series or a description of how a routine works. Those live in
`docs/` and are read when needed:

- `docs/commands.md`: every command, script and make variable
- `docs/internals.md`: layout, memory, processors, TCP, the tables, curves, records,
  and the shortcuts that remain. Read the part you are about to change.
- `docs/server.md`: the server, how to deploy, the name, renewal, the certificate
- `docs/pitfalls.md`: what went wrong before and what was tried and rejected
- `bench/README.md`: the comparison with nginx and Caddy, method and numbers
- `tools/ec.py` (its docstring): the curve code's other half

## Decided with the user
- **Security can never be lowered, only raised.** Everything behind TLS is in scope:
  anything a packet can make it do. Port 80 says one public thing to everyone.
- The measure is connections per byte of image: a feature has to pay for its bytes.
  Don't golf it, don't bloat it.
- Scope: the best product in its niche, "a clunky, limited but fast and secure OS".
  A new image for every change of content or certificate is the point, not a defect.
- TLS 1.3 only, one cipher: AES-128-GCM, which every TLS 1.3 client has (no
  ChaCha20-Poly1305: what it cost in bytes bought nothing).
- Not to be built: session tickets, SACK, post-quantum key exchange, TLS 1.2 (so SSL
  Labs stays at A, not A+), ACME or a clock inside the image.
- The certificate chain stays at four certificates until the user says otherwise.
- Ask before removing any of the TLS shortcuts listed in `docs/internals.md`.
- Commit and push: the user said "you can always commit and push" (2026-11-13). What
  has passed the tests below for its kind of change goes onto `main` and is pushed.
- `hcloud` may be used to create, reset and delete servers (a load generator costs by
  the hour: delete it, then `hcloud server list`).
- Taking 15kb.org down for tests needs the user's word each time.
- The bounty's page and README are on the branch `bounty`, not on `main`. 15kb.org is
  packed from that branch (`tools/bounty_ceremony.sh` refuses any other) and stays on it
  until the deadline: nothing merged into `main`, and no pull request, reaches the server.
- Keep this file short. When something is learned, put it in `docs/pitfalls.md` as one
  or two lines, or fix the docs it contradicts. Delete what is no longer true.

## Where it stands
- The system is 13,859 bytes. It boots from GRUB or a BIOS boot sector, uses all the
  RAM and up to 4 processors, modern virtio-net, and serves GET and HEAD by path with
  compressed forms, ETag and 304, keep-alive, and a redirect on port 80.
- Memory per held connection: 24 bytes on port 80, 128 bytes for TLS.
- 15kb.org runs the bounty's image since 2026-11-20: packed from the branch `bounty`,
  alone on the server's disk (no Linux), with a Let's Encrypt certificate until
  2027-02-18 whose key is also the key of the Bitcoin address on its page. That key is
  not on this machine: the user has it as 24 words. SSL Labs: A.
- On the server (2 shared vCPUs; last measured 2026-11-14) it does 7,300 to 8,800 new
  TLS connections a second and 100,000 to 120,000 requests a second on kept
  connections, two to three times nginx; large files at 1.2 GB/s, a quarter more than
  nginx did. Numbers and method: `bench/README.md`.
- Tested from outside as well (2026-11-14): Wycheproof's vectors, Valgrind with the
  secrets undefined, tlsfuzzer, real ClientHellos damaged at random. All pass. What
  tlsfuzzer's scripts miss in us is the shortcuts of `docs/internals.md` and nothing
  else; each is named in `tools/tlsfuzz.sh`.

## Next
1. For the user to decide, each described in `docs/internals.md` ("Shortcuts that
   remain"): two TLS shortcuts that the tests from outside point at: a ChangeCipherSpec
   after the ServerHello, which RFC 8446 wants sent to a client that has a session id
   (30 bytes or so); and a ClientHello in two records.
2. The handshake further: OpenSSL's assembly does the ladder and the signature in
   about a fifth fewer cycles.
3. Later: IPv6, DHCP, a retransmission timer that knows the round trip, pacing, zstd,
   taking out the reset knock.

## What "secure" means here
A validating client gets server authentication, confidentiality, integrity and forward
secrecy against a network attacker, and no packet makes the server leak its key:
- a fresh X25519 secret, ECDSA nonce and server random per handshake, from `rdrand`.
  Each draw is compared with the one before (`rand`); a stuck generator ends the machine
- ECDSA nonces are made 64 at a time per processor and each is used once (`stock`). A
  nonce used twice gives the key away: keep it that way
- the key exists only in the image. `build*/` and `cert*/` hold it, are not in git, and
  are for their owner's eyes only; so is /boot/k15.bin on the server
- a client record is read only after its AEAD tag has verified, compared in constant time
- only code is executed and it is never written; nor is the site. Everything a packet
  can fill is data the processor refuses to run
- a fault is the machine's end on every processor: each has an empty interrupt table
- a connection's key seals 2^24 records (and takes at most 2^32 - 2 from the client),
  then the connection is closed
- nothing of a request is reflected in an answer
- nothing in the curve arithmetic, table lookups or ciphers branches on or indexes with
  a secret; an X25519 key share that makes the shared secret zero is refused
- attacker-controlled lengths and indices are bounded
- nothing is traded for forward secrecy: no reused key shares, no derived secrets

## Workflow
Tests can't share the machine: run suites one after another and nothing beside them.
Don't change the source or a test script while a suite runs.
- After every change: `./measure.sh` (ten seconds).
- After touching crypto or `tools/ec.py`: `make test` (the model first, then the asm),
  `make outside` and `make ct` (`tools/outside.sh fetch` once, for what they run with).
- After touching the handshake, records, or what a bad packet gets:
  `unshare -Urn tools/tlsfuzz.sh` (three minutes).
- After anything else: `tools/suite.sh` (59 runs, ten minutes). Also with `SMP=1` and
  `SMP=4` after touching what processors share or how the machine starts. On 4,
  `raw1m_20k` fails when the host is busy: run it alone before believing it.
- After touching boot or the polling loops: `measure.sh` with `DEBUG=1`, `KNOCK=` and
  `LIFE=` images too (`DEBUG=1` fails at port 80's page, as it always has).
- After touching `.resend`, `.tx`, `sendseg`, `tcp_send`, the timers, handshake buffers
  or cookie rules: the lossy runs many times over (16 runs of each kind, and the site
  test under loss a few times). What is wrong there is wrong once in thousands.
- After touching what lets segments go (`C_CW`, the window, what counts as lost):
  `tools/bneck.sh` over a few paths next to the last commit's image.
- make says if a hot routine has a jump on a 32-byte boundary: then
  `tools/jcc.py build/os.lst mask ROUTINE` and the new mask after `HOT`.
- Then the server, for anything that could behave differently on a real machine, and
  `bench/` from a load generator for anything that could change what it does under
  load. Both need the user's word (see above).
- A claim about the machine is checked on the machine (QEMU's monitor, a packet
  capture), not read from the docs. A new behaviour gets a test that fails without it.

## Before touching the live site
- Until 2027-02-18 nothing is deployed to 15kb.org and `k3` is not reset, put into the
  rescue system or rebuilt: any of that needs the user's word, and the rescue system is
  a way to the bounty's key. `./k15 deploy` and `./k15 renew` cannot reach it (no Linux).
- The renewal timer (`15kb-renew.timer`) is disabled and stays so: it would make a new
  key. A change before the deadline is the user's to make: `tools/bounty_ceremony.sh
  --redeploy` from the branch `bounty`, with the 24 words.
- `tools/monitor_bounty.py` says whether page, certificate and address are as they
  should be.
- Never remove `build-*` or `cert-*` folders wholesale: some hold the only copy of a
  packed image or a key. `cert-15kb.org/bounty-server.pem` is what `--redeploy` and
  `--revoke` need.
