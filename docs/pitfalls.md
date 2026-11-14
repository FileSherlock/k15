# Pitfalls, and what was tried and rejected

One or two lines each. Add to it when something costs an hour; delete what stops being true.

## Shell and tools
- `pkill -f pattern` and `pgrep -f pattern` match the shell that runs them, also over
  ssh. Use `pkill -f "holdloo[p]"`, or a pid file.
- Long shell commands with a here-document can be refused: write a script file, run that.
- `perf` is not allowed here. Time pieces with `make bench`, or count cycles in the
  guest (`DEBUG=1`).
- `GROUPS=x command` gives the command nothing: bash keeps that name. Hence `KEX`.
- A script that bash is running must not be rewritten in place. Don't edit what a
  background run uses.
- `tcpdump` in tap.sh's namespace can't be killed from this shell. It goes when its
  interface goes (`ip link del`). A packet socket in Python works instead.
- tc: `action gact drop random netrand drop 100` drops everything. It is
  `gact pass random netrand drop 100`.
- Snap Firefox can't start through its launcher: `tools/ffcheck.py` runs the binary.
- `crontab` can't be written from Claude's shell. Use a systemd user timer.
- Hetzner's web console garbles `|` and `[`: use ssh. A recycled cloud address has an
  old host key: give ssh its own known-hosts file for a load generator.

## nasm
- A non-local label ends the scope of `.local` labels. Read the first error.
- `K2`, `st4`, `XEND`, `XBEGIN`, `XTEST` are registers or instructions, not names.
- An `equ` used before it is defined costs passes until nasm gives up.
- A number is not reached relative to rip; a label plus a number is.
- make can't have file names with spaces as prerequisites.

## QEMU and the tests
- QEMU keeps the image open: rebuilding under a running VM changes nothing.
- slirp is slow and serial: one connection in 20 waits a second when they come faster
  than 2 ms apart, and it walks every socket. Load tests go over tap.
- Every guest processor polls: `top` shows 100% whatever the load.
- A hung test leaves a `qemu-system` spinning. Killing a load client leaves sockets in
  TIME-WAIT for a minute, and the forwarded port with them.
- Other VMs beside a suite make `raw1m_20k` fail on four processors.
- Over tap nothing is lost for lack of room. A window change needs `tools/bneck.sh`.
- netem drops a whole GSO packet as one loss, and a Linux client whose first flight is
  lost waits 3 s, then 6 s: at 5% loss a handshake can outlast a 20 s timeout.
- A failure of 1 in 10,000 does not show in one run. Run the lossy test 16 times, and
  the same on the last commit as a control.
- A test knob can break what it tests: forcing all upper bits of the initial sequence
  number took the SYN cookie's meaning away. Check a control far from the edge.
- The table space must begin on a 2 MiB boundary.
- A test's client is a TCP with rules of its own: Linux takes a reset only at exactly
  the next number it expects, and a connection that was only ever sent a SYN-ACK is
  made again by its next packet. Watch the wire, not the sockets.

## Code
- Sequence numbers are compared by the sign of their difference (`js`/`jns` after
  `sub`), never with `jl`/`jle`: those break where a segment straddles 2^31.
- `mulx` leaves 64 bits in rcx: `mov cl, n` after it is not a count. `and` between an
  `add` and its `adc` takes the carry away.
- A helper called from a waiting loop must not touch the loop's registers.
- A register that "is still zero" isn't after a call that returns something in it.
- A check in front of a loop's label is skipped by every jump to the label.
- Memory we did not zero is not zero (the transmit lock in low memory).
- What is in BSS is per processor, whether one thinks of it or not. Shared state goes
  in low memory.
- Where a jump lies can cost 6% on Skylake and nothing on Zen 2: see `HOT`.
- The key share is found by walking the ClientHello. Searching for its first four
  bytes failed once in two million handshakes. Extensions come in any order.
- Clients send a ChangeCipherSpec record before their second ClientHello.
- A processor always has an interrupt table unless it is told an empty one. Ask QEMU
  (`info registers -a`) what each processor has.
- A timer that sends again needs an end.
- Waiting to send is no reason not to receive: drain the device's ring from every
  loop that waits.
- Under overload what matters is where frames wait: deep rings of our own, not the
  device's 256.
- A length is compared before anything is taken off it: `sub ecx, 20` / `cmp ecx, 20`
  let an IP total length of less than 20 pass for 4 GiB, and the next write was the
  machine's end. One frame, from the first image to 2026-11-14 (`tools/rawtest.py`).
- What a router would have dropped is still a frame to whoever is on the same link.
- What was counted is no bound for a walk that comes after, once another processor can
  change it in between (`find`: the free slots of a bucket). Every walk has its own end.
- A processor that has no work must not do the idle work either: its share of a shared
  table is somebody else's (`tidle`, with three processors).
- "It takes an hour and a nanosecond" is no reason to leave a race: a host takes a
  processor away for milliseconds, in the middle of anything. Close it, and make the
  test hold one side still (`RACE=n`, `tools/racetest.py`).

## Measuring
- Where a frame's time goes can't be seen from outside. Over tap QEMU's packet path
  is the limit; on the server the network path is (about 130,000 frames a second).
- The server is not the same machine from hour to hour. Compare two images in turn,
  in one session, several times each.
- The load generator's `nstat` says what kind of trouble it is: SynRetrans (a SYN or
  its answer lost), TCPTimeouts (data), TcpInErrs (a SYN-ACK of ours sent again).
- A step at 1 s in the times is a SYN, at 200 ms a segment. A smooth tail is a queue.
- A number nobody measured is a guess. A feature somebody else sized is not sized.
- A grade is what the grader says today. Compare with a site that has the grade
  before writing down why.
- A fix is read best by somebody who has not heard why it is right: the review of the
  slot race found it sound, and two older faults beside it that nobody had asked about.
- A test written beside the code knows what the code knows. Vectors made elsewhere
  found in a minute that a client's point of small order makes our own key share zero.
- tlsfuzzer's scripts fail in their first lines against us for four reasons that are
  shortcuts of ours, not faults (`tools/tlsfuzz.py` says which). What it is good for
  here: the server stays up, and another implementation checks every signature and tag.
- A connection that fails at once from here is ours: another program has the port.
  Use base ports below 32768.

## Operating
- A tool "to be run from cron" must be a no-op on most days and say so itself.
- Where a key is made is where it stays: only a request travels to the server.
- Look at the headers of every kind of answer after a deploy (200, 404, 301, 405).
- Which certificates a chain can do without is a question about other people's trust
  stores, not this machine's.

## Tried and rejected
- Compressed EC point in the leaf (Firefox refuses); subjectAltName not critical with
  an empty subject (Chrome); empty issuer (curl, Firefox); CA and leaf with one serial
  (NSS).
- virtio multiqueue: the server's card has one queue pair.
- `pdep` to mask without touching the carry: slow on Zen 2.
- Ephemeral secrets derived from a boot key, or a key share reused for a window:
  forward secrecy would be lower.
- Mixing the private key into every nonce through SHA-256: `stock` runs inside a
  handshake whose hash state it would need.
- The SYN-ACK timer on every frame: under load it fired for clients whose answer was
  waiting in our ring. It runs when idle.
- Dropping SYNs first when a ring fills: the wait moves into the clients' SYN timers.
- A fixed 10 segments in flight instead of congestion control: 14 KB a round trip.
- The data timer in the SYNs' table: a SYN flood would push real timers out.
- Holding back the ack of a request for a long response: clients give up after
  seconds of unacknowledged data.
- A window that doubles past 64 KB without SACK: loses dozens of segments where the
  path is narrower, and they come back one a round trip. It grows slowly instead.
- Using what a client's SACK says without keeping it: Linux bunches its acks, and
  D-SACK looks the same.
- Three bits for the client's window shift: Linux says 10. Four bits.
- Getting past 130,000 frames a second on the server: a second generator, one
  processor, no interrupts: the same ceiling each time.
- The bounty's page is 19 bytes from losing its compressed forms: gzip has to bring `/`
  into one record (1,418 bytes with its head), and a real address packs worse than the
  placeholder's zeros. After a change to `site/index.html`, look at `site.json`'s forms.
