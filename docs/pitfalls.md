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
  old host key: give ssh its own known-hosts file for a load generator. (`./k15 deploy
  --grub` took such a server for one that does not answer, and reset it. It says what
  ssh said now, and leaves the server alone.)
- WSL exports the machine's name as NAME to every shell: make does not take a NAME from
  the environment that is the host's name (not tried on WSL).

## nasm
- A non-local label ends the scope of `.local` labels. Read the first error.
- `K2`, `st4`, `XEND`, `XBEGIN`, `XTEST` are registers or instructions, not names.
- An `equ` used before it is defined costs passes until nasm gives up.
- A number is not reached relative to rip; a label plus a number is.
- make can't have file names with spaces as prerequisites.

## QEMU and the tests
- QEMU keeps the image open: rebuilding under a running VM changes nothing.
- make does not see that a variable changed: `DEBUG=3 DHMAX=120`, then `DEBUG=3` into
  the same folder, leaves the first image there (its `made` says which it is). Another
  variable, another `B=` or `-o`.
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
- A test that runs a byte to show that it can't be run has to run a "return": anything
  else faults either way. `tools/wxtest.sh` ran the site's last byte, whatever that
  was, and could not have failed; nor did it have a site that began where the code ends.
- `-device loader,addr=A,data=D,data-len=N` puts bytes into a guest's memory before
  its BIOS runs (what a loader may have left); `-action shutdown=pause` stops a
  machine where it would start over, with its memory still to be read.
- A test's ports are the suite's: two tests at once on one port, and the QEMU that
  could not start looked like a machine that had ended, which is what that test
  waits for. "It ended" has to mean: by itself, without a word, with status 0.
- "Its answer is near the new connection's first number" does not say that there is a
  new connection: one client's cookies lie multiples of 2^14 apart, and the old
  connection answering looked the same. The answer begins at exactly that number + 1.

## Code
- Sequence numbers are compared by the sign of their difference (`js`/`jns` after
  `sub`), never with `jl`/`jle`: those break where a segment straddles 2^31.
- `mulx` leaves 64 bits in rcx: `mov cl, n` after it is not a count. `and` between an
  `add` and its `adc` takes the carry away.
- A helper called from a waiting loop must not touch the loop's registers.
- A register that "is still zero" isn't after a call that returns something in it, or
  that only says "clobbers esi" in its comment (`find` wrote an IPv6 client's identity
  through esi after the hash had moved it: into the hash). Nothing failed but 1
  connection in 5,000 under reordering.
- Whether two clients are told apart shows in a small table: with millions of slots
  two clients never met, and "everybody is the same client" passed 30,000 connections.
- A check in front of a loop's label is skipped by every jump to the label.
- Memory we did not zero is not zero (the transmit lock in low memory).
- What is in BSS is per processor, whether one thinks of it or not. Shared state goes
  in low memory.
- Where a jump lies can cost 6% on Skylake and nothing on Zen 2: see `HOT`.
- Aligning is not padding: where an image is loaded is a number too (`DELTA`). nasm's
  `org` wants that number on its first pass, so what depends on where the code ends
  takes an assembly of its own to find.
- nasm removes its output when it fails: with `-o /dev/stdout`, as root, that is the
  device, and the next build writes the image, key and all, into a file of that name.
  Assemble into a file.
- A page a loader read through is not empty. The boot sector reads the image in pieces
  at 0x8000, the page the other processors start in, which can be executed: it held
  the image's last piece, site and all. What is made executable is zeroed first.
- Two hosts send a RST, with two numbers: one that has the connection and gives it
  up, at its own next number; one that has none, at the number of our ack. They
  differ while our ack is held back a byte. We take the second: every later segment
  of ours brings it.
- The sequence number is looked at before the ack, or the ack alone will do: with any
  sequence number at all, a made-up ack moved `C_ACK`, and one in ten thousand ended
  a response. The first rule about acks (data and FIN only) left that open; the
  reader who had not written it saw it.
- The key share is found by walking the ClientHello. Searching for its first four
  bytes failed once in two million handshakes. Extensions come in any order.
- Clients send a ChangeCipherSpec record before their second ClientHello.
- A processor always has an interrupt table unless it is told an empty one. Ask QEMU
  (`info registers -a`) what each processor has.
- A timer that sends again needs an end.
- What one timer sends unasked, another part takes for a sign: the SYN-ACK that goes
  again after 0.25 s makes a client 300 ms away acknowledge twice, and the flight goes
  twice for that. "A flight sent twice says nothing of the round trip" then left every
  such client without one, which is every client the measurement was for. Watch the
  wire at the round trip the change is about (`DELAY=300`), not at the tap's 0.1 ms.
- Waiting to send is no reason not to receive: drain the device's ring from every
  loop that waits.
- Under overload what matters is where frames wait: deep rings of our own, not the
  device's 256.
- A length is compared before anything is taken off it: `sub ecx, 20` / `cmp ecx, 20`
  let an IP total length of less than 20 pass for 4 GiB, and the next write was the
  machine's end. One frame (`tools/rawtest.py`).
- What a router would have dropped is still a frame to whoever is on the same link.
- What was counted is no bound for a walk that comes after, once another processor can
  change it in between (`find`: the free slots of a bucket). Every walk has its own end.
- A processor that has no work must not do the idle work either: its share of a shared
  table is somebody else's (`tidle`, with three processors).
- r8 to r15 are the crypto's scratch: what is in them is secret until it is set. A
  register that goes into a frame is set first (the server's name in a DHCP REQUEST was
  whatever r9 held, until an offer without that option was thought of).
- A test's server must not be able to say "yes, for a year" by accident: the random
  DHCP answers silenced the client they were meant to exercise, and the test passed
  with 150 of 13,000 read.
- What several processors know and one of them changes in more than one step is
  changed by one processor only, or in one step. The DHCP client's three words were
  written by whoever got the answer: "what is in low memory is everybody's" was the
  design, and the fault. Give the frames that change it to one processor (`drain`).
- A door that is "open for milliseconds a day" is open for as long as nobody shuts
  it: asking for a renewal that no server answers went on for ever, with one number.
  What is random in a question is made anew for every question.
- A mask after `HOT` can be stale without the build saying so, as long as the routine
  happens to sit well: `xdh`'s was, until 20 bytes of code in front of it moved it.
- A length that is echoed is bounded where it is read: a session id of more than 32
  bytes went back with lengths that wrapped at 256. And a frame shorter than what is
  read of it leaves the frame before it to be read: a short ARP request was answered
  from that.
- "It takes an hour and a nanosecond" is no reason to leave a race: a host takes a
  processor away for milliseconds, in the middle of anything. Close it, and make the
  test hold one side still (`RACE=n`, `tools/racetest.py`).
- rdrand's "success" proves nothing: processors were sold in 2019 whose rdrand said all
  ones every time, and that it had succeeded. `rand` compares each draw with the last.

## Measuring
- Where a frame's time goes can't be seen from outside. Over tap QEMU's packet path
  is the limit; on the server the network path is (about 130,000 frames a second).
- The server is not the same machine from hour to hour. Compare two images in turn,
  in one session, several times each.
- The load generator's `nstat` says what kind of trouble it is: SynRetrans (a SYN or
  its answer lost), TCPTimeouts (data), TcpInErrs (a SYN-ACK of ours sent again).
- A step at 1 s in the times is a SYN, at 200 ms a segment. A smooth tail is a queue.
- A number nobody measured is a guess. A feature somebody else sized is not sized.
- Two fetches through a path that loses packets say nothing: 6 MiB through 1% loss took
  14 to 25 s with one and the same image. A rule was changed for a difference of that
  size before nine fetches each showed there was none.
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
- What a file is called (its Content-Type) came from this machine's /etc/mime.types
  for the endings pack.py does not know: the same site packed differently on another
  machine. Python's own table now.
- A rescue system has host keys nobody has seen: ssh there proves nothing. What does:
  the machine's disk has the key of the certificate the site just showed (`k15`:
  `itself`). Before that, nothing secret goes to it.
- Which key a file is about is not who has the key: `openssl pkey -pubout` says what a
  key file says of itself (its public half is written in it, and nobody checks it
  against the secret one), and a certificate says the same. Ask for a signature
  (`proves`). The review that had not heard why the check was right found this in
  half an hour; the test beside the code had 21 checks and not this one.
- What takes a machine down must be the last thing that can still be refused: whatever
  can be known before (does the site show a certificate? can the request be made?) is
  asked before, and what can only be known after starts the machine again when the
  answer is no.
- `dd of=FILE` cuts a file to what it writes, and leaves a disk as long as it is: say
  `conv=notrunc`, so that a test with a file for a disk sees what a disk would.

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
