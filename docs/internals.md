# How it works

Read the part you are about to change. `tools/ec.py` has the curve code's other half.

## Layout
- `src/os.asm`: everything after the loader, and at its end the site (`incbin`). 64-bit
  long mode, interrupts off, a table of interrupt handlers of length nothing on every
  processor (a fault resets the machine), one polling loop per
  processor. Start-up, in 32-bit code as the loader leaves us: everything of ours below
  the table space zeroed, page tables for it (who may write and execute what), long
  mode. Then: the memory map into page tables (below), the table space zeroed and divided,
  SHA-256 constants, `ecinit` (fields, constants and tables for the curves, the programs
  unpacked), the start of the key schedule, virtio-net, the key for `prf`, the other
  processors.
  Code is 32-bit in style where it came from k2 (`pushad` is a macro for the old
  registers, the seven that are not the stack's; r8-r15 belong to the crypto and are
  nobody's to keep). Addresses below 4 GiB live in 32-bit registers; a connection's
  slot does not (`rbp`).
- `src/boot.asm`: BIOS boot sector: reads the image, however long, 64 sectors at a time
  and copies each piece to where it goes from 1 MiB up (from real mode, with segments
  that reach all of memory: set anew for every piece, the BIOS may put them back), asks
  the BIOS for its memory map (int 15h, E820), protected mode, enters the image like a
  multiboot loader (the map in a multiboot information structure at ebx, as GRUB passes
  it). `tools/mkdisk.py` writes the image's length into it.
- virtio-net: `pcird` reads PCI configuration; the driver finds 1af4:1041 or :1000 on any
  bus, walks its capabilities for the common, notify and device structures (a BAR may be
  64-bit and anywhere: each structure is mapped at a place of ours), negotiates
  VERSION_1 and, if the device offers both, CSUM and HOST_TSO4 (it sums what we send and
  cuts a frame of up to 64 KiB into segments: `TSO` says whether), and polls the used
  ring. Frames to send are built in the transmit buffers (`txbuf` gives the next one and
  waits if the device holds all N, `txgo` queues it; the two bracket a lock, the
  transmit ring being all processors'); the device is told (`txkick`, if it hasn't set
  NO_NOTIFY) when the polling loop has handled everything that came in, or every 32
  frames: telling it leaves the virtual machine and costs more than everything else
  done for a frame. A frame for the card to cut is built outside that lock, in one of 8
  buffers of 64 KiB that each processor has for itself (`txbig`: the next in a circle,
  once the device has sent what it last held, which `TXCNT`, the count of all frames
  ever queued, and the device's own count tell), queued by `tcp_big` with the 12 bytes
  in front that say how it is to be cut, and the device is told at once.
- `tcp`: ARP requests for our address get a reply (whole ones: 42 bytes; behind a shorter
  frame lies the one before it); then only IPv4 without options, unfragmented,
  TCP, to our address, with the TCP checksum right and a length that fits the frame and
  both headers (40 bytes at least: asked before 20 are taken off it), port 443 or 80 gets
  further. `tcp_send` cuts an answer into segments, `tcp_seg` builds and sends one.
  In it: `.walk` (records, whole or put together), `.tx` (a response on its way).
- `dhask`, `dhsend`, `dhcp`: where our address comes from, if the image has none ("Our
  address", below).
- `record` (a client's record: authentic? a request? for which response), `pick` and
  `seek` (which form of it, by the request's Accept-Encoding and If-None-Match), `geom`
  (how the response in hand is cut), `sendseg` (one segment of it), `sendrun` (all the
  records that may go, in one frame for the card to cut), `tarm`/`tqrun` (who waits for
  an ack), `tsc`/`clock` (the calibrated clock), `sm` (is this a connection past its handshake).
- `handshake`, `hrrmsg`, `thash` (the transcript's hash, continued, not restarted),
  `keys`, `hmac`, `expand`; `sha256`/`shablk`; `seal` with `ks64`, `aeskey`, `aes4`,
  `gh1` and four-block GHASH.
- `xdh`, `sign`, `stock`, `binv`, `comb`, `select`, `vm`, `fas`, `fmul`, `inv`, `ecinit`:
  the curves, see below. `rand`: what is random (`rdrand`, each draw compared with the
  one before).
- `tools/ec.py`: the curve code's other half: the programs, and a model of the arithmetic
  that the asm must match number for number. Read its docstring before touching either.
- `tools/gen.py`: certificate, curve programs and constants -> `build/*.inc`.
  `tools/pack.py`: the site -> `build/site.bin`, `site.inc`.
  `tools/mkdisk.py`: the disk image. `k15`: the tool on top.
- `tools/mksite.py`, `tools/sitecheck.py`, `tools/sitetest.sh`, `tools/tlsclient.py`,
  `tools/wxtest.sh`, `tools/jcc.py`, `tools/tlsprobe.sh`, `tools/k15test.sh`: the test
  site and its checker, the shared TLS client pieces, the W^X test (and what else must be
  the machine's end), the jumps on boundaries, a scanner's questions, the tool's own test.
  `tools/racetest.sh`, `tools/racetest.py`: a slot taken from under its connection's timer.
- From outside (`tools/outside.sh fetch` gets them into `ext/`): `test/outside.py`
  (Wycheproof's vectors and RFC 6979's against the host build), `test/ct.c` (the host
  build under Valgrind, secrets marked undefined), `tools/tlsfuzz.sh` and
  `tools/tlsfuzz.py` (tlsfuzzer against a running image). `test/asm.h`: the asm as C
  calls it.
  `tools/bneck.sh`, `tools/bnecktest.sh`, `tools/tl.py`: a bottleneck between guest and
  client, the test that uses it, a download's timeline from a capture.
  `tools/churn.py`, `tools/flood.py`, `tools/idletest.py`: slots given back, slots not
  given to clients that don't exist, slots taken from connections long quiet.
- `tools/vm.sh`: QEMU command line and curl options, sourced by `k15`, `tap.sh` and the
  test scripts
- `tools/bench.c`, `bench/`: the comparison with other servers (see Commands)
- `tools/ffcheck.py`, `tools/nssdb.py`, `tools/certerr.py`: the browser checks' helpers

## Memory
What the page tables say (`start`):
- The first 18 MiB as they are: the frame being handled at address 0 (`FR`: it stays as
  it came, so its fields are the packet's variables, `P_SEQ` and so on, a byte away from
  ebx = 0); the image at 1 MiB, up to 1 MiB of it; buffers and variables from 2 MiB
  (`BSS`; `OB` is our answer to one packet; the stack comes down from 4 MiB); virtio
  rings at 4 MiB (`VQ`) and behind them the page tables; receive and transmit buffers at
  5 and 7 MiB (`RXB`, `TXB`: 2 KiB each, descriptor i is buffer i, a 12-byte virtio header
  in front; `txgo` writes a descriptor's address each time, because a frame for the
  card to cut lies elsewhere); the other processors' page tables at 9 MiB and their
  memory from 10 MiB; at 16 MiB the buffers for the frames the card cuts (`BIGB`: 8 of
  64 KiB for each of four processors; here, where what the device is told is where
  the memory is: the table space is not mapped that way).
- An image of more than 1 MiB (a site with large files) pushes all of that up, in whole
  pages of 2 MiB (`LOW`, known when it is assembled: pack.py says how long the site is):
  "2 MiB" in this file and in the source means 2 MiB + LOW. An image can have 768 MiB.
- Who may do what: the first 2 MiB are in pages of 4 KiB: low memory is data (written,
  never executed) but for the page the other processors start in (code); of the image
  the pages with code are executed and not written, the rest only read. Everything from
  BSS up, in pages of 2 MiB, is data. `CR0.WP` is set once start-up has made its last
  write to a page that is not to be written (the copy of `tramp`).
- Behind that, from 18 MiB up, **the table space**: every 2 MiB of RAM that the loader's
  memory map calls available, one after the other, wherever it is. On the server that is
  the rest of the 2 GiB below 4 GiB and then what is above. Boot divides it: n handshake
  buffers and n places of 2 KiB for early segments (n a power of two: about 1/32 and 1/64
  of it; one mask, `HSMASK`), 4 n SYNs of late (128 bytes each, and a dword for when:
  `tnote`), for each of four processors a ring of n frames (2 KiB each: `drain`) and a
  queue of 4 n connections that wait for an ack (64 bytes each: `tarm`), then the table
  for TLS (an eighth of the rest: `TSHARE`), then the table for port 80. In a 4 GiB
  machine n is 16,384, and the buffers, places, SYNs, rings and queues take 248 MiB of
  it; on the server (3,982 MiB of table space) that leaves 3.8 million TLS slots and 143
  million for port 80.
- The card's structures (and the local APIC), each in 4 MiB of its own in GiB 505.
Variables in BSS are reached relative to the instruction pointer (`BSS equ mb + ...`:
nasm won't do that for a plain number). Needs 64 MiB or more.

## Our address
An image is built without an address (the default) or with one (`make IP=a.b.c.d`,
`./k15 pack -i`). With one, it is a constant in two comparisons (`NOTOURS`: the ARP
request's target, the IP header's destination), nobody is asked, and there is no UDP in
the image. Without, it is a variable, and a DHCP client is assembled in (450 bytes):
- What we send never needs it: a frame of ours answers one, and goes from the address
  that one was sent to, to where it came from (`tcp_seg` takes both from the frame in
  hand, `ethhdr` the card's address). So an address is all DHCP has to give us: no
  mask, no router, no name server is asked for or looked at.
- The first processor asks when it is time (`dhask`, every turn of its polling loop, by
  `DHT`): with no address a DISCOVER, with one a REQUEST to keep it. Both go to
  everybody (the REQUEST as RFC 2131 has a client ask that has heard nothing from its
  own server, "rebinding": to send it to the server alone we would have to find the
  way there). 342 bytes, of which 300 are the message: the least there may be. Again
  after 2 s, 4 s, ... 128 s and then every 128 s, until an answer comes.
- An answer is a frame like any other (`tcp` lets UDP through to `dhcp` whatever
  address it is sent to), so it goes to whichever processor its addresses hash to:
  what the processors know of all this is in low memory, where it is everybody's
  (`MYIP`, `DHT`, `DHB`). It counts if its UDP checksum is right or left out (0: OVN's
  DHCP does that), if it is from port 67 to port 68, has our number (`DHX`: 32 bits
  from `rand` at boot), **and we are asking** (`DHB`): once we have our address, nobody
  can tell us another until we ask again, so somebody far away who guesses the number
  has milliseconds a day to hit. Its options are walked as far as the message goes,
  and the first four bytes of three are kept: the time (51), the kind (53), the
  server's name for itself (54).
- An OFFER, while we have no address, gets a REQUEST for the address it offers, naming
  the server. An ACK makes the address ours: `MYIP`, and `DHT` is half its time from now
  (and a second; six days at most, which is what the clock's 32 bits of ticks can
  say). A NAK makes it not ours, and a second later we ask anew.
- `tools/dhcptest.py` plays the server, right and wrong (and 13,000 answers damaged at
  random); `tools/dhcptest.sh real` is dnsmasq; every test through QEMU's own network
  has QEMU's.

## Processors
The server's card has one receive queue, so the processors are fed in software. The
first one (the one that booted) empties the device's ring (`drain`): each frame is copied
into the ring of the processor whose connection it is (`prf` of its addresses and ports,
the low bits of the word that also picks the place of an early segment), its own
included. A ring holds n frames (16,384 in 4 GiB): with handshakes to make, that is half
a second of work; beyond that frames are lost, and clients send them again. Each
processor handles the frames in its ring, one at a time (`ring1`), with the same code.
The device's ring is small (256 on the server), and what finds no room in it is lost on
the host's side: so the first processor empties it before every frame it handles, and from inside whatever takes long
(`bdrain`: every 64 steps of the ladder, after each k G that `sign` has to make itself,
and while it waits for the transmit lock or a free transmit buffer).
- Each of the others has page tables of its own that differ from the first one's in two
  places: BSS and page 0 are memory of its own (BSS a copy of the first one's as it was
  when everything was set up). So all that is at a fixed address there (the frame, the
  transcript, the curve registers, the stock of nonces, counters) is per processor, and
  nothing in the code says so.
- Shared, and how: the transmit ring (`TXLOCK`, from `txbuf` to `txgo`); the connection
  tables (a connection is one processor's, but a bucket is not: a new connection takes
  its slot with one `lock cmpxchg` on the slot's first 8 bytes, against what `find` saw
  there; if another processor was quicker, the packet is as good as lost and comes
  again); handshake buffers (each processor has every n-th: `hsnew`); the places for
  early segments (a place's low bits are its processor). The queue of connections that
  wait for an ack is each processor's own.
- They are started with INIT and SIPI to "all but self" (`tramp`, copied to 0x8000: from
  real mode straight to long mode); each takes a number with `lock xadd`. Frames go to
  the largest power of two of them (`NCPUM`). With one processor nothing changes but the
  uncontended lock. One that gets no frames (the third of three; one that took its
  number after the count was read) waits for the count and then halts (`apstart`;
  `tools/cputest.py` asks QEMU; if the first processor counted nobody, it waits for
  good). Until 2026-11-14 it went round the polling loop like the others, and its turn
  at the SYNs of late (`tidle`) was at the first processor's places: it answered that
  one's SYNs again, on that one's connections.
- A slot that changes hands between processors (a connection quiet for an hour, in a
  full table) does so in one step on each side. The taker's `cmpxchg` asks for the slot's
  first eight bytes as it saw them in one look (`find.used`), C_AGE among them, and puts
  its own there, C_AGE included (`tcp.make`). The owner, before it does anything with
  that connection, changes C_AGE with an `xchg` and then looks, in one look at those
  eight bytes, whether the slot still is its connection's (`hold`). So one of the two
  finds out: the taker that the slot is not as it was (it gets nothing, and its packet
  comes again), or the owner that it has no connection (its packet is as good as lost).
  A slot quiet for all of 255 units is not taken: a packet of its own, a unit on, would
  leave C_AGE as it is.
- The owner has two ways to a slot, and both go through `hold`: a packet of the
  connection's client (`tcp`, after `find`), and the connection's timer (`tqrun`). The
  timer is no sign of life, and C_AGE is what it gives a client up by: so it keeps what
  C_AGE said and puts it back when it is done, if the slot still is that connection's
  (`own`). Until 2026-11-14 the timer worked on the slot it had looked up without any
  of this. A taker could then get the slot while the timer was in the middle of it, and
  the timer went on with a slot that was another connection's: in the test that holds
  the timer still at that point (`tools/racetest.sh`), it sent ten records of the new
  connection, sealed with the new connection's key, to the old client's address in one
  run, and in another the new connection's client got a record it could not open and
  gave up. With the two a few instructions further apart it could have sealed under
  the new key with a record number made from the old connection's numbers: the same
  key and number for two different records. What stood in the way was time alone (a
  connection that waits for an ack is given up after two minutes of silence, a slot is
  taken after 68; so a processor had to have had no idle moment for an hour, and then
  the two had to meet within the microsecond, or within however long the host takes a
  processor away for).

## How TCP works here
No copy of what was sent, except the handshake flight: everything else is made again
from what does not change. A connection knows the next byte it expects (`C_NXT`), our
next byte (`C_SND`) and the client's last ack (`C_ACK`). There are two ways of sending.
The old one, for the flight and for port 80 (whose answer is one response, the same for
every request): build all of it, send it at once, and build the end again when the
client turns out to lack it (`.resend`; the bullets from "In-order data" on). And the
one for files:

**A response on its way (`tcp.tx`).** A TLS connection past its flight (`sm`) has one
response in hand: which (`C_AS`: a number in the site; a bit for "only its head"), where
it began in our sequence numbers (`C_RS`), and the number of its first record (`C_SR`).
The response is a stretch of the image, cut into records of as many bytes as the
client's segments take (`geom`: 216, 536, 1220 or 1440, less 22 of record), so a
segment is a record, and segment number i of a response can be made at any time from
those three and i: nothing is kept, a file of a gigabyte costs a connection its 128
bytes.
- The client's acks let the next segments go. So many may be on their way as the client
  takes (its window, shifted as its SYN said: window scaling; the shift is in the top
  four bits of `C_FL2`) and as `C_CW` says: 10 to begin with, as many more as are
  acknowledged while nothing was ever lost and less than 64 KB may be on their way
  (twice as many each round trip), half as many after a loss (2 at least), and from
  then on one more for every 16 KiB acknowledged. That is TCP's congestion control in a
  byte and a bit; without it (a fixed 10, the first version) 1.5 MiB took 2.2 s over a
  round trip of 20 ms, with it 0.6 s, and with what follows 0.37 s.
- **Past 64 KB, carefully.** That much was all there could be before windows were
  scaled. More than that may be on their way only while the connection has never lost
  anything (after its first loss: 64 KB at most, for good), grows by one segment for
  every 64 KiB acknowledged (a segment a round trip at 64 KB, five at the most there
  can be, 255 segments), and a new response begins with 64 KB at most (44 segments),
  whatever the one before got to. The reason is that we find what is lost one segment
  a round trip (below), and a window that doubles up to 367 KB loses dozens at once
  where the path holds less: 6 MiB through 20 Mbit/s with a queue of 60 packets took
  23.6 s that way, 5.2 s with 64 KB and no more, and takes 4.3 s now (bench/README.md
  has seven such paths: this is better than 64 KB on six of them, 3% behind on one).
- Lost, says: an ack that repeats, once if no more than two segments are on their way
  (more such acks can't come), else three times (swapped neighbours look the same once
  or twice); the client sending old data again; and time (below). What goes again is
  the one segment at the client's ack. From then until the client's ack has reached
  `C_SND`, nothing new is sent, so every ack that moves on but not that far says the
  same: the segment it now asks for was on its way with the first and is lost too, and
  goes again at once. (It was: "an ack that moves on by no more than the segment sent
  again". A second hole further on was then left to the timer: a quarter second each,
  and half a second for the one after. With 255 segments on their way instead of 44,
  that happened on the server in every other run: `wrk` counted requests of over 2 s.)
- **Many records to a frame** (`sendrun`). Where the card cuts frames into segments
  (`TSO`), all the records that may go now are sealed into one frame, up to 45 of them
  (what 64 KiB hold), in a buffer of the processor's own (`txbig`), and the card gets
  it with the headers once, the size of a segment, and the pseudo header's sum where
  the checksum goes (`tcp_big`). A record is a segment, so the card cuts where we would
  have. If what may go is less than a third of what may be on its way, and not the
  response's end, it waits for the acks that are still to come: a small frame brings a
  small ack back, which lets a small frame go, and a full window then trickles out
  three segments at a time (on the server that was 518 MB/s where it is 920 with the
  wait). What is sent again is one record, as ever (`sendseg`); a frame that is lost
  whole (a queue on the host drops what it is given, not segments) comes back a
  segment a round trip.
- **The timer for what we sent** (`tarm`, `tqrun`). A connection that is owed something
  (an ack is outstanding, or the client's window is shut) is in its processor's queue,
  once: the first 64 bytes of a frame of its client's, the time, the ack. A polling loop
  with nothing else to do takes the oldest: not a quarter second old yet (512 ticks of
  1/2048 s, from `clock`, which scales `rdtsc` by `TSCM` calibrated against timer 2 at
  boot; twice as long for every time in vain, up to 16 s): to the back. Old enough: if
  the client has everything by now, that is that; if its ack has moved, back into the
  queue; if not, the segment at its ack goes again (and half as many may be on their
  way). As with SYN-ACKs: only when idle. And not for ever: after six times in vain
  (16 s), a client from which nothing at all has come for more than a unit of C_AGE (a
  minute or two) has gone: it is sent a reset, and its slot is free. One that takes no
  more for now but answers when it is sent to stays, as in TCP. (The reset has the number we got to, `C_SND`: a client that lacks some of what
  we sent does not take it, RFC 5961. For one that has gone that is all the same.)
- A request for the next response is taken only when the client has acknowledged all of
  this one. One that comes earlier (two requests at once) is as good as not arrived, and
  what follows it in its segment too: the client sends it again (`.busy`).
- A response that goes at once, takes several segments and is no longer than 64 KB does
  not acknowledge the last byte of the request until the client has all of it, as in
  the old way (`F_DEFER`): then even with every timer of ours lost, the client asks
  again. One that is longer than that is acknowledged at once: a client that waited
  minutes for an ack would give the connection up (Windows after five tries), and one
  that asks again while its response is still arriving looks like a loss to us.
- The client's FIN (or a method we don't serve: `record` closes after its answer) makes
  the connection closed: nothing more is taken from the client, our FIN goes with the
  last segment of what it still has to get, and the slot is free when that is
  acknowledged.
- Sequence numbers go round: which of two is further on is the sign of their difference
  (`js`/`jns` after a `sub`), never a signed comparison (`jl`, `jle`: they look at the
  overflow as well). One `jle` stopped a response for ever where it crossed 2^31
  (`docs/pitfalls.md`); the suite's `*isn*` and `site_wrap*` runs make every
  connection cross.

**Requests (`tcp.walk`, `record`).** What comes in on 443 is records. One that lies whole
in a segment is looked at where it is; one that does not (and every ClientHello) is put
together in a handshake buffer, up to 4 KB; one that says it is longer gets a reset. A
record counts if its tag is right for the client's next sequence number (`C_ST`); then
it is decrypted, and if it holds application data that begins with `GET ` or `HEAD `,
the path (up to a space, `?` or the line's end) is looked up in the site's table: the
response for it, or the one that says 404. What begins with another word in capitals
and a space gets the 405 and the end of the connection; anything else that is authentic
(an alert, a header line in a record of its own) counts and gets nothing. After 2^32 - 2
records from the client (`STLIFE` in tests), or once our key has sealed 2^24 (`KEYLIFE`),
the connection is closed so neither counter wraps.

The old way, and what both share:
- In-order data is taken (a segment that overlaps what we have is trimmed), data from
  further on is kept (see below) and gets an ack of what we expect, a keep-alive probe
  gets an ack.
- Loss shows in two ways, and both lead to `.resend`, which builds the end of what we sent
  again, from the client's ack on (the last records by sealing the response again under
  the same sequence numbers, and before them the end of the flight from the handshake
  buffer): old data arriving again with an ack below `C_SND` (the client's request is
  unacknowledged because our answer carried the ack), or the same ack below `C_SND` twice
  without data (the client got something behind a hole).
- An answer of several segments does not acknowledge the last byte the client sent
  (`tcp_send`, `F_DEFER`); that is done when the client's ack shows it has the whole
  answer. Until then the client keeps retransmitting that byte, whichever of our segments
  were lost, so a flight of several segments needs no timer either. A client that then has
  nothing to say acknowledges late (Linux: 40 ms), and gets our ack after that: one more
  small packet, no delay for the next request.
  (Two earlier rules were not enough. Acknowledging with the last segment: a hole in the
  middle plus the loss of the client's one duplicate ack left it with nothing outstanding,
  4 in 2,000 at 3% loss. Not acknowledging what the packet at hand brought: an answer sent
  again for a duplicate ack is sent for a packet that brought nothing, so it acknowledged
  everything, and if the segment that filled the hole was lost again and the next
  duplicate ack too, nobody had anything left to send: 1 handshake in 8,000 at 3% loss
  with a flight of two segments, found by running the test 16 times.)
- A retransmitted ClientHello must get the same flight, not a new handshake: the client may
  have the first one already (its retransmission was only early), and would then hold keys
  we no longer have.
- Handshake buffers (`HSP`: n of 4 KiB, see "Memory"): a connection takes one with its
  first ClientHello byte (`hsnew`: the next in a circle that is not in use; if 16 in a
  row are, the 16th all the same). It holds the ClientHello while that arrives (any number
  of segments) and then, in its place, the flight. In use means: its owner's slot still
  names it. The slot lets go when the client's ack says it has the flight, so a buffer is
  busy for a round trip, not until 1,024 others have come. A connection whose buffer went
  to another and that needs it (the rest of its ClientHello arrives, or its flight has to
  go out again) is reset. Later a connection takes one again for every record that comes
  in pieces, until the record is whole.
- A ClientHello without an x25519 key share gets a HelloRetryRequest as its whole flight
  (`hrrmsg`), and the connection goes on waiting for a ClientHello: all it keeps is the
  hash of the first one, where its keys will be (the transcript begins with that hash and
  with the request, which is made again from the second ClientHello: same session id,
  same suite). Clients send a ChangeCipherSpec record in front of the second one: while
  we wait for a ClientHello, a record that is not a handshake record is passed over.
- A client we can't serve gets seven bytes and our FIN: a fatal alert, "protocol version"
  if TLS 1.3 is not among the versions it offers (extension 43; a client of TLS 1.2 has
  none), "handshake failure" if our cipher suite is not among its, if x25519 is
  not among its groups (extension 10: then there is nothing to ask for), or if it sent no
  x25519 share after being asked, and "illegal parameter" if its x25519 share makes the
  shared secret all zeros (a point of small order). The alert is its connection's flight
  (kept, sent again if lost), and the connection is closed from our side (`handshake` sets
  F_CLOSED, `tcp.fin` sends the FIN). Before 2026-11-12 such a client got a ServerHello
  with a suite it had not offered, or with its own random as a key share: scanners call
  that intolerance, and it cost a handshake's work for every piece of junk.
  `tools/tlsprobe.sh HOST[:PORT] [CA]` asks what a scanner asks, one thing at a time.
- A segment from further on than we expect is kept (`oohold`) and used as soon as what
  comes before it has arrived (`.reply`). There are n places of 2 KiB for such segments; a
  client's place is picked by its hash and holds one segment, the earliest; two clients
  that share a place overwrite each other, and the loser's client retransmits. This
  matters on a real network: between the user's machine and the server, two segments sent
  back to back (a ClientHello in two parts; Finished and the request) arrive swapped 5-25%
  of the time. Dropping the early one cost a client timeout (+220 ms) on a quarter of all
  fetches; Linux on the same server counts the same swaps (TCPOFOQueue) and hides them the
  same way.
- The one thing sent unasked is a SYN-ACK again. A SYN gets no slot, so the SYNs of late
  are kept on the side (`tnote`: 4 n places, a client's picked by its hash, the frame as
  it came), and a connection made takes its SYN out. A polling loop that has no frame to
  handle goes round the places (`tidle`, 8 a turn); a SYN still there after a quarter
  second goes through `tcp` once more, three times at most, one a tick (1/2048 s) at
  most: a flood of SYNs gets at most 2,048 SYN-ACKs a second and processor on top of its
  own. Without it a lost SYN-ACK costs the client a second,
  and a retransmission timeout of 3 s for the rest of the connection. Only when idle:
  while frames wait in a processor's ring, the client's answer may be one of them (it
  ran on every frame at first, and under load the clients counted thousands of second
  SYN-ACKs for connections they had made long ago: `TcpInErrs` in nstat).
- Port 80 has no keys and no files: every request gets the same response (pack.py:
  where the site is, or its front page), and requests are found by counting line ends
  (`.plain`: two in a row, CRs ignored, end a request; a request body would be read as
  more request lines). At most 4 KiB go at a time while nothing sent before is
  unacknowledged, and any further bytes wait in `oohold` for the ack (`.pbusy`, `.pwait`),
  so a 54-byte duplicate ack never makes port 80 resend more than 4 KiB.

## The connection tables
- Two tables, one per port, so that a connection to port 80 costs 24 bytes (address, port,
  a byte of flags, a byte of time, `C_NXT`, `C_SND`, `C_ACK`, and four spare bytes) and a
  TLS connection 128: the same twenty, then the number of the client's next record
  (`C_ST`), the response in hand (`C_SR`, `C_RS`, `C_AS`: ten bytes), its handshake buffer
  and how much of a record is in it, a byte of flags and the window's shift (`C_FL2`), a
  byte of window (`C_CW`), and 88 bytes of keys (two of 32, of which AES-128 uses 16, with
  their 12 of iv). They fill the table space behind the buffers: the TLS table gets an
  eighth (`TSHARE`), port 80 the rest.
- A connection is in one of two buckets of 16 slots, picked by two words of `prf(addresses,
  ports)`; a new one goes into the bucket with more free slots (`find`), into the first
  of them: a walk that ends with the bucket. (The free slots are counted first; if
  another processor has taken the last one by then, `find` looks again. Until
  2026-11-14 the walk had no end: it went on into the next bucket, where `find` never
  looks for that connection again, or out of the table: from the one for TLS into the
  one for port 80, a slot of 128 bytes laid over five or six of port 80's.
  `tools/racetest.sh 3`.) A slot is free when its address is 0. With two buckets to
  choose from the table fills to 85% before anyone finds both full, and at 92% one in a
  thousand does; one run of 16 slots from one hash, as it was, lost 0.8% of the held
  connections at 70% (`tools/rawc.c` measures it; both match a simulation).
- A slot for port 80 is 24 bytes, and a bucket of 16 (384 bytes) begins on a 64-byte
  cache line: every slot's first 8 bytes lie inside one line, so the `lock cmpxchg` that
  claims it (`tcp.make`) never crosses two lines and locks the bus (as every 16th slot
  did when they were 20 bytes). The slots of the TLS table are 128 bytes and never lie
  so either.
- `prf` is eleven AES rounds (the processor's `aesenc`) over the frame's addresses and
  ports under round keys from rdrand at boot: about 50 cycles, and clients can't aim at
  each other's buckets. Its four words pick the two buckets, make the cookie's secret
  (`W`), and the last one the place of an early segment and the processor. (It was a
  ChaCha20 block: 3,200 cycles, half of what a frame then cost.)
- A SYN gets a SYN-ACK and no slot. Our initial sequence number is a cookie: `W` with the
  low bits of the client's initial sequence number xored into bits 14-31; bits 6-13 are
  `W`'s own (`HINT`); bits 2-5 say by how much the client shifts its window (what its
  SYN's window scale option said, 0 to 14; our SYN-ACK then has the option too, with a
  shift of 0 for ours); bits 0-1 say which of the four segment sizes the client takes.
  The first packet that acknowledges it (the bare ack, or the first data if that ack
  got lost) makes the slot (`ckx`, `.make`). A SYN flood from made-up addresses
  therefore takes no slots at all. (The shift takes four bits because it needs them:
  Linux 7 says 10, Windows 8, macOS 6. So the cookie checks 26 bits where it checked
  30: a made-up ack has to be sent 67 million times, not a thousand million, for one
  slot of 128 bytes that nobody uses. The client's own shift it can lie about as it
  can about its window.)
- A packet for no connection: if its ack carries our HINT bits it belongs to a new
  connection whose first packets were lost (the client will send them again): ignored.
  Otherwise, if it has data or a FIN, it gets a RST (the client is talking to a connection
  we no longer have: after a restart, or it was replaced). 1 in 256 of those match the
  hint by chance and get silence instead. (Without the hint: resets for 1 in 1,000 new
  connections at 3% loss, where netem drops the first five segments as one.) With the
  test knob `ISNTOP` (12 bits forced) 6 bits of the client's sequence number are left
  in the cookie where there were 10: enough for the lossy runs (224,000 handshakes).
- An ack that fits no connection in its slot but is a valid cookie replaces the connection
  (the client reused the port and we never saw the old one end), **but only if a SYN has
  come for that slot since its last fitting ack** (`F_SYN`). Without that condition a
  late copy of a connection's own first ack, which is a valid cookie for ever, started
  the connection over once the client's later acks had moved on: every tenth connection
  under `REORDER=25`, as soon as the handshake was quicker than netem's 5 ms.
- Full: when both buckets are full, the new connection is refused: its SYN gets a RST
  (`.deny`), or if room ran out after the SYN-ACK, its first packet does. Connections that
  are held are not given up for new ones. The exception keeps the table from silting up
  with clients that vanished: a slot whose connection has been quiet for more than `IDLE`
  (64 units of 64 s, 68 minutes; `C_AGE` is a byte of that clock) is taken if
  there is no free one. (It was "the quietest of 16 goes": that pushed out held
  connections from half full on.) `tools/idletest.py` tests the rule (the suite's
  `idle`): a full table, nobody quiet, no room; two minutes on, 200 new connections
  each in a quiet one's place, and none in the place of one that kept talking. A
  connection that gave way and had never been sent anything but its SYN-ACK is made
  again by its next packet: its ack still is a valid cookie.
- A slot is freed by a RST with the expected sequence number, and by a FIN: it gets our
  FIN, and if the client had everything we sent, the slot is free at once (a lost FIN of
  ours means the client's next FIN gets a RST). If the client still lacks something, the
  slot stays (`F_CLOSED`) and answers retransmissions until the client's ack covers our
  FIN.

## How the curve code works
Built for bytes per cycle: one multiplication, one add/subtract, a register machine, and
the curve formulas as data. `tools/ec.py` is the reference: it holds the programs and a
model that asserts every bound.
- Numbers: four limbs of 64 bits, below 2^256, standing for their residue ("weakly
  reduced"); nothing is ever compared with a modulus. `fmul`: the 512-bit product (mulx
  with two carry chains, adcx/adox, a row per limb), then for 2^255 - 19 what is above
  2^256 folded back times 38, for the two Montgomery fields (p and n of P-256) four
  rounds of Montgomery reduction and a subtraction by carry. `fas`: add or subtract, then
  M taken off or put back, once or twice: both corrected values are computed whatever
  the case and one of three is kept (cmov). A field is 104 bytes that `ecinit` builds:
  2^256 - M, M, -1/M mod 2^64 (0 says "fold"), the exponent that inverts.
- `vm` runs programs for 16 registers: in the image 2 bytes an operation, unpacked at
  boot to four dwords (three addresses and the operation). Unpacking them took a ladder
  step from 717 cycles to 529: the decoding had cost more than the additions.
- Our key share, e times the base point: 64 additions on edwards25519 from a table of
  j 16^i B (16 entries a nibble, 98 KiB, made at boot), each entry found by reading all 16
  and masking (`select`). The shared secret, e times the client's point: the Montgomery
  ladder, 256 steps, one conditional swap a step. Both end in a division, which they
  share (`XPRE`, `inv`, `XPOST`), and in `freeze`.
- A signature's r = x(k G): 64 additions on P-256 from a table of (j + 1) 16^i G. Jacobian
  mixed addition can't add a point to itself or to infinity, so the table never holds
  infinity, the sum starts at 2^255 G, and k has the difference taken off first (`KOFFV`;
  ec.py's `sign` asserts that no partial sum can meet the point it is added to, and
  says how unlikely the two exceptions in 2^252 are).
- `stock` makes these 64 at a time: 64 times k G, then two inversions for all of them
  (`binv`, Montgomery's trick: Z of every k G, and every k). `sign` takes one r and one
  1/k and needs four multiplications. The polling loops call `stock` when they have
  nothing else to do and the stock is empty, one k G a call; `sign` does when it finds
  none. So a signature costs 89,000 cycles under full load and next to nothing below it.
- `inv` is a^(m-2) by squaring and multiplying, for all three moduli: 20,000 to 31,000
  cycles, once a handshake (X25519) and twice per 64 (the signatures).
- Our X25519 scalar is clamped and the client's u has its top bit cleared (RFC 7748), so
  every point of small order makes the shared secret all zeros, which `handshake` refuses.
- r and s go out as DER INTEGERs of whatever length they have (`derint`); nothing is
  retried.
- `HOT mask` in front of a routine puts it where none of its jumps crosses a 32-byte
  boundary or ends on one: the routines a handshake spends its time in (the hash, the
  ladder, the register machine, the field arithmetic, the ciphers). On Intel's
  processors from Skylake to Cascade Lake (the server's is one) such a jump is decoded
  again every time, and all that shares its 32 bytes with it. Where the jumps fall
  depends on every byte in front, so two builds differed by 6% in handshakes a second
  there, and by nothing here (Zen 2). The mask says at which of the 32 places behind a
  boundary the routine may begin, and it gets only the padding that takes it to the
  next of them: 35 bytes in all (it was "the next boundary, and n bytes more": 226).
  `tools/jcc.py` finds such jumps (make says so if one of these routines has one) and,
  with `mask`, the mask for a routine that has been changed; of `xdh` and `seal`, which
  are called once a handshake and once a record, the jumps inside loops count.

## Records
`seal` makes a record for some bytes and the byte that says what they are (handshake
messages, application data); or, the other way round (carry set), decrypts what a
client's record held and puts behind it the tag that record should have had, which
`record` compares before it looks at anything. The cipher is AES-128-GCM, the one suite
there is; the key block of a direction is 32 bytes for the key's 16 and 12 of iv.
- The key schedule is made again for every record (`aeskey`: 176 bytes would not fit a
  slot), four counter blocks interleaved across the ten AES rounds (`aes4`, by way of
  `ks64`, 64 bytes of key stream), and GHASH four blocks at a time with one reduction
  (`HTAB` holds H^1..H^4 times x; `gh1` handles single blocks and the powers).
- ChaCha20-Poly1305 was there too until 2026-11-14, for clients that named it first (whose
  processors have no AES): 665 bytes, and every client that has TLS 1.3 has AES-128-GCM
  (RFC 8446 9.1: a MUST; ChaCha20 is a SHOULD).
- Full 64-byte blocks are xored directly in xmm0-xmm3 without bouncing through memory,
  with a 16-byte/byte tail for what remains (a byte at a time, with source and
  destination the same, cost 6,500 cycles of a record of 1,418 bytes).
- What a record costs (`make bench`, Ryzen 7 3800X): 1,418 bytes of a file 1,780 cycles,
  180 bytes 660 (3,900 and 940 before four-block AES and GHASH; 11,600 before
  2026-11-12, night).

## Shortcuts that remain
From k2, where they saved bytes, and from the first version that served files. Ask before
removing the ones about TLS.
- TLS 1.3 only, one suite: TLS_AES_128_GCM_SHA256 (wherever the client names it),
  X25519, ecdsa_secp256r1_sha256; who lacks one of these, or has a session id of more
  than 32 bytes, is told so (an alert) and
  nothing else. Of the ClientHello the cipher suites, the versions, the groups and the
  x25519 key share are looked at (`handshake` walks the extensions; every length on the
  way is bounded by the ClientHello's end, and what is looked at inside an extension by
  that extension's): no name (SNI: a client gets the one site whatever it calls us,
  and its certificate says which names that is good for), no ALPN (we speak HTTP/1.1
  whatever the client
  offers), no signature algorithms (ours is ecdsa_secp256r1_sha256, which every TLS 1.3
  client must have).
- The client's Finished is not checked as such: it carries handshake keys, fails the tag
  check like any forgery, and is passed over. The first request proves the same thing.
- A bad record is passed over, not answered with an alert. No close_notify, no KeyUpdate
  (a client that changes its keys is not understood after that; a connection of ours
  ends before its key has sealed too much), no session tickets, no ChangeCipherSpec for
  middleboxes.
- A client record of more than 4 KB (a request with that many headers and cookies) ends
  the connection.
- A ClientHello is one record. One that comes in two (TLS allows it; no browser does
  it) is taken for a short one, which has no TLS 1.3 in it: "protocol version".
- What a client says it can verify (signature_algorithms) is not looked at, nor its
  legacy_version, nor whether its second ClientHello is its first with a key share. A
  malformed x25519 share is no share: it is asked for one (a HelloRetryRequest), where
  a server is to refuse.
- HTTP: GET and HEAD, the path compared byte for byte with what pack.py made of the file
  names (so `/a%20b.txt`, not `/a b.txt`; a query is cut off; no `..` to resolve: a path
  is in the table or it is not). A request is a record that begins with its request
  line: the line in pieces over several records is not found, and of two requests in
  one record the second is not seen. Of the request's headers two are read, and only
  for a file that has other forms: Accept-Encoding (does its line hold "br" or "gzip",
  and not followed by ";q=0": other weights are not weighed, "*" means nothing) and
  If-None-Match (does its line hold the ETag of the form picked; "*" does not count).
  A header counts if it is in the record that has the request line. No Host (one
  site), no Range, no If-Modified-Since (there are no dates), no `Connection: close`
  (the client has the Content-Length; we close first only after a 405). No Date
  header: there is no clock.
- Two requests at once on 443: the second waits for the client's retransmission timer
  (0.2 s).
- TCP: no SACK and no timestamps (so what is lost is found a segment a round trip, and
  a window past 64 KB opens slowly: "How TCP works here"), no pacing (what an ack lets
  go goes at once), a first timeout of 0.25 s whatever the round trip is (a path
  slower than that gets a segment twice), and the old way (`tcp_send`) for the flight
  and port 80 (capped at 4 KiB unacknowledged on port 80). Our own window is 64 KB,
  unscaled. A segment's data is taken by its sequence number whatever its ack says (RFC
  5961, 5.2 wants the ack inside what we sent as well: a blind sender has less to guess). The IP header's checksum is not looked at: what we use of that header is
  fixed or goes into TCP's checksum, which is.
- Port 80: one response, whatever is asked; a request body is not understood.
- DHCP: an address that could not be renewed is used on (a server that gives up its
  address is no server; we go on asking every 128 s); nobody is asked whether the
  address offered is in use (no ARP probe, no DECLINE), and it is not given back (no
  RELEASE: we don't shut down); T1 is half the lease whatever options 58 and 59 say;
  the number in our messages is one for as long as we are up; the first server to
  offer is taken. While we have no address, ours is 0.0.0.0: a neighbour who asks for
  that gets an answer.
- `keys` writes 20 junk bytes after an IV: the handshake makes both key blocks in `KA` and
  copies them into the slot.
- The handshake's scratch (transcript, key schedule, curve registers) is one per
  processor: one handshake at a time on each, start to finish, inside one call of `tcp`.
- Secrets are not wiped after use: the last handshake's are overwritten by the next, and
  unused nonces wait in the stock. (The private key is in the same memory, which is
  data: read, written, never executed.)
- The first page with data behind the code can be executed (code and what follows share
  it: 4 KiB at most, of constants, among them the key; and where the chain is short, as
  the tests' is, the site's first bytes too. A chain of four certificates fills the page).
