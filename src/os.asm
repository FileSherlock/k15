; os.asm - bare-metal HTTPS server, flat image loaded at 1 MiB (nasm -f bin)
;
; Boot: by src/boot.asm from a disk, or as a multiboot v1 "a.out kludge" kernel (GRUB,
;       `qemu -kernel`). Sets up long mode, its own segments, stack and zeroed memory, and
;       starts the other processors if there are any (up to MAXCPU in all).
; CPU:  64-bit, with rdrand (secrets), AES and PCLMULQDQ (the hash that places connections;
;       AES-GCM), SSE4.1, and BMI2 and ADX (mulx, adcx, adox: the curves).
; NIC:  virtio-net (modern PCI interface), polled. Our IP is baked in (OURIP).
; TCP:  ports 443 (TLS) and 80 (one response for everybody: the page, or where to go); see `tcp`.
; TLS:  1.3, TLS_AES_128_GCM_SHA256, X25519 (asked for
;       with a HelloRetryRequest if need be), ecdsa_secp256r1_sha256.
; HTTP: GET and HEAD for the files of the site the image ends with (tools/pack.py); see `record`.
; Like k2, and unlike k1, this one is meant to be secure: a fresh X25519 key and a fresh ECDSA nonce per
; handshake (rdrand), a real certificate chain, client records are authenticated before
; they are read, and no memory is both written and executed. See docs/internals.md for the
; shortcuts that remain.
;
; Convention: a routine keeps the eight registers of old (pushad/popad: macros here) unless
; it says otherwise; r8-r15 and the SSE registers are scratch, the crypto's to use. All
; buffers live at fixed addresses in zeroed RAM at 2 MiB: one set for each processor (see
; MAXCPU below).
;
; Memory, as the page tables built at boot show it (2 MiB pages): the first 16 MiB as they
; are, and behind them, in one piece, all the other RAM the loader's memory map names,
; wherever it is (also above 4 GiB): the "table space", which the handshake buffers and
; the two connection tables fill. So a slot's address takes 64 bits; everything else is
; below 4 GiB, and 32-bit registers do for it.
;
; The image ends with the site it serves (tools/pack.py: SITE, at the end of this file), so
; it can be long. Up to 1 MiB of it lies between 1 MiB and 2 MiB, where nothing else is. If it
; is longer, everything that is said to be at "2 MiB" and up here is as much further up as
; it takes (LOW: whole pages of 2 MiB): the buffers, the tables, the table space.

%use smartalign                 ; (`align` fills with as few instructions as it takes)
%include "conf.inc"             ; CHAIN_LEN

%ifdef HOST
default abs
BSS     equ 0x200000
%else
default rel
%include "site.inc"         ; SITE_LEN, and where things are in the site
%assign LOW ((0x110000 + SITE_LEN + 0x1FFFFF) >> 21 << 21) - 0x200000 ; (the code ends below 1 MiB + 64 KiB)
BSSN    equ 0x200000 + LOW  ; (BSS as a number)
BSS     equ mb + 0x100000 + LOW ; 2 MiB (said relative to the image, so that the assembler reaches
%endif                      ; what is there relative to the instruction pointer: a byte less)
FR      equ 0               ; the Ethernet frame being handled. At address 0 (old real-mode
                            ; IVT, unused), so `xor reg, reg` loads it and its fields are a
P_ADV   equ FR + 18         ; byte away: (where the IP header had its id) how far its ack moved,
P_IP    equ FR + 26         ;   the client's address,
P_PORTS equ FR + 34         ;   its port and ours (as on the wire),
P_SEQ   equ FR + 38         ;   its sequence number (in host order once `tcp` has started;
                            ;   moved on past bytes we already had)
P_ACK   equ FR + 42         ;   its ack (the same)
P_FL    equ FR + 47         ;   its flags
P_WIN   equ FR + 48         ;   how much it takes beyond its ack (a word, as on the wire)
P_MORE  equ FR + 52         ;   (in place of the urgent pointer) 1: its data is to be
P_EV    equ FR + 53         ;   acknowledged now; and what it means for a response on its
E_ACK   equ 1               ;   way (`tcp.tx`): E_ACK: it wants an ack; E_RTO: something
E_RTO   equ 2               ;   we sent seems lost, E_DUP: or perhaps is, says an ack that
E_DUP   equ 4               ;   repeats; E_SENT: something has gone out that carries our
E_SENT  equ 8               ;   ack; E_NEW: this packet's request has its response
E_NEW   equ 16
%ifndef HOST
VQ      equ 0x400000 + LOW  ; the two rings, 64 KiB apart (enough for queues of 1024)
PML4    equ VQ + 0x20000    ; page tables (built at boot): the top one,
PDPT0   equ PML4 + 0x1000   ;   the one for the first 512 GiB,
PDDEV   equ PML4 + 0x2000   ;   the page directory for the card's structures,
PT0     equ PML4 + 0x3000   ;   the page table for the first 2 MiB,
PDT     equ VQ + 0x30000    ;   and page directories: 8 bytes for each 2 MiB that is mapped
PDT_END equ VQ + 0xF0000    ;   (room for 192 GiB)
%endif
DEVG    equ 505             ; the card's structures are mapped in this GiB: 4 MiB for each kind
                            ; of structure (1 common, 2 notify, 4 device), at 4 MiB * kind
STACK   equ BSS + 0x200000  ; the stack grows down from 4 MiB
; More processors than one: each of the others has its own page tables, which differ from
; the first one's in two places: the 2 MiB at BSS and the 4 KiB at FR are memory of its own
; (a copy of BSS as the first one had it when it had set everything up). So what is at fixed
; addresses there is per processor, with nothing in the code that says so. What they
; share: the tables and buffers of the table space, the transmit ring (TXLOCK), and what
; is said here.
MAXCPU  equ 4
TRAMP   equ 0x8000          ; where the others start, in real mode (`tramp` is copied there)
TXLOCK  equ 0x9F00          ; held from `txbuf` to `txgo` (not in the page of TRAMP: that one
NCPUM   equ 0x9F04          ; is code); how many processors take frames, less 1 (a power of two, less 1)
KST     equ 0x9F08          ; reset knock: 1 after the first port (development builds)
TXCNT   equ 0x9F20          ; how many frames have ever been queued for sending (a qword: `txgo`)
%ifndef HOST
APMEM   equ 0x900000 + LOW  ; for each other processor 32 KiB: four page tables, its page 0,
APBSS   equ 0xA00000 + LOW  ; and 2 MiB: its BSS
%endif
TR      equ BSS + 0x20000   ; handshake transcript
VB      equ BSS + 0x30000   ; what a client record should look like (for its tag)
SB      equ BSS + 0x40000   ; seal scratch: what the tag is made over
OB      equ BSS + 0x50000   ; our answer to one packet (OBMAX bytes)
HB      equ BSS + 0x0C900   ; HMAC buffer (key pad | message)
INFO    equ HB + 64         ; HKDF info is built right where HMAC wants its message
SH      equ BSS + 0x0CB00   ; SHA-256: the state of the hash being made,
TSH     equ SH + 32         ;   the state of the handshake transcript's hash (see `thash`),
PADB    equ SH + 64         ;   and the end of a message with its padding (two blocks)
KS      equ BSS + 0x0CD80   ; a block of key stream (64-byte aligned)
RK      equ BSS + 0x0CE00   ; AES-128: the eleven round keys of the record at hand,
NB      equ RK + 176        ;   its counter block (nonce | counter),
TAGM    equ NB + 16         ;   what its tag is masked with,
BSWAPM  equ TAGM + 16       ;   how pshufb reverses 16 bytes (made at boot)
HTAB    equ BSWAPM + 16     ; GHASH: H^1 .. H^4 (each times x), then their halves xored
SLOTS   equ BSS + 0x0D500   ; key schedule values, 8 x 32 bytes, addressed from ebp
KH      equ BSS + 0x0D600   ; handshake traffic key | iv
CVB     equ BSS + 0x0D680   ; CertificateVerify content to be signed (+ room for padding)
KT      equ BSS + 0x0D800   ; SHA-256 round constants (computed at boot), 64 dwords; 512-aligned
HT      equ KT + 0x104      ; SHA-256 initial hash (computed at boot), 8 dwords (+ 56 junk)
REGS    equ BSS + 0x0E400   ; the curve machine's 16 registers of four limbs (not in the image's
                            ; page: TCG takes a slow path for every write to a page with code)
E       equ REGS + 0x200    ; our X25519 secret (32 bytes), then
KD      equ E + 64          ; an ECDSA nonce as the table is asked for it (see `stock`),
KOFFV   equ KD + 32         ; and what it has lost on the way there (made at boot)
NPOOL   equ 64              ; ECDSA nonces are made so many at a time (`stock`):
POOLR   equ BSS + 0x10000   ;   r = x(k G) of each,
POOLK   equ POOLR + NPOOL * 32 ; R^2 / k,
POOLZ   equ POOLK + NPOOL * 32 ; and while they are made: Z of k G,
POOLP   equ POOLZ + NPOOL * 32 ; and the partial products of an inversion (`binv`)
XP      equ BSS + 0x12000   ; the curve programs as `vm` runs them (unpacked at boot)
F25519  equ REGS + 0x300    ; the three fields (see `ecinit`): 2^255 - 19,
FP256   equ F25519 + FSIZE  ;   p of P-256
FN256   equ FP256 + FSIZE   ;   and its n. A field is 2^256 - M, then
F_M     equ 32              ;   M,
F_INV   equ 64              ;   -1/M mod 2^64 (0: not a Montgomery field)
F_EXP   equ 72              ;   and the exponent that inverts
FSIZE   equ 104
TABE    equ BSS + 0x100000  ; the multiples of edwards25519's base point that `xdh` adds up,
TABP    equ BSS + 0x120000  ; and those of P-256's that `sign` does (both made at boot)
VST     equ BSS + 0x0F000   ; virtio-net driver state:
MAC     equ VST + 4         ;   our MAC address (6 bytes, from the device)
Q0      equ VST + 16        ;   receive queue: desc, avail, used (addresses), size - 1, used
Q_SEEN  equ 16              ;     entries seen (dwords), and where to notify the device about
Q_NOTE  equ 24              ;     it (a qword)
Q1      equ Q0 + 32         ;   transmit queue, the same
VCAP    equ VST + 88        ;   where the device's structures are, by kind (qwords at 8 * kind)
VMUL    equ VST + 136       ;   (the dword read after each, at 8 * kind: for notify, its offset multiplier)
NV      equ BSS + 0x0F200
RXLEN   equ NV              ; the length of the frame in FR
HSNEXT  equ NV + 4          ; handshake buffers looked at so far (`hsnew`)
NOW     equ NV + 8          ; when the frame came, in units of 64 s (a byte: see C_AGE)
HSMASK  equ NV + 56         ; n - 1 (see TABV)
OOBASE  equ NV + 60         ; where the places for early segments are
TXK     equ NV + 12         ; 1: frames are queued that the device has not been told about
TT      equ NV + 16         ; the table of TLS connections: address (a qword), number of buckets
PT      equ NV + 32         ; the table of connections to port 80: the same
TPOS    equ NV + 48         ; how far the transcript has been hashed (see `thash`)
SUITE   equ NV + 52         ; 0 if the ClientHello names our cipher suite, else -1
POOLN   equ NV + 64         ; how many of the nonces made are left
POOLFILL equ NV + 68        ; how far the next ones are (32 for each k G there is)
CPUN    equ NV + 72         ; which processor this is (0: the one that booted)
CLAIMQ  equ NV + 80         ; the first 8 bytes of the slot `find` chose for a new connection
BORN    equ NV + 88         ; when we booted, in ticks of 1/2048 s (make LIFE=n)
TMMASK  equ NV + 92         ; SYNs that may be answered again (`tnote`): how many places, less 1,
TMF     equ NV + 96         ;   where the SYNs are (128 bytes each: tries left, length, frame),
TMT     equ NV + 100        ;   and where the times they came are (a dword each; 0: none)
THAND   equ NV + 104        ;   how far this processor has got round them (`tidle`),
TNOW    equ NV + 108        ;   the time, in ticks of 1/2048 s (`clock`),
TLAST   equ NV + 112        ;   when a SYN was last answered again,
TTRY    equ NV + 116        ;   and how often the SYN in hand may be yet (0: it is the client's)
RBASE   equ NV + 120        ; the processors' rings of frames (`drain`): where the first one is,
RSTEP   equ NV + 124        ;   how far apart they are,
MYRING  equ NV + 132        ;   and where this processor's is
TXM     equ NV + 136        ; the response in hand (`geom`): the bytes of a segment of it,
TXP     equ NV + 140        ;   how many of them are the response's (the rest is the record's),
TXL     equ NV + 144        ;   the response's length,
TXN     equ NV + 148        ;   in how many records it goes,
TXBLOB  equ NV + 152        ;   where it is,
TXEND   equ NV + 156        ;   the sequence number behind its last byte,
TXLIM   equ NV + 160        ;   and the one up to which the client takes it for now
SEGP    equ NV + 164        ; where the data of the segment in hand began (`tcp.busyc`)
TQB     equ NV + 172        ; this processor's connections that wait for an ack (`tarm`): where
TQH     equ NV + 176        ;   the queue is, how many have been taken out,
TQT     equ NV + 180        ;   how many put in,
TQTRY   equ NV + 184        ;   and (a byte) how often the one in hand has been sent again in vain
TSO     equ NV + 188        ; not 0: the card cuts a frame of ours into segments and sums them
BIGN    equ NV + 192        ; so many such frames this processor has made (`txbig`),
TSCM    equ NV + 200        ; 2^64 / cycles per tick of 1/2048 s (calibrated at boot)
RLAST   equ NV + 208        ; what the processor's random number generator said last (`rand`)
BIGQ    equ BSS + 0x0F100   ;   and for each of its buffers a count of frames queued (TXCNT)
                            ;   that is past the one it last held (qwords)
HKS     equ BSS + 0x0F400   ; the eleven round keys of `prf`, made at boot
HKO     equ HKS + 176       ;   and its output
KA      equ BSS + 0x0F300   ; application keys as `keys` makes them (2 x 44 bytes + 20 of junk)
%ifndef HOST
RXB     equ 0x500000 + LOW  ; receive buffers, 2 KiB each (12-byte virtio header + frame)
TXB     equ 0x700000 + LOW  ; transmit buffers, the same
BIGB    equ 0x1000000 + LOW ; and for each processor BIGS buffers of 64 KiB, for frames that
%endif                      ; the card cuts into segments (`txbig`, `sendrun`)
%ifndef BIGSH
%define BIGSH 3             ; (make BIGSH=n, for tests: 2^n of them)
%endif
BIGS    equ 1 << BIGSH
BIGPAY  equ 0xFF00          ; such a frame holds so many bytes of segments at most
%ifndef OURIP
%define OURIP 0x0F02000A    ; 10.0.2.15, as it is on the wire (make IP=a.b.c.d)
%endif
%ifdef ISNTOP
%ifndef ISNBITS
%define ISNBITS 12
%endif
ISNLOW  equ (1 << (32 - ISNBITS)) - 1
%endif
%ifndef KEYLIFE
%define KEYLIFE 24          ; (make KEYLIFE=n, for tests: a connection's key seals 2^n records)
%endif
%ifndef WIN
%define WIN 10              ; so many segments of a response may be on their way to begin with (make WIN=n)
%endif
OO_TAG  equ 0               ; A segment that came early (see `oohold`): whose it is: a word of
OO_SEQ  equ 4               ;   the client's hash (0: nobody's), its sequence number,
OO_LEN  equ 8               ;   length
OO_FIN  equ 12              ;   and whether it had a FIN
OO_DATA equ 16
T_TIME  equ 38              ; A connection that waits for an ack (`tarm`) is the first 64 bytes
T_ACK   equ 42              ;   of a frame of its client, and in place of its sequence number,
T_TRY   equ 46              ;   ack and header length: since when, for which ack, the how
                            ;   manieth time
%ifndef HOST
TABV    equ (BIGB + (MAXCPU * BIGS << 16) + 0x1FFFFF) & ~0x1FFFFF ; The table space: from 18 MiB up (see the top of this file). Boot
                            ; divides it: n handshake buffers, n places of 2 KiB for early
                            ; segments (n a power of two: about 1/32 and 1/64 of it), 4 n
                            ; SYNs of late (`tnote`), a ring of n frames and a queue of 4 n
                            ; waiting connections for each processor (`drain`, `tarm`), then
                            ; the two connection tables: the one for TLS, the one for port 80.
HSP     equ TABV            ; Handshake buffers (see `hsnew`): each holds
%endif
%assign HS_SHIFT 12
%rep 4
%if CHAIN_LEN + 512 > (1 << HS_SHIFT) - 16
%assign HS_SHIFT HS_SHIFT + 1
%endif
%endrep
%if CHAIN_LEN + 512 > (1 << HS_SHIFT) - 16
%error "the certificate chain is too long for a handshake buffer"
%endif
%if CHAIN_LEN + 5120 > 0x10000  ; (the transcript: the chain, and up to 4,883 bytes of the rest)
%error "the certificate chain is too long for the transcript's 64 KiB"
%endif
HS_OWNER equ 0              ;   the connection it belongs to (its slot: a qword),
HS_FLEN equ 8               ;   the length of our flight (0: not sent yet),
HS_CH   equ 16              ;   and the ClientHello record as far as it has arrived (up to
HS_FL   equ HS_CH           ;   CHMAX), then, in its place, our flight as it was sent
CHMAX   equ (1 << 12) - 16
BUCKET  equ 16              ; slots in a bucket (see `find`)
%ifndef TSHARE
%define TSHARE 3            ; the TLS table gets 1/2^TSHARE of that memory (make TSHARE=n)
%endif
%ifndef IDLE
%define IDLE 64             ; a connection that has been quiet for longer than this (in units of
%endif                      ; 64 s: 68 minutes) may be replaced when a new one finds no room
HINT    equ 0x3FC0          ; see the cookie in `tcp`
OBMAX   equ 0x40000         ; room for one answer at OB

S_Z     equ -128            ; slot offsets from ebp = SLOTS + 128
S_EH    equ -96
S_ES    equ -64
S_D     equ -32
S_HS    equ 0
S_TS    equ 32
S_TH    equ 64
S_D1    equ 96              ; (constant: what the handshake secret is extracted with)

; A connection's slot. One for port 80 is the first PSLOT bytes; one for TLS has it all.
C_IP    equ 0               ; the client's address (0: the slot is free)
C_PORT  equ 4               ; and port (a word)
C_FLG   equ 6               ; a byte: F_CLOSED, F_DEFER, which segment size the client takes
F_CLOSED equ 1              ;   (bits 2-3: MSSTAB), F_SYN; on port 80 whether a line has just
F_DEFER equ 2               ;   ended (bit 7); on 443, in bits 5-6, how many acks in a row have
F_DEFER_BIT equ 1           ;   said the same (F_DUP3: three, and we have sent again what they
F_SYN   equ 16              ;   ask for). F_CLOSED: FINs exchanged, but the client lacks
F_DUP   equ 0x20            ;   something. F_DEFER: its data is not acknowledged before it has
F_DUP3  equ 0x60            ;   our answer. F_SYN: a SYN has come for it since its last ack
                            ;   that fitted
C_AGE   equ 7               ; when its last packet came (NOW; a byte, so after 256 units of
                            ; silence a connection looks young again for a while)
C_NXT   equ 8               ; next sequence number we expect from the client
C_SND   equ 12              ; our next sequence number
C_ACK   equ 16              ; the client's last ack
PSLOT   equ 20
C_ST    equ 20              ; 0 = waiting for the ClientHello, else 1 + the number of the
                            ; client's next record (of those under its application key)
C_SR    equ 24              ; the response in hand (see `tcp.tx`): the number of its first record,
C_RS    equ 28              ;   the sequence number of its first byte (before the first
                            ;   response: of the byte after our flight),
C_AS    equ 32              ;   and which it is (a word: its number in the site; bit 15: only
                            ;   its head)
C_HS    equ 34              ; its handshake buffer + 1 (a word; if that still says so itself)
C_LEN   equ 36              ; a word: so many bytes of a record that came in pieces are in that buffer
C_FL2   equ 38              ; a byte: F_FIN, F_ARMED, and in the top four bits by how many
F_FIN   equ 2               ;   bits the client's window is to be shifted (what its SYN said:
F_ARMED equ 4               ;   window scaling). F_FIN: our FIN has gone out. F_ARMED: it is
                            ;   in the queue of `tarm`.
F_HRR   equ 8               ;   F_HRR (before the handshake): we have asked for a second
F_CA    equ 8               ;   ClientHello; F_CA (after it): something was lost on this
                            ;   connection once.
C_CW    equ 39              ; a byte: so many segments of a response may be on their way (`tcp.tx`)
C_KIV   equ 40              ; our application key | iv (44 bytes), then the client's
TSLOT   equ 128

; What 32-bit code calls pushad and popad: the seven registers of old besides rsp (so the
; one a routine returns is at [rsp+48] for eax, [rsp+24] for ebx, [rsp+16] for ebp,
; [rsp] for edi)
%macro pushad 0
        push rax
        push rcx
        push rdx
        push rbx
        push rbp
        push rsi
        push rdi
%endmacro
%macro popad 0
        pop rdi
        pop rsi
        pop rbp
        pop rbx
        pop rdx
        pop rcx
        pop rax
%endmacro
; HOT mask: the routine that follows begins where none of its jumps crosses a 32-byte
; boundary or ends on one. The routines a handshake spends its time in are placed so: on
; Intel's processors from Skylake to Cascade Lake (the cloud server's is one) such a jump
; is decoded again every time it is met, and so is all that shares its 32 bytes. Without
; this, how fast a handshake is there depends on how many bytes of code happen to lie in
; front (6% between two builds, measured). Bit k of the mask says that the routine may
; begin k bytes behind a boundary; it gets as few bytes of padding as take it to such a
; place (35 bytes in all; it was the next boundary and some more for each: 226 bytes).
; `tools/jcc.py build/os.lst mask ROUTINE` says the mask, and the build says when
; a routine that was changed needs a new one. (Of `xdh` and `seal`, which are called
; once a handshake and once a record, the jumps inside loops count: ROUTINE:loops.)
%macro HOT 1
%assign %%k 32
%define %%pad 0
%rep 32
%assign %%k %%k - 1
%xdefine %%pad ((((%1) >> ((($ - $$) + %%k) & 31)) & 1) ? %%k : %%pad)
%endrep
        times %%pad nop
%endmacro
; Development builds (make DEBUG=1) count things in DBG and show six counters, four hex
; digits each, in place of the end of the page on port 80: `count n` adds one to counter n.
; 0: frames with a bad length or checksum, 1: cycles per frame handled (an average, made when
; shown), 2: connections refused for lack of room and frames lost to a full ring (`drain`),
; 3: segments that came early, 4: resends, 5: RSTs sent. With DEBUG=2, 3 and 5 are instead
; what tells how busy this processor is: the turns of its polling loop that found nothing to
; do, in units of 4,096, and the time, in units of 2^24 cycles. Two fetches give a rate, and
; a processor with nothing to do gives the rate that means idle (bench/busy.sh does that).
DBG     equ BSS + 0x0F500
%macro count 1
%ifdef DEBUG
        inc dword [DBG + 4 * %1]
%endif
%endmacro
%ifndef DEBUG
%define tcpd tcp            ; (the polling loops call `tcp` through what counts its cycles)
%endif
; WXGATE label (make WXTEST=6 or 7, for tools/wxtest.sh): what a table of interrupt handlers
; at address 0 would have for an invalid instruction, at 16 times its number: a gate to
; `label`, which is in our code. Then such an instruction. A processor that has no such
; table can't go on from there: the machine's end. (See `GDT`.)
%macro WXGATE 1
        mov dword [abs 6*16], ((0x100000 + (%1 - mb)) & 0xFFFF) | 8 << 16
        mov dword [abs 6*16+4], 0x8E00 | ((0x100000 + (%1 - mb)) >> 16 << 16)
        and qword [abs 6*16+8], 0
        ud2
%endmacro

; (make RACE=3 is in `find`.)
; RACEWAIT age (make RACE=n IDLE=1, for tools/racetest.py): `tqrun`, with a connection in
; hand that has been quiet for long enough to be taken (%1: its C_AGE as it was), stops
; there for up to 30 s, or until another processor has made the slot its own and has just
; taken that connection's first request: the moment at which going on as if the slot were
; still ours shows. RACE=1: before `tqrun` has said "in use" (`hold`), 2: after.
%macro RACEWAIT 1
        mov al, [NOW]
        sub al, %1
        cmp al, IDLE
        jbe %%go
        call clock
        mov r10d, eax
        xor r11d, r11d
%%w:    call bdrain
        pause
        call clock
        sub eax, r10d
        cmp eax, 30 * 2048
        jae %%go
        cmp dword [rbp+C_ST], 2
        jae %%two
        or r11d, -1             ; (below 2: it is another's, before its first request)
        jmp %%w
%%two:  test r11d, r11d
        jz %%w
%%go:
%endmacro

%ifdef HOST
BITS 64
        section .text align=32
        global sha256, hmac, expand, seal, shaconst, echost, xdh, sign
        global E, REGS
%else
        org 0x100000
BITS 32
mb:     dd 0x1BADB002, 0x00010002, -(0x1BADB002 + 0x00010002)
        dd mb, mb, 0, 0, start

; ----------------------------------------------------------------------------
start:                          ; Entered in 32-bit protected mode by whoever loaded us at 1 MiB
        cli                     ; (boot.asm, GRUB's or QEMU's multiboot), with ebx = what a
        cld                     ; multiboot loader tells its kernel: the memory map is what we
        lidt [GDT]              ; need of it. Nothing else is assumed: no interrupt handlers
        mov edi, BSSN           ; (a table of them of length nothing: see `GDT`), our own page
        mov ecx, (TABV - BSSN) / 4 ; tables, segments and stack, and memory we zero ourselves:
        xor eax, eax            ; first all that is ours below the table space. The top table
        rep stosd               ; and the next one have one entry each for now (the rest is
        mov dword [PML4], PDPT0 + 3 ; filled in from long mode), and the first page directory
                                ; maps the first 16 MiB as they are
        mov dword [PDPT0], PDT + 3
        mov dword [PDPT0+DEVG*8], PDDEV + 3
        mov byte [PDPT0+DEVG*8+7], 0x80 ; (the card's registers: not to be executed)
        ; Who may do what. Only our code is executed, and it is not written (CR0.WP, once
        ; all is set up); nor is the site. Everything else is data: written, and never
        ; executed. So nothing a packet can put into memory can be run, and nothing that
        ; runs can be changed. The first 2 MiB are in pages of 4 KiB for that: low memory
        ; (data, but for the page where the other processors start), then the image: the
        ; pages with code, and behind them what is only read.
        mov dword [PDT], PT0 + 3
        mov edi, PT0
        xor ecx, ecx
.pg:    mov eax, ecx
        shl eax, 12
        mov al, 3               ; present, to be written,
        mov edx, 0x80000000     ; not to be executed
        cmp ecx, TRAMP >> 12
        je .x
        test ch, ch
        jz .put
        mov al, 1               ; the image: not to be written,
        cmp ecx, CODEPG
        jae .put                ; and behind its code not to be executed
.x:     mov al, 1
        xor edx, edx
.put:   stosd
        xchg eax, edx
        stosd
        inc ecx
        cmp ch, 2
        jb .pg
        mov edi, PDT + 8        ; From 2 MiB up, pages of 2 MiB: more of the image if it is
        mov eax, 0x200081       ; long (only read), then, from BSS on, data; none of it to be
.low:   cmp eax, BSSN           ; executed
        jb .ro
        or al, 2
.ro:    stosd
        mov byte [edi+3], 0x80
        scasd
        add eax, 0x200000
        cmp eax, TABV
        jb .low
        mov eax, cr4
        or eax, 0x220           ; PAE (long mode's kind of paging); the SSE registers may be used
        mov cr4, eax
        mov eax, PML4
        mov cr3, eax
        mov ecx, 0xC0000080
        rdmsr
        or ah, 9                ; long mode, once paging is on; and pages can be barred from
        wrmsr                   ; execution
        mov eax, cr0
        or eax, 0x80000000
        mov cr0, eax
        lgdt [GDTR]
        jmp 8:.long
BITS 64
.long:  mov esp, STACK
        push 16
        pop rax
        mov ds, eax
        mov es, eax
        mov ss, eax
        mov ebx, ebx            ; (the upper halves are not ours to rely on after the switch)
        mov edi, PDT + (TABV >> 21) * 8
        ; The table space: every 2 MiB of RAM from 16 MiB up that the memory map calls
        ; available, one after the other (rdi = the next page directory entry).
        xor ecx, ecx
        test byte [rbx], 0x40   ; (no memory map: no tables)
        jz .mapped
        mov ecx, [rbx+44]
        mov ebx, [rbx+48]
        add ecx, ebx            ; its end
.ent:   cmp ebx, ecx
        jae .mapped
        cmp byte [rbx+20], 1    ; RAM that is ours to use: from rax up to r8
        jne .nent
        mov rax, [rbx+4]
        mov r8, [rbx+12]
        add r8, rax
        mov edx, TABV
        cmp rax, rdx
        jae .piece
        mov rax, rdx
.piece: add rax, 0x1FFFFF       ; in whole pages, not to be executed
        and rax, -0x200000
        and r8, -0x200000
        mov al, 0x83
        bts rax, 63
        bts r8, 63
.page:  cmp rax, r8
        jae .nent
        cmp edi, PDT_END
        jae .nent
        stosq
        add rax, 0x200000
        jmp .page
.nent:  mov eax, [rbx]          ; (an entry says how long it is, after that length)
        lea ebx, [rbx+rax+4]
        jmp .ent
.mapped:
        mov ebx, edi
        mov edi, PDPT0          ; the page directories, one for each GiB
        mov eax, PDT + 3
        mov ecx, (PDT_END - PDT) >> 12
.gib:   stosq
        add eax, 0x1000
        loop .gib
        sub ebx, PDT + (TABV >> 21) * 8
        shl rbx, 18             ; rbx = the size of the table space
        mov rcx, rbx
        shr rcx, 3
        xor eax, eax
        mov edi, TABV
        rep stosq               ; which starts as zero too
        mov rax, rbx            ; n, for the handshake buffers and the early segments: what
        shr rax, 17             ; takes up 1/32 and 1/64 of it, or the power of two below
        bsr rcx, rax
        cmp cl, 15              ; (C_HS is a word)
        jbe .hn
        mov cl, 15
.hn:    xor eax, eax
        inc eax
        shl eax, cl
        lea edx, [rax-1]
        mov [HSMASK], edx
        mov edx, eax
        shl edx, HS_SHIFT
        add edx, HSP
        mov [OOBASE], edx
        lea ecx, [rax*4-1]      ; 4 n SYNs that may be answered again: 128 bytes each, and
        mov [TMMASK], ecx       ; a dword for when
        shl eax, 11
        add eax, edx
        mov [TMF], eax
        inc ecx
        shl ecx, 7
        add eax, ecx
        mov [TMT], eax
        shr ecx, 5
        add eax, ecx
        mov [RBASE], eax        ; for each processor a ring of frames (n frames, and 2 KiB in
        mov [MYRING], eax       ; front for how far it is) and behind it a queue of 4 n
        shl ecx, 4              ; connections that wait for an ack (64 bytes each: `tarm`)
        lea edx, [rcx*8+2048]
        add ecx, edx
        add edx, eax
        mov [TQB], edx
        mov [RSTEP], ecx
        shl ecx, 2              ; (MAXCPU of them)
        add eax, ecx            ; rax = where the tables start
        lea rbx, [rbx+TABV]
        sub rbx, rax            ; what they have:
        mov edi, TT
        mov [rdi], rax
        mov rax, rbx            ; for TLS a share of that memory,
        shr rax, TSHARE + 11    ; in buckets (of BUCKET * TSLOT = 2048 bytes)
%ifdef CAP                      ; (make CAP=n: no more than n slots in each table, to test full ones)
        cmp rax, CAP / BUCKET
        jbe .tc
        mov eax, CAP / BUCKET
.tc:
%endif
        mov [rdi+8], eax
        shl rax, 11
        sub rbx, rax            ; and for port 80 the rest
        add rax, [rdi]
        mov [rdi+16], rax
        xchg rax, rbx
        xor edx, edx
        mov ecx, BUCKET * PSLOT
        div rcx
%ifdef CAP
        cmp rax, CAP / BUCKET
        jbe .pc
        mov eax, CAP / BUCKET
.pc:
%endif
        mov [rdi+24], eax
        fninit
%endif
; shaconst: SHA-256 constants from their definition: KT[i] = frac(cbrt(prime i)) * 2^32
; (Newton's method, so only exactly rounded x87 ops), HT[i] = frac(sqrt(prime i)) * 2^32.
; Inlined into the boot path; a function only in the host test build.
%ifdef HOST
shaconst:
        pushad
%endif
        mov edi, KT-4           ; the loop also counts 1 as a prime: its entry lands at KT-4
        push 3
        xor ebx, ebx            ; prime candidate
.np:    inc ebx
        mov ecx, ebx
.td:    dec ecx                 ; trial division by ebx-1 .. 2
        cmp ecx, 1
        jbe .pr
        mov eax, ebx
        cdq
        div ecx
        test edx, edx
        jnz .td
        jmp .np
.pr:    push rbx
        fild dword [rsp]        ; p
        fld st0                 ; y = p
        mov cl, 40
.nw:    fld st0
        fmul st0, st0
        fdivr st0, st2          ; p / y^2
        fadd st0, st1
        faddp st1, st0
        fidiv dword [rsp+8]     ; y = (2y + p/y^2) / 3
        loop .nw
        fmul dword [TWO32]
        fisttp qword [rdi]      ; low dword = fraction bits (the next entry overwrites the rest)
        fsqrt                   ; (only the first 8 matter; the rest land in junk space)
        fmul dword [TWO32]
        fisttp qword [rdi+HT-KT]
        pop rax
        scasd
        bt edi, 8               ; KT is 512-aligned: bit 8 first sets at KT+256
        jnc .np
        pop rax
%ifdef HOST
        popad
        ret
%else
        call ecinit             ; what the curves need (fields, constants, tables)
        mov ebp, SLOTS + 128    ; and what every key schedule starts with: SHA256(""), the
        xor ecx, ecx            ; early secret of no PSK, and what the handshake secret is
        lea edi, [rbp+S_EH]     ; derived from
        call sha256
        lea ebx, [rbp+S_Z]
        mov esi, ebx
        mov cl, 32
        lea edi, [rbp+S_ES]
        call hmac
        mov ebx, edi
        mov esi, L_DER
        lea edx, [rbp+S_EH]
        lea edi, [rbp+S_D1]
        call expand

        ; virtio-net, modern interface (virtio 1.0; what a cloud's 1AF4:1041 speaks, and a
        ; transitional 1AF4:1000 too): the registers are memory, found through the device's
        ; PCI capabilities, wherever the BIOS put them (each kind of structure is mapped
        ; into a place of its own in our address space). Two queues (0 receive, 1 transmit);
        ; descriptor i always points at buffer i.
        mov ebx, 0x80000000     ; PCI configuration address: bus 0, device 0, function 0
.pci:   xor eax, eax
        call pcird
        cmp ax, 0x1AF4
        jne .next
        shr eax, 16
        cmp ax, 0x1041
        je .dev
        cmp ax, 0x1000
        je .dev
.next:  add ebx, 0x100          ; next function, device, bus (the card sits behind a bridge)
        jmp .pci
.dev:   push 4
        pop rax
        call pcird
        or al, 7                ; command: I/O, memory, bus master
        out dx, ax
        push 0x34
        pop rax
        call pcird
        xchg eax, esi           ; capability list
.cap:   and esi, 0xFC
        jz .caps
        mov eax, esi
        call pcird              ; id | next | length | type (1 common, 2 notify, 4 device)
        mov ecx, eax
        cmp al, 9               ; vendor-specific: a virtio structure
        jne .nxt
        shr eax, 24
        cmp al, 4
        ja .nxt
        lea rbp, [VCAP+rax*8]
        cmp qword [rbp], 0      ; the first of each kind counts
        jne .nxt
        xchg eax, edi           ; edi = the kind
        lea eax, [rsi+4]
        call pcird
        movzx eax, al           ; which BAR
        lea r8d, [rax*4+0x10]
        mov eax, r8d
        call pcird
        mov r9d, eax
        and r9d, -16            ; r9 = where it is,
        test al, 4
        jz .bar
        lea eax, [r8+4]         ; with an upper half in the next register if it is a 64-bit one
        call pcird
        shl rax, 32
        or r9, rax
.bar:   lea eax, [rsi+8]
        call pcird              ; and the structure's offset inside it
        add r9, rax
        shl edi, 4              ; map the 2 MiB page it is in, and the next
        mov rax, r9
        and rax, -(1 << 21)
        mov al, 0x9B            ; (present, writable, 2 MiB, not cached)
        mov [PDDEV+rdi], rax
        add rax, 1 << 21
        mov [PDDEV+rdi+8], rax
        and r9d, (1 << 21) - 1
        shl edi, 18
        add r9, rdi
        mov eax, DEVG
        shl rax, 30
        add rax, r9
        mov [rbp], rax
        lea eax, [rsi+16]
        call pcird              ; (notify: the multiplier for queue_notify_off)
        mov [rbp+VMUL-VCAP], eax
.nxt:   movzx esi, ch
        jmp .cap
.caps:  mov rbp, [VCAP+8]       ; common configuration
        mov byte [rbp+20], 0    ; status 0: reset
        mov byte [rbp+20], 3    ; ACKNOWLEDGE | DRIVER
        xor eax, eax
        inc eax
        mov [rbp+8], eax        ; features, word 1: VERSION_1 (bit 32), nothing else:
        mov [rbp+12], eax       ; frames behind a 12-byte header
        dec eax
        mov [rbp+8], eax        ; Word 0: that the card sums what we send (CSUM, bit 0) and
        mov [rbp], eax          ; cuts a frame of up to 64 KiB into segments (HOST_TSO4, bit
%ifndef NOTSO                   ; 11), if it offers both: then a response goes many records
        mov eax, [rbp+4]        ; to a frame (`sendrun`). (make NOTSO=1: never.)
        and eax, 0x801
        cmp eax, 0x801
        je .tso
        xor eax, eax
.tso:
%endif
        mov [rbp+12], eax
        mov [TSO], eax
        mov byte [rbp+20], 11   ; FEATURES_OK
        mov rsi, [VCAP+32]      ; device configuration: the MAC comes first
        mov edi, MAC
        movsd
        movsw
        xor ebx, ebx            ; queue
.q:     mov [rbp+22], bx        ; select it
        movzx ecx, word [rbp+24] ; its size N (a power of two)
        cmp ecx, 1024
        jbe .n
        mov ecx, 1024           ; (what our ring area holds)
        mov [rbp+24], cx
.n:     mov esi, ebx
        shl esi, 5
        add esi, Q0             ; our notes on this queue
        mov edi, ebx
        shl edi, 16
        add edi, VQ
        mov [rsi], edi          ; descriptors: 16 N bytes
        mov [rbp+32], edi
        lea eax, [rcx-1]
        mov [rsi+12], eax
        mov eax, ecx
        shl eax, 4
        add eax, edi
        mov [rsi+4], eax        ; available ring: flags, idx, N entries
        mov [rbp+40], eax
        mov byte [rax], 1       ; (its flags: no interrupts. We look for ourselves, and
                                ; nobody would take them)
        lea eax, [rax+rcx*2+6+4095]
        and eax, -4096
        mov [rsi+8], eax        ; used ring: flags, idx, N x (id, length)
        mov [rbp+48], eax
        push rcx
        imul eax, ebx, TXB - RXB
        add eax, RXB
        mov edx, ebx
        xor dl, 1
        shl edx, 1              ; receive buffers are for the device to write (flag 2)
.desc:  mov [rdi], eax
        mov dword [rdi+8], 2048
        mov [rdi+12], edx
        add eax, 2048
        add edi, 16
        loop .desc
        pop rcx
        test ebx, ebx
        jnz .en
        mov edi, [rsi+4]        ; receive: hand all N buffers to the device
        mov [rdi+2], cx
        xor eax, eax
.av:    mov [rdi+4+rax*2], ax
        inc eax
        cmp eax, ecx
        jb .av
.en:    movzx eax, word [rbp+30] ; where to notify the device about this queue
        imul eax, [VMUL+16]
        add rax, [VCAP+16]
        mov [rsi+Q_NOTE], rax
        mov word [rbp+28], 1    ; enable
        inc ebx
        cmp bl, 2
        jb .q
        mov byte [rbp+20], 15   ; DRIVER_OK
        mov rdx, [Q0+Q_NOTE]
        mov word [rdx], 0       ; notify queue 0: there are buffers

        mov edi, HKS            ; the round keys for `prf`
        push 22
        pop rcx
        call rand

        mov ecx, 1 << 26        ; Calibrate the clock against timer 2 (1,193,182 Hz):
        mov bl, 2               ; 9,322 ticks are 1/128 s, or 16 of our ticks of 1/2048 s
.cal:   in al, 0x61             ; (two runs, the shorter counts: the host may interrupt one)
        and al, 0xFC
        or al, 1
        out 0x61, al
        mov al, 0xB0
        out 0x43, al
        mov ax, 9322
        out 0x42, al
        mov al, ah
        out 0x42, al
        call tsc
        xchg rsi, rax
.pit:   pause
        in al, 0x61
        mov bh, al
        call tsc
        sub rax, rsi
        cmp rax, rcx
        jae .pnx
        test bh, 0x20
        jz .pit
        cmp eax, 1 << 19
        jb .pnx
        xchg eax, ecx
.pnx:   dec bl
        jnz .cal
        cmp ecx, 1 << 26
        jb .pok
        mov ecx, 1 << 24        ; (no timer: 2^20 cycles a tick, as at 2.1 GHz)
.pok:   xor eax, eax
        push 16
        pop rdx
        div rcx
        mov [TSCM], rax
%ifdef LIFE
        call clock
        mov [BORN], eax
%endif
        ; The other processors, should there be any (up to MAXCPU - 1): each gets page
        ; tables (as ours, but for BSS and page 0) and a copy of BSS as it is now: all the
        ; constants, and nothing yet of what must not be the same on two processors (the
        ; nonces of `stock`: none have been made).
        mov esi, tramp
        mov edi, TRAMP
        push TRAMPLEN
        pop rcx
        rep movsb
        mov rax, cr0            ; From here on, what the page tables say is not written is
        bts eax, 16             ; not written by us either (that copy was the last such
        mov cr0, rax            ; write)
        mov edi, TXLOCK         ; (what is shared down there starts as zero: that memory
        xor eax, eax            ; is whatever the loader left in it)
        mov cl, 5
        rep stosq
        mov ebx, 1
.cpu:   mov r8d, ebx
        shl r8d, 15
        add r8d, APMEM - 0x8000
        lea eax, [r8+0x1003]
        mov [r8], rax           ; top table: one entry, to
        mov esi, PDPT0
        lea edi, [r8+0x1000]
        mov ch, 2
        rep movsq               ; a copy of our second one, whose first GiB is from
        lea eax, [r8+0x2003]
        mov [r8+0x1000], rax
        mov esi, PDT
        mov ch, 2
        rep movsq               ; a copy of our first page directory, whose first 2 MiB
        lea eax, [r8+0x3003]    ; are in pages of 4 KiB,
        mov [r8+0x2000], rax
        mov eax, ebx
        shl eax, 21
        add eax, APBSS - 0x200000 + 0x83
        bts rax, 63
        mov [r8+0x2000+(BSSN>>21)*8], rax ; and whose 2 MiB at BSS are its own
        mov esi, PT0
        mov ch, 2
        rep movsq
        lea eax, [r8+0x4003]
        bts rax, 63
        mov [r8+0x3000], rax    ; (page 0: its own)
        mov esi, BSS
        mov edi, ebx
        shl edi, 21
        add edi, APBSS - 0x200000
        mov ecx, 0x200000 / 8
        rep movsq
        mov [rdi+CPUN-STACK], ebx
        inc ebx
        cmp bl, MAXCPU
        jb .cpu
        mov eax, 0xFEE0009B     ; The local APIC, mapped where the card's structures are:
        mov [abs PDDEV+10*8], rax ; INIT to all the others, then twice "start at TRAMP"
        mov rsi, (DEVG << 30) + (10 << 21) + 0x300
        mov ebx, 0x000C4500
        call .wait
        mov bx, 0x4600 + (TRAMP >> 12)
        call .wait
        call .wait
        mov eax, [abs TRAMP+apcount-tramp] ; So many came. Frames go to a power of two of us.
        cmp eax, MAXCPU - 1
        jbe .came
        push MAXCPU - 1
        pop rax
.came:  inc eax
        bsr ecx, eax
        xor eax, eax
        inc eax
        shl eax, cl
        dec eax
        mov [abs NCPUM], eax
%ifdef WXTEST                   ; (make WXTEST=n, for tools/wxtest.sh: each of these must be
%if WXTEST = 1                  ; the machine's end)
        mov byte [mb], 0        ; code written
%elif WXTEST = 2
        mov eax, STACK - 64     ; data executed
        mov byte [rax], 0xC3
        call rax
%elif WXTEST = 3
        mov byte [SITE + SITE_LEN - 1], 0 ; the site written
%elif WXTEST = 4
        mov eax, SITE + SITE_LEN - 1 ; the site executed
        mov ecx, RXB
        mov byte [rcx], 0xC3    ; (and a packet buffer)
        call rax
%elif WXTEST = 5
        mov eax, RXB            ; a packet buffer executed
        mov byte [rax], 0xC3
        call rax
%elif WXTEST = 6                ; a fault, with a handler for it named where the frame in hand
        WXGATE poll             ; lies (as a client's packet could name one)
%endif
%endif
        jmp poll
.wait:  mov [rsi], ebx
        call clock              ; (22 ticks: 10.7 ms)
        mov ecx, eax
.w:     pause
        call clock
        sub eax, ecx
        cmp eax, 22
        jb .w
        ret

poll:
%ifdef LIFE                     ; development builds (make LIFE=n): after n minutes the
        call clock              ; machine is reset, whatever happens: a test server then
        sub eax, [BORN]         ; boots what its disk boots by default, also when the network
        cmp eax, LIFE * 60 * 2048 ; side of a new image turns out not to work
        ja reset
%endif
        cmp dword [CPUN], 0
        jne .ring
        call drain
.ring:  call ring1              ; then one frame of our own, if there is one
        jnz poll
        call txkick             ; none: time to tell the device what we have queued for it,
        call tidle              ; to see who has waited too long for an ack,
        call tqrun
        cmp dword [POOLN], 0    ; and to get on with the next signatures if there are none
        jne .idle
        call stock
        jmp poll
.idle:  count 9                 ; (a turn with nothing to do)
        pause
        jmp poll

; ring1: the next frame in this processor's ring goes through `tcp`; ZF if there is none.
; (Clobbers everything.)
ring1:  mov ebx, [MYRING]
        mov eax, [rbx+64]
        cmp eax, [rbx]
        je .none
        and eax, [HSMASK]
        inc eax
        shl eax, 11
        lea esi, [rbx+rax]
        lodsd
        mov ecx, eax
        mov [RXLEN], ecx
        xor edi, edi            ; FR
        rep movsb
        inc dword [rbx+64]
        test byte [rbx+64], 31  ; (if frames keep coming, the device is told of ours every
        jnz .go                 ; 32 of them)
        call txkick
.go:    call tcpd
        or al, 1
.none:  ret

; drain (the first processor's): everything the device has goes into our own rings, each
; frame into the ring of the processor whose connection it is. That takes a few hundred
; cycles a frame, and it is done before every frame handled and at intervals during what
; takes long (`bdrain`), so the device's ring (256 on the server) only has to hold what
; comes in some tens of microseconds, and what we can't keep up with waits in ours (n
; frames each, see TABV: 16,384 in 4 GiB) instead of being lost: with handshakes to make
; that is what half a second brings. A connection is one processor's: which, the hash of
; its addresses and ports says (the bits that also pick the place of an early segment:
; those are then one processor's too). Clobbers rax, rcx, rdx, rbx, rsi, rdi, xmm0.
drain:  mov esi, [Q0+8]         ; used ring: anything new?
        mov eax, [Q0+Q_SEEN]
        cmp ax, [rsi+2]
        je .done
        inc dword [Q0+Q_SEEN]
        and eax, [Q0+12]
        mov edx, [rsi+4+rax*8]  ; buffer id
        mov ecx, [rsi+8+rax*8]  ; bytes written, header included
        mov esi, edx
        and esi, [Q0+12]        ; (id and length are the device's: keep both inside our buffers)
        shl esi, 11
        add esi, RXB + 12
        sub ecx, 12
        and ecx, 2047
        xor eax, eax
        cmp [abs NCPUM], eax
        je .put
        push rsi
        push rcx
        call prf
        pop rcx
        pop rsi
        pextrd eax, xmm0, 3
        and eax, [abs NCPUM]
.put:   imul eax, [RSTEP]
        add eax, [RBASE]        ; that processor's ring: how many frames have been written,
        mov ebx, eax            ; at +64 how many read, then the frames (2 KiB each, length
        mov edi, [rbx]          ; first)
        mov eax, edi
        sub eax, [rbx+64]
        cmp eax, [HSMASK]
        ja .lost                ; (full: the frame is lost)
        cmp ecx, 2044
        ja .give                ; (and so is one that would not fit its place there)
        and edi, [HSMASK]
        inc edi
        shl edi, 11
        add edi, ebx
        mov eax, ecx
        stosd
        rep movsb
        inc dword [rbx]
.give:  mov esi, [Q0+4]         ; give the buffer back
        movzx eax, word [rsi+2]
        and eax, [Q0+12]
        mov [rsi+4+rax*2], dx
        inc word [rsi+2]
        mov esi, [Q0+8]
        test byte [rsi], 1      ; the device says when it doesn't need to be told
        jnz drain
        mov rdx, [Q0+Q_NOTE]
        mov word [rdx], 0
        jmp drain
.lost:  count 2
        jmp .give
.done:  ret

; bdrain: the same, from the middle of long work, on whichever processor: keeps the eight
; old registers
bdrain: cmp dword [CPUN], 0
        jne .no
        pushad
        call drain
        popad
.no:    ret

; Another processor starts here, in real mode (at TRAMP, where this was copied): it takes
; a number, and with it the page tables made for it, goes straight to long mode, and
; then lives off the frames the first processor puts in its ring.
BITS 16
tramp:  cli
        xor ax, ax
        mov ds, ax
        mov eax, 1
        lock xadd [TRAMP+apcount-tramp], eax
        inc eax
        cmp eax, MAXCPU
        jae .no
        shl eax, 15
        add eax, APMEM - 0x8000
        mov cr3, eax
        mov eax, cr4
        or eax, 0x220
        mov cr4, eax
        mov ecx, 0xC0000080
        rdmsr
        or ah, 9
        wrmsr
        mov eax, cr0
        and eax, 0x9FFFFFFF     ; (caches on: a processor starts with them off)
        or eax, 0x80010001
        mov cr0, eax
        o32 lgdt [TRAMP+apgdt-tramp]
        jmp dword 8:apstart
.no:    hlt
        jmp .no
apcount: dd 0
apgdt:  dw 23
        dd GDT
TRAMPLEN equ $ - tramp
BITS 64
apstart: mov esp, STACK
        push 16
        pop rax
        mov ds, eax
        mov es, eax
        mov ss, eax
        lidt [GDT]              ; (no interrupt handlers here either: see `GDT`)
        mov eax, [CPUN]
        imul eax, [RSTEP]
        add [TQB], eax          ; (its own queue of waiting connections, and its own ring)
        add eax, [RBASE]
        mov [MYRING], eax
.w:     pause                   ; Until the first processor has counted us. Frames go to a
        mov eax, [abs NCPUM]    ; power of two of us: one that gets none (the third of
        test eax, eax           ; three; one that came after the count) has nothing to do,
        jz .w                   ; and must not go through the motions either: its turn at
        cmp [CPUN], eax         ; the SYNs of late (`tidle`) would be at another's
        ja .rest
%ifdef WXTEST
%if WXTEST = 7                  ; (the same on a processor that was started up: its table is
        WXGATE poll             ; at address 0 whatever loaded us)
%endif
%endif
        jmp poll
.rest:  hlt
        jmp .rest

%ifdef DEBUG
tcpd:   rdtsc                   ; (`tcp`, with the cycles spent on frames, and how many frames)
        push rax
        call tcp
        rdtsc
        pop rdx
        sub eax, edx
        add [DBG+24], eax
        adc dword [DBG+28], 0
        inc dword [DBG+32]
        ret
%endif

%ifdef KNOCK_A
%define RESET
%endif
%ifdef LIFE
%define RESET
%endif
%ifdef RESET
; reset: the machine starts over (development builds only: the knock, and LIFE)
reset:  mov al, 0xFE
        out 0x64, al            ; keyboard controller: pulse the reset line
        int3                    ; (and if that does nothing: a fault, which nobody handles)
%endif

; pcird: eax = PCI configuration dword at register eax of the device at ebx (dx = 0xCFC after)
pcird:  and al, 0xFC
        add eax, ebx
        mov dx, 0xCF8
        out dx, eax
        mov dl, 0xFC
        in eax, dx
        ret

; txbuf: ebx = where to build the next frame to send. Each frame gets its own buffer, the next
; of N in a circle; if the device still has all N, wait for it.
txbuf:  pushad
.lock:  lock bts dword [abs TXLOCK], 0 ; (one processor at a time, until `txgo`)
        jnc .mine
        call bdrain             ; (what comes in while we wait must not wait for us)
        pause
        jmp .lock
.mine:  mov ebx, [Q1+4]         ; available ring
        mov esi, [Q1+8]         ; used ring
        movzx eax, word [rbx+2]
.full:  mov edx, eax
        sub dx, [rsi+2]
        cmp dx, [Q1+12]
        jbe .room
        call txkick.now         ; (whoever queued them: another processor may be waiting for us)
        call bdrain
        jmp .full
.room:  and eax, [Q1+12]        ; buffer = descriptor = ring position
        shl eax, 11
        add eax, TXB + 12
        mov [rsp+24], rax
        popad
        ret

; txgo: queue the frame of ecx bytes at ebx: built where txbuf said, or in a buffer of the
; caller's own (`txbig`), after txbuf has made the ring ours. It goes out with txkick.
txgo:   pushad
        mov edx, [Q1+4]
        movzx eax, word [rdx+2]
        and eax, [Q1+12]
        mov [rdx+4+rax*2], ax
        shl eax, 4
        add eax, [Q1]
        sub ebx, 12             ; (in front of a frame, 12 bytes for the device: all zero, or
        mov [rax], rbx          ; what `tcp_big` says there)
        add ecx, 12
        mov [rax+8], ecx
        inc word [rdx+2]
        inc qword [abs TXCNT]
        mov byte [TXK], 1
        mov byte [abs TXLOCK], 0
        popad
        ret

; txbig: ebx = where this processor may build a frame of up to 64 KiB (for `tcp_big`): the
; next of its BIGS buffers, in a circle, once the device has sent what the buffer last held.
; That it has when it has sent as many frames as had been queued by the time the buffer
; after this one was asked for (BIGQ has that count; the device sends in the order of the
; ring). Until then: wait, and let what comes in go on to the rings. (Clobbers eax, edx,
; esi, edi.)
txbig:  mov eax, [BIGN]
        inc dword [BIGN]
        lea rsi, [BIGQ]
        mov rdx, [abs TXCNT]
        lea edi, [rax-1]
        and edi, BIGS - 1
        mov [rsi+rdi*8], rdx    ; (the buffer before this one: its frame is queued by now)
        and eax, BIGS - 1
.wait:  mov edx, [Q1+8]
        movzx edi, word [rdx+2] ; How many frames the device has sent (a word of that count;
        mov rdx, [abs TXCNT]    ; read before the count of those queued, of which it is then
        neg edi                 ; never ahead):
        add edi, edx
        movzx edi, di           ; so many it still has,
        sub rdx, [rsi+rax*8]    ; and so many were queued after this buffer's
        cmp rdx, rdi
        jae .free
        call txkick.now
        call bdrain
        pause
        jmp .wait
.free:  mov ebx, [CPUN]
        shl ebx, BIGSH
        add ebx, eax
        shl ebx, 16
        add ebx, BIGB + 12
        ret

; txkick: tell the device that there are frames to send, if there are some it has not been
; told about and it wants to be told. Telling costs far more than anything else we do for a
; frame (it leaves the virtual machine), so the polling loop does it when it has handled
; all that came in, not for every frame.
txkick: push rax
        btr dword [TXK], 0
        jnc .no
        mov eax, [Q1+8]
        test byte [rax], 1
        jnz .no
.tell:  mov rax, [Q1+Q_NOTE]
        mov word [rax], 1       ; notify queue 1
.no:    pop rax
        ret
.now:   push rax
        jmp .tell

; ethhdr: at edi (which moves on) the start of a frame to the sender of the one in FR: to its
; address, from ours (clobbers esi)
ethhdr: push 6
        pop rsi                 ; FR + 6
        movsd
        movsw
        mov esi, MAC
        movsd
        movsw
        ret

; ----------------------------------------------------------------------------
; tcp: handle the frame in FR (RXLEN bytes). FR stays as it came, except that its sequence
; number and ack are turned into host order (P_SEQ, P_ACK); what we send is built in the
; transmit buffers (`tcp_seg`).
;
; Each connection knows the next byte it expects from the client (C_NXT), our next byte
; (C_SND) and the client's last ack (C_ACK). What we have sent is never stored, except the
; handshake flight: everything else is made again from what never changes. On port 443
; that is the response in hand, a stretch of the image, sealed a record to a segment
; (`.tx` has how it is sent and sent again). On port 80 it is one response for every
; request, and with the flight it goes the old way: anything the client turns out not to
; have is built again from the byte its ack names and sent at once (`.resend`), and two
; things tell us that a packet of ours was lost:
;   - the client sends old data again, with an ack below C_SND: its request is not
;     acknowledged because the answer, which carries our ack, did not arrive;
;   - the client repeats an ack below C_SND without data: it got something after a hole.
; So that the first always works, an answer of several segments does not acknowledge the
; client's data (`tcp_send`): that happens when the client's ack says it has all of it.
;
; Connections live in two hashed tables (`find`): one for port 443, one with small slots for
; port 80, which has no TLS and no files (a request ends with an empty line and gets the
; one response). A SYN gets a SYN-ACK and no slot (`.syn`); the first packet that
; acknowledges it makes the connection. A segment that comes before its predecessor is
; kept (`oohold`).
tcp:
        xor ebx, ebx            ; FR (and 0), all the way through
        cmp word [rbx+12], 0x0608
        jne .ip
        cmp word [rbx+20], 0x0100 ; ARP request for our address: answer it
        jne .ret
        cmp dword [rbx+38], OURIP
        jne .ret
        call txbuf
        mov edi, ebx
        call ethhdr
        push 12                 ; the request's type and header up to the operation,
        pop rsi
        push 9
        pop rcx
        rep movsb
        mov al, 2               ; which is: reply. We are its sender,
        stosb
        mov esi, MAC
        movsd
        movsw
        mov eax, OURIP
        stosd
        push 22                 ; the request's sender is its target
        pop rsi
        mov cl, 10
        rep movsb
        mov cl, 42
        jmp txgo
.ip:    cmp word [rbx+12], 0x0008 ; IPv4, no options, not a fragment, TCP, to us, all of it
        jne .ret                ; in this frame, the TCP checksum right: nothing else gets
        cmp byte [rbx+14], 0x45 ; any further. (The IP header has a checksum of its own, but
        jne .ret                ; what we use of it is fixed here or goes into TCP's.)
        test word [rbx+20], 0xFF3F
        jnz .ret
        cmp byte [rbx+23], 6
        jne .ret
        cmp dword [rbx+30], OURIP
        jne .ret
        movzx ecx, word [rbx+16]
        xchg cl, ch             ; IP total length
        lea eax, [rcx+14]
        cmp eax, [RXLEN]
        ja .bad
        cmp ecx, 40             ; (our header and TCP's at least: asked before the one is
        jb .bad                 ; taken off, or a length of less than 20 would pass as 4 GiB)
        sub ecx, 20             ; TCP length
        mov [rbx+22], bl        ; the pseudo header, in place: 0, protocol, TCP length, addresses
        mov eax, ecx
        xchg al, ah
        mov [rbx+24], ax
        mov [rbx+rcx+34], bl    ; (a zero byte after an odd length)
        push rcx
        lea esi, [rbx+22]
        add ecx, 12
        call csum
        pop rcx
        test ax, ax
        jz .sums
.bad:   count 0
.ret:   ret
.sums:
%ifdef KNOCK_A                  ; development builds only (make KNOCK=a,b): a packet to port a,
        movzx eax, word [rbx+36] ; then one to port b, resets the machine, so a test server
        xchg al, ah             ; comes back up in whatever its disk boots by default
        cmp eax, KNOCK_A
        jne .kb
        mov byte [abs KST], 1   ; (the two packets may go to different processors)
.kb:    cmp eax, KNOCK_B
        jne .nok
        cmp byte [abs KST], 1
        jne .nok
        jmp reset
.nok:
%endif
        cmp word [rbx+36], 0xBB01 ; port 443: TLS
        je .port
        cmp word [rbx+36], 0x5000 ; port 80: the same without
        jne .ret
.port:  cmp [rbx+P_IP], ebx     ; (no client is 0.0.0.0: that marks a free slot)
        je .ret
        movzx eax, byte [rbx+46]
        shr eax, 4
        shl eax, 2              ; TCP header length
        cmp al, 20
        jb .ret
        sub ecx, eax            ; payload length
        jb .ret
        lea esi, [rbx+rax+34]   ; payload
        mov eax, [rbx+P_SEQ]
        bswap eax
        mov [rbx+P_SEQ], eax
        mov eax, [rbx+P_ACK]
        bswap eax
        mov [rbx+P_ACK], eax
        call clock
        mov [rbx+P_MORE], bx    ; (and P_EV)
        mov dl, [rbx+P_FL]
        call find               ; ebp = the connection's slot; or, if it has none, eax = -1
        sbb eax, eax            ; and ebp = a slot for a new one (0: there is no room)
        jnz .slot
        call hold               ; Its slot, which is in use from here on (`hold`): unless
        jne .gone               ; another processor has just made it its own, and then
        xor eax, eax            ; this packet is as good as lost
.slot:  test dl, 4
        jz .nrst
        inc eax                 ; RST: if it is the next thing its connection expects, that
        jz .ret                 ; was the connection
        mov eax, [rbx+P_SEQ]
        cmp eax, [rbp+C_NXT]
        jne .ret
.free:  and dword [rbp+C_IP], 0
.gone:  ret
.nrst:  test dl, 2
        jz .nsyn
        test dl, 16
        jnz .ret
        ; SYN. It gets a SYN-ACK and no slot: the slot is made when an ack shows that the
        ; client received it (`.miss`), so only clients that really are at their address can
        ; take up slots. For that our initial sequence number is a "cookie", made of W, a
        ; keyed hash of the client's address and ports (`prf`):
        ;   bits 14-31: W xor the low bits of the client's initial sequence number, so that
        ;               the packet that follows the SYN-ACK is recognised as the first;
        ;   bits 6-13:  W (HINT): tells a packet that acknowledges a SYN-ACK of ours, first
        ;               or not, from one of a connection we don't know;
        ;   bits 2-5:   by how many bits the client shifts its window (window scaling:
        ;               what its SYN said, 14 at most; 0: it does not);
        ;   bits 0-1:   which of four segment sizes the client takes (MSSTAB).
        inc eax
        jz .nos
        or byte [rbp+C_FLG], F_SYN ; (for a connection we have: its client may be starting
        jmp .syn                ; over, see `.odd`)
.nos:   test rbp, rbp
        jz .deny                ; (no room where this connection would go: say so now)
.syn:   movzx ecx, byte [rbx+46] ; its options: how much the client takes in one segment,
        shr ecx, 4              ; and whether it scales its window
        lea ecx, [rcx*4-20]
        lea esi, [rbx+54]
        mov edx, 536            ; (what one that doesn't say must take)
        xor r8d, r8d
.opt:   cmp ecx, 2
        jl .optd
        lodsb
        dec ecx
        cmp al, 1               ; padding
        je .opt
        jb .optd                ; end of options
        movzx edi, byte [rsi]   ; length of this one, with the two bytes that say so
        dec edi
        jle .optd
        cmp edi, ecx
        ja .optd
        cmp al, 2
        jne .ows
        cmp edi, 3
        jne .onx
        movzx edx, word [rsi+1]
        xchg dl, dh
.ows:   cmp al, 3               ; (window scale: a shift, of which 14 is the most there is)
        jne .onx
        cmp edi, 2
        jne .onx
        movzx r8d, byte [rsi+1]
        cmp r8d, 14
        jbe .onx
        mov r8b, 14
.onx:   add esi, edi
        sub ecx, edi
        jmp .opt
.optd:  call tnote
        mov eax, [rbx+P_SEQ]
        lea edi, [rax+1]        ; (the SYN takes a sequence number, and so does ours)
        shl eax, 14
        xor eax, [HKO+8]
        and al, 0xC0
%ifdef ISNTOP                   ; (make ISNTOP=n ISNBITS=b, for tests: the top b bits of
        and eax, ISNLOW         ; every initial sequence number are n's, so that what we
        or eax, ISNTOP & ~ISNLOW ; send crosses 2^31 or 2^32 soon. The cookie then says
%endif                          ; that much less: see `ckx`)
        cmp edx, 536            ; the largest of the four sizes that is not more than the
        sbb eax, -1             ; client's
        cmp edx, 1220
        sbb eax, -1
        cmp edx, 1440
        sbb eax, -1
        lea eax, [rax+r8*4]
        xchg eax, edx
        mov al, 0x12            ; SYN|ACK. Its options: what we take in one segment, and, if
        mov esi, SYNOPT         ; the client scales its window, that we know (and don't
        push 4                  ; scale ours: 64 KB at a time is more than any request)
        pop rcx
        test r8d, r8d
        jz .seg
        mov cl, 8
.seg:   jmp tcp_seg
.deny:  count 2
        mov al, 0x14            ; RST|ACK: connection refused
        mov edi, [rbx+P_SEQ]
        inc edi
        xor edx, edx
        xor ecx, ecx
        jmp .seg

.nsyn:  test dl, 16
        jz .ret
        inc eax
        jnz .est
        ; No such connection. If this is the first packet after one of our SYN-ACKs, it is a
        ; new one, in the slot `find` chose. If it acknowledges a SYN-ACK of ours but is not
        ; the first (that one got lost, and its ack before it), the client will send the
        ; first again: nothing to do. Anything else that expects an answer is told that there
        ; is no connection (after a FIN we forget at once; and we may have been restarted).
.miss:  call ckx
        jz .make
        test ax, HINT
        jz .ret
        test dl, 1
        jnz .rst
        test ecx, ecx
        jz .ret
.rst:   count 5
        mov al, 4               ; RST, where the client's ack says
        mov edx, [rbx+P_ACK]
        xor ecx, ecx
        xor edi, edi
        jmp .seg
.full:  count 2                 ; there is no room for it: refused
        jmp .rst
.make:  test rbp, rbp
        jz .full
        movzx edi, byte [NOW]   ; The slot becomes this connection's in one step, if it still
        shl edi, 24             ; is as `find` saw it: another processor may have taken it
        mov di, [rbx+P_PORTS]   ; since, for a connection of its own. (Then this packet is as
        shl rdi, 32             ; good as lost, and will come again.) Its first eight bytes:
        mov eax, [rbx+P_IP]     ; the client's address and port, no flags, and the time
        or rdi, rax             ; (C_AGE): from that step on it is not one that has long
        mov rax, [CLAIMQ]       ; been quiet, for anybody to take
        lock cmpxchg [rbp], rdi
        jne .ret
        mov eax, [HKO+12]       ; (its SYN-ACK has arrived: `tnote`)
        and eax, [TMMASK]
        mov edi, [TMT]
        mov [rdi+rax*4], ebx
        push rcx
        lea rdi, [rbp+8]
        push (PSLOT - 8) / 4
        pop rcx
        cmp [rbx+P_PORTS+2], bl
        je .mk
        mov cl, (C_KIV - 8) / 4 ; (a slot of the TLS table goes on)
.mk:    xor eax, eax
        rep stosd
        pop rcx
        mov eax, [rbx+P_SEQ]
        mov [rbp+C_NXT], eax
        mov eax, [rbx+P_ACK]
        lea edx, [rax-1]        ; What the SYN-ACK noted in our sequence number: the client's
        shl edx, 2              ; window shift (the top four bits of C_FL2; in a slot for
        mov dh, dl              ; port 80, which ends before that, rdi is at a byte of C_ACK
        and dh, 0xF0            ; here, which is set next) and its segment size
        mov [rdi-2], dh
        and dl, 0x0C
        mov [rbp+C_FLG], dl
        mov [rbp+C_SND], eax
        mov [rbp+C_ACK], eax

        ; The client's ack counts if it is in [C_ACK, C_SND]. edx = 1: it lacks something we
        ; sent, 2: and says so with the same ack as before, 0: neither
.est:   xor edx, edx
        mov [rbx+P_ADV], edx
        mov eax, [rbx+P_ACK]
        sub eax, [rbp+C_ACK]    ; how much further than before
        mov edi, [rbp+C_SND]
        sub edi, [rbp+C_ACK]    ; how much there is to acknowledge
        cmp eax, edi
        ja .odd
        jb .ak0
        test byte [rbp+C_FLG], F_CLOSED ; It has all we sent. If that includes our FIN, that
        jz .nfin                ; was the connection
        cmp [rbx+P_PORTS+2], bl
        je .free
        test byte [rbp+C_FL2], F_FIN
        jnz .free
.nfin:  cmp [rbx+P_PORTS+2], bl
        je .nhs
        cmp [rbp+C_ST], ebx
        je .nhs
        cmp [rbp+C_LEN], bx
        jne .nhs
        mov [rbp+C_HS], bx      ; (it has our flight, and no record of its own is being put
.nhs:   btr dword [rbp+C_FLG], F_DEFER_BIT ; together: the handshake buffer can go to another)
                                ; If that was an answer of several segments, its
        jnc .ak1                ; data is acknowledged only now
        inc byte [rbx+P_MORE]
        jmp .ak1
.odd:   test byte [rbp+C_FLG], F_SYN ; Not an ack for this connection: for a new one from
        jz .ak                  ; the same address and port, whose predecessor we never saw
        call ckx                ; end? Only if a SYN has come: a late copy of this
        jnz .ak                 ; connection's own first ack is a valid cookie too, and
        mov rax, [rbp]          ; must not start it over.
        mov [CLAIMQ], rax
        jmp .make
.ak0:   inc edx
        test eax, eax
        jnz .ak1
        inc edx
.ak1:   add [rbp+C_ACK], eax
        mov [rbx+P_ADV], eax
        and byte [rbp+C_FLG], ~F_SYN
.ak:    test byte [rbp+C_FLG], F_CLOSED
        jz .open
        test edx, edx           ; Closed: nothing more is taken from the client. If it lacks
        jz .quiet               ; something (our FIN at least) and asks, by sending anything
        cmp dl, 2               ; but a plain new ack, it gets that again
        je .resend
        test byte [rbx+P_FL], 1
        jnz .resend
        test ecx, ecx
        jnz .resend
.quiet: call sm                 ; Nothing to say. But if a response is on its way, the ack
        jc .tx                  ; may have made room for more of it
        ret
.open:  mov eax, [rbp+C_NXT]
        sub eax, [rbx+P_SEQ]    ; how many of this segment's bytes we already have
        js .early
        jz .inord
        cmp eax, ecx
        ja .old
        jb .trim
        test byte [rbx+P_FL], 1 ; all of its data is old; a FIN after it would be new
        jz .old
.trim:  add esi, eax            ; drop what we have, the rest is new
        sub ecx, eax
        add [rbx+P_SEQ], eax
        jmp .new
.early: count 3                 ; From further on: what comes before it is late (neighbours do
        neg eax                 ; get swapped on the way) or lost. Keep it for when that
        cmp eax, 0xFFFF         ; arrives, if it is inside our window and not empty, and say
        ja .ack                 ; what we expect.
        mov al, [rbx+P_FL]
        and eax, 1
        or eax, ecx
        jz .ack
        call oohold
        jmp .ack
.old:   jrcxz .ack              ; (a keep-alive probe: one byte back, no data)
        test edx, edx           ; old data again. If the client lacks something of ours, that
        jnz .resend             ; is why; if not, an ack will do
.ack:   call sm
        jc .txa
        mov esi, OB
        xor ecx, ecx
        mov al, 0x10
        jmp .send
.inord: test ecx, ecx
        jnz .new
        test byte [rbx+P_FL], 1
        jnz .new
        cmp dl, 2               ; no data: an ack. The same ack twice with something
        je .resend              ; outstanding: a segment of ours is missing
        cmp [rbx+P_MORE], bl
        jne .ack
        jmp .quiet

.new:   mov edi, OB             ; edi = end of our answer
.more:  add [rbp+C_NXT], ecx    ; ecx new bytes at esi, in order
        cmp [rbx+P_PORTS+2], bl
        je .plain
        mov [SEGP], esi
        ; TLS: records. One that is all in this segment is looked at where it is (`record`).
        ; One that is not (and every ClientHello, whose buffer our flight will need) is put
        ; together in a handshake buffer: C_LEN bytes of it are there. Its header says how
        ; long it is; if that is more than the buffer holds, we can't go on.
.walk:  test ecx, ecx
        jz .reply
        movzx eax, word [rbp+C_LEN]
        test eax, eax
        jnz .part
        cmp [rbp+C_ST], ebx
        je .coll
        cmp ecx, 5
        jb .coll
        movzx edx, word [rsi+3]
        xchg dl, dh
        add edx, 5              ; the record's length
        cmp edx, ecx
        ja .coll
        call record
        jc .busy
        add esi, edx
        sub ecx, edx
        jmp .walk
.coll:  push rbx
        call hsnew
        jmp .buf
.part:  push rbx
        call hsbuf
        jc .resetp              ; (its first part is gone: the buffer was needed for others)
.buf:   push 5
        pop rdx
        cmp eax, edx
        jb .take                ; (first its header)
        movzx edx, word [rbx+HS_CH+3]
        xchg dl, dh
        add edx, 5
        cmp edx, CHMAX
        ja .resetp
.take:  sub edx, eax            ; so many bytes are wanted,
        cmp edx, ecx
        jbe .tk
        mov edx, ecx            ; and so many are here
.tk:    push rcx
        push rdi
        lea edi, [rbx+HS_CH+rax]
        mov ecx, edx
        rep movsb
        pop rdi
        pop rcx
        sub ecx, edx
        add eax, edx
        mov [rbp+C_LEN], ax
        cmp eax, 5
        jb .nyet
        movzx edx, word [rbx+HS_CH+3]
        xchg dl, dh
        add edx, 5
        cmp eax, edx
        jb .nyet
        cmp dword [rbp+C_ST], 0 ; all there. Before the handshake it is the ClientHello, if
        jne .rec                ; it is a handshake record at all (clients send a
        cmp byte [rbx+HS_CH], 22 ; ChangeCipherSpec before a second ClientHello, for
        je .hello               ; middleboxes' sake: nothing to us);
        pop rbx
        mov [rbp+C_LEN], bx
        jmp .walk
.rec:   push rsi
        lea esi, [rbx+HS_CH]
        call record             ; any other is looked at like those that come in one piece
        pop rsi
        pop rbx
        jc .busyc
        mov [rbp+C_LEN], bx
        mov [rbp+C_HS], bx      ; (and the buffer can go to another)
        jmp .walk
.nyet:  pop rbx
        jmp .walk
.hello: push rsi                ; (the rest of this segment)
        push rcx
        push rbx
        inc dword [rbp+C_ST]
        lea esi, [rbx+HS_CH+5]
        lea ecx, [rdx-5]
        call handshake          ; edi = end of our flight
        pop rbx
        mov ecx, edi            ; keep the flight, where the ClientHello was: a client that
        sub ecx, OB             ; sends its ClientHello again has to get this one again (it
        mov [rbx+HS_FLEN], ecx  ; may have got it already)
        mov eax, [rbp+C_SND]
        add eax, ecx
        mov [rbp+C_RS], eax     ; (behind it our responses will begin)
        push rdi
        mov esi, OB
        lea edi, [rbx+HS_FL]
        rep movsb
        pop rdi
        pop rcx
        pop rsi
        pop rbx
        mov [rbp+C_LEN], bx
        test byte [rbp+C_FLG], F_CLOSED ; (a client we can't serve has been told so, and
        jnz .out                ; nothing more is taken from it)
        jmp .walk
        ; A request whose response can't be the one in hand yet (`record`): it is as good
        ; as not arrived, and so is all that follows it in this segment. The client will
        ; send it again.
.busyc: mov eax, esi            ; (one put together: this segment's part of it leaves the buffer)
        sub eax, [SEGP]
        sub [rbp+C_LEN], ax
        add ecx, eax
.busy:  sub [rbp+C_NXT], ecx
        and byte [rbx+P_FL], ~1
        jmp .out

        ; Port 80. A request ends with an empty line (the top bit of C_FLG: the last line
        ; has just ended; CRs don't count either way) and gets the response.
.plain: test ecx, ecx
        jz .reply
        movzx edx, byte [rbp+C_FLG]
        shr edx, 7
.hb:    lodsb
        cmp al, 13
        je .hn
        cmp al, 10
        jne .h0
        inc edx
        cmp dl, 2
        jb .hn
        cmp edi, OB + OBMAX - P80_LEN
        ja .h0                  ; (no room for another response)
        call respond
.h0:    xor edx, edx
.hn:    loop .hb
        and byte [rbp+C_FLG], 0x7F
        shl edx, 7
        or [rbp+C_FLG], dl

.reply: xor ebx, ebx
        call ooent              ; Is a segment that came early next now? Then go on with it.
        jne .out
        mov eax, [rbp+C_NXT]
        sub eax, [rdx+OO_SEQ]   ; how many of its bytes we have by now
        js .out                 ; (it is still ahead)
        mov [rdx+OO_TAG], ebx
        mov ecx, [rdx+OO_LEN]
        cmp eax, ecx
        ja .out
        jb .use
        cmp [rdx+OO_FIN], bl    ; (all of its data came another way; a FIN after it is new)
        je .out
.use:   test byte [rbx+P_FL], 1
        jnz .out                ; (nothing follows a FIN)
        lea esi, [rdx+OO_DATA+rax]
        sub ecx, eax
        mov al, [rdx+OO_FIN]
        or [rbx+P_FL], al
        jmp .more
.out:   call sm
        jc .txo
        mov esi, OB             ; our answer is at OB, up to edi; it follows what we sent before
        mov ecx, edi
        sub ecx, esi
        mov al, 0x10            ; ACK
        jz .fin
        mov al, 0x18            ; ACK|PSH
.fin:   test byte [rbp+C_FLG], F_CLOSED ; (our answer was "no": `handshake`. We close)
        jnz .ours
        test byte [rbx+P_FL], 1
        jz .send
        inc dword [rbp+C_NXT]   ; the client's FIN takes a sequence number and gets ours with
.ours:  or al, 1                ; the answer
.send:  mov edx, [rbp+C_SND]
        add [rbp+C_SND], ecx
        test al, 1
        jz .sq
        inc dword [rbp+C_SND]   ; (ours takes one too)
        or byte [rbp+C_FLG], F_CLOSED
        cmp [rbx+P_PORTS+2], bl
        je .f80
        or byte [rbp+C_FL2], F_FIN
.f80:   mov edi, [rbx+P_ACK]    ; If the client had all we sent and there was nothing more to
        sub edi, edx            ; say, that was the connection (should our FIN get lost, the
        or edi, ecx             ; client's next one is told that there is none). If not, the
        jnz .sq                 ; slot stays until the client has the rest.
        call tcp_send
        jmp .free
.sq:    jmp tcp_send

        ; A TLS connection whose client has had our flight (`sm`). What we send from then
        ; on is cut from the response in hand, which is a stretch of the image (`geom`):
        ; a record of it to a segment, so that any segment can be made again from nothing
        ; but where the response began (C_RS), which record that was (C_SR) and the
        ; client's ack. The client's acks let the next segments go: as many may be on
        ; their way as the client takes (its window) and as C_CW says, which begins at WIN
        ; and grows with what is acknowledged until something is lost, is halved then, and
        ; grows slowly after that (TCP's congestion control, in a byte). What tells us
        ; that a segment was lost:
        ;   - an ack that repeats: once, if two segments or less are on their way (no more
        ;     such acks can come), else three times (neighbours get swapped on the way,
        ;     and that looks the same). The segment it asks for goes again, once;
        ;   - then, an ack that moves on by no more than that segment: the one after it
        ;     was lost too (had it arrived, the ack would have gone past it);
        ;   - the client sending old data again (it waits for our ack: `tcp_send`), and
        ;     time passing without an ack (`tqrun`).
        ; A client's request for the next response waits until it has acknowledged all of
        ; this one (`record`), so one response is all a connection has to know of.
.txo:   test byte [rbx+P_FL], 1
        jz .txa
        inc dword [rbp+C_NXT]   ; the client's FIN: ours follows what it still has to get
        or byte [rbp+C_FLG], F_CLOSED
        and byte [rbp+C_FLG], ~F_DEFER
.txa:   or byte [rbx+P_EV], E_ACK
.tx:    call geom
        mov eax, [rbp+C_SND]
        sub eax, [rbp+C_ACK]    ; so much is on its way
        mov dl, [rbx+P_EV]
        test dl, E_RTO
        jnz .loss
        test dl, E_DUP
        jz .adv
        test eax, eax
        jz .pump
        cmp byte [rbp+C_FLG], F_DUP3
        jae .pump               ; (what it asks for has gone again already)
        add byte [rbp+C_FLG], F_DUP
        mov ecx, [TXM]
        add ecx, ecx
        cmp eax, ecx
        jbe .loss
        cmp byte [rbp+C_FLG], F_DUP3
        jb .pump
        jmp .loss
.adv:   mov ecx, [rbx+P_ADV]
        test ecx, ecx
        jz .pump
        cmp byte [rbp+C_FLG], F_DUP3
        jb .clr
        test eax, eax           ; (After a loss: its ack has moved on, but not to the end of
        jnz .rtx                ; what was on its way then, and nothing has been sent
                                ; since: what it asks for now was lost as well)
.clr:   and byte [rbp+C_FLG], ~F_DUP3
        movzx edi, byte [rbp+C_CW] ; The ack moved on, and nothing seems lost: more may
        imul edi, [TXM]         ; be on its way. As long as nothing ever was lost, and less
        shr edi, 16             ; than 64 KB may be: as many segments more as were
        jnz .ai                 ; acknowledged (twice as many each round trip);
        test byte [rbp+C_FL2], F_CA
        jnz .ai
        xchg eax, ecx
        xor edx, edx
        div dword [TXM]
        jmp .grow
.ai:    mov eax, [rbp+C_ACK]    ; after that, one more for every 16 KiB acknowledged; and
        mov edx, eax            ; above 64 KB, for every 64 KiB (a segment or a few more
        sub edx, ecx            ; each round trip: where that is one too many, few are
        xor eax, edx            ; lost, and each of those takes a round trip to make good)
        shr eax, 14
        test edi, edi
        jz .a16
        shr eax, 2
.a16:   test eax, eax
        jz .pump
        push 1
        pop rax
.grow:  movzx edx, byte [rbp+C_CW]
        add eax, edx
        cmp eax, 255
        jbe .cw
        mov eax, 255
.cw:    mov [rbp+C_CW], al
        jmp .pump
.loss:  shr byte [rbp+C_CW], 1  ; Something was lost: half as many may be on their way
        cmp byte [rbp+C_CW], 2  ; from now on (two at least)
        jae .ca
        mov byte [rbp+C_CW], 2
.ca:    or byte [rbp+C_FL2], F_CA
.rtx:   or byte [rbp+C_FLG], F_DUP3
        count 4
        mov eax, [rbp+C_ACK]
        call sendseg
.pump:  movzx eax, word [rbx+P_WIN]
        xchg al, ah             ; what the client takes beyond its ack (shifted as its SYN
        mov cl, [rbp+C_FL2]     ; said; but once something has been lost on a connection,
        shr cl, 4               ; no more than 64 KB, which was all there could be before
        shl eax, cl             ; windows were scaled: beyond it we only feel our way
        test byte [rbp+C_FL2], F_CA ; while nothing is lost),
        jz .wf
        mov edx, 0xFFFF
        cmp eax, edx
        cmova eax, edx
.wf:    mov ecx, [TXM]
        movzx edx, byte [rbp+C_CW]
        imul edx, ecx           ; and what we let be on its way
        cmp eax, edx
        cmova eax, edx
        test eax, eax
        jz .w2
        cmp eax, ecx
        cmovb eax, ecx          ; (a segment at least, unless it takes nothing at all)
.w2:    add eax, [rbp+C_ACK]
        mov [TXLIM], eax
        mov edx, [rbp+C_SND]    ; At the start of a response that takes several segments
        cmp edx, [rbp+C_RS]     ; and goes at once: the last byte the client sent is not
        jne .pl                 ; acknowledged before it has them all (see `tcp_send`)
        test byte [rbp+C_FLG], F_CLOSED
        jnz .pl
        mov edx, [TXEND]
        sub eax, edx
        js .pl
        sub edx, [rbp+C_RS]
        cmp edx, ecx
        jbe .pl
        cmp edx, 0xFFFF         ; (and no more than 64 KB: a longer one is on its way for
        ja .pl                  ; longer than a client waits for an ack before it asks again)
        or byte [rbp+C_FLG], F_DEFER
.pl:    cmp byte [rbp+C_FLG], F_DUP3 ; (While the client lacks something that was on its
        jae .pa                 ; way, nothing new goes: so its ack says when it has it all)
        mov eax, [rbp+C_SND]
        mov edx, eax
        sub edx, [TXEND]
        jns .pd                 ; (all of it has gone)
        mov edx, eax
        sub edx, [TXLIM]
        jns .pa                 ; (the client takes no more for now)
        cmp byte [TSO], 0       ; Where the card cuts frames for us, a frame should be worth
        je .go                  ; it. If what may go now is less than a third of what may
        neg edx                 ; be on its way at all, and not the response's end, it
        lea ecx, [rdx+rdx*2]    ; waits for the acks that are to come. (A small frame
        mov edi, [TXLIM]        ; brings a small ack, which lets a small frame go: with
        sub edi, [rbp+C_ACK]    ; that, a full window sends three segments at a time, and
        cmp ecx, edi            ; as many frames a second as without any of this.)
        jae .go
        mov ecx, [TXEND]
        sub ecx, eax
        cmp ecx, edx
        ja .pa
.go:    call sendrun
        jmp .pl
.pd:    jnz .pa
        test byte [rbp+C_FLG], F_CLOSED
        jz .pa
        call sendseg            ; (and our FIN, if it did not go with the last of it)
.pa:    test byte [rbx+P_EV], E_SENT
        jnz .owed
        test byte [rbx+P_EV], E_ACK
        jz .owed
        xor ecx, ecx            ; nothing went that carries our ack: a bare one
        mov al, 0x10
        mov edx, [rbp+C_SND]
        call ackno
        call tcp_seg
.owed:  mov eax, [TXEND]        ; Is the client owed anything now?
        test byte [rbp+C_FL2], F_FIN
        jz .nf
        cmp eax, [rbp+C_ACK]    ; If all it lacks is our FIN, that was the connection (should
        je .free                ; the FIN get lost, the client's own is told that there is none)
        inc eax
.nf:    cmp eax, [rbp+C_ACK]
        je .ret1
        test byte [rbp+C_FL2], F_ARMED
        jnz .ret1
        call tarm               ; then it waits for an ack, and not for ever
.ret1:  ret

        ; The client lacks the end of what we sent, from its ack on. If a response is on
        ; its way, `.tx` sees to it. Otherwise what we sent is our flight, or on port 80
        ; the same response for every request: built again and sent, all the client lacks.
.resend:
        call sm
        jnc .lres
        mov al, E_DUP
        test byte [rbx+P_FL], 1
        jnz .lost
        jrcxz .ev
.lost:  mov al, E_RTO | E_ACK
.ev:    or [rbx+P_EV], al
        jmp .tx
.lres:  count 4
        mov edi, OB
        mov eax, [rbp+C_SND]
        sub eax, [rbx+P_ACK]    ; so many bytes (our FIN, if it lacks that, is not one)
        test byte [rbp+C_FLG], F_CLOSED
        jz .rsz
        dec eax
.rsz:   xor esi, esi
        cmp [rbx+P_PORTS+2], bl
        je .recs
        test eax, eax
        jz .none
        push rbx
        call hsbuf              ; the end of the flight, which is in the handshake buffer,
        jc .resetp              ; unless that has gone to another connection since
        mov esi, [rbx+HS_FLEN]
        sub esi, eax
        jb .ret0p               ; (more than we ever sent)
        lea esi, [rbx+rsi+HS_FL]
        xchg eax, ecx
        rep movsb
        pop rbx
        xor esi, esi
        jmp .none
.recs:  mov ecx, P80_LEN        ; port 80: so many responses, the first of them possibly
        mov esi, eax            ; not from its start
        add eax, ecx
        dec eax
        xor edx, edx
        div ecx
        push rax
        imul eax, ecx
        sub eax, esi
        xchg eax, esi           ; esi = how much of the first one the client has
        pop rcx
        jrcxz .none
.again: cmp edi, OB + OBMAX - P80_LEN
        ja .none                ; (as many as there is room for)
        call respond
        loop .again
.none:  add esi, OB
        mov ecx, edi
        sub ecx, esi
        jb .ret0
        mov al, 0x19            ; (after our FIN: that again too)
        test byte [rbp+C_FLG], F_CLOSED
        jnz .rs
        mov al, 0x18
        jrcxz .ret0
.rs:    mov edx, [rbx+P_ACK]
        call tcp_send
.ret0:  ret
.ret0p: pop rbx
        ret
.resetp: pop rbx
.reset: mov al, 4               ; we can't go on with this connection: say so and forget it
        mov edx, [rbp+C_SND]
        xor ecx, ecx
        xor edi, edi
        call tcp_seg
        jmp .free

; sm: CF if connection rbp is a TLS one whose client has had our flight: what it gets from
; then on is cut from the response in hand (`tcp.tx`)
sm:     cmp byte [abs P_PORTS+2], 0
        je .no
        cmp dword [rbp+C_ST], 0
        je .no
        push rax
        mov eax, [rbp+C_ACK]
        sub eax, [rbp+C_RS]
        not eax
        add eax, eax
        pop rax
.no:    ret

; ackno: edi = what we acknowledge to the client of connection rbp
ackno:  mov edi, [rbp+C_NXT]
        test byte [rbp+C_FLG], F_DEFER
        jz .all
        dec edi
.all:   ret

; geom: the response connection rbp has in hand, and how it is cut: a segment has TXM bytes
; (the client's choice, see MSSTAB), and holds one record, of which TXP bytes are the
; response's. The response is the TXL bytes at TXBLOB (or only their head), goes in TXN
; records, and its last byte has the sequence number before TXEND. Keeps all registers.
geom:   pushad
        movzx eax, byte [rbp+C_FLG]
        shr eax, 2
        and eax, 3
        movzx ecx, word [MSSTAB+rax*2]
        mov [TXM], ecx
        sub ecx, 22             ; (a record's header, the byte that says what it holds, its tag)
        mov [TXP], ecx
        movzx eax, word [rbp+C_AS]
        mov esi, eax
        and esi, 0x7FFF
        shl esi, 4
        add esi, SITE + AT_OFF  ; where it is, its length, its head's length
        mov edx, [rsi]
        add edx, SITE
        mov [TXBLOB], edx
        add ax, ax              ; (only the head?)
        mov eax, [rsi+4]
        jnc .all
        mov eax, [rsi+8]
.all:   mov [TXL], eax
        lea eax, [rax+rcx-1]
        xor edx, edx
        div ecx
        mov [TXN], eax
        imul eax, eax, 22
        add eax, [TXL]
        add eax, [rbp+C_RS]
        mov [TXEND], eax
        popad
        ret

; sendseg: the segment of the response in hand (`geom`) that begins with sequence number
; eax goes out: the record that byte is in, from that byte on; behind the response's last
; byte, our FIN, if the connection is closed. C_SND moves on if this is further than we
; had sent. Keeps all registers.
sendseg:
        pushad
        mov edi, eax
        sub eax, [rbp+C_RS]     ; how far into the response's bytes on the wire that is
        mov ecx, [TXEND]
        mov edx, ecx
        sub ecx, [rbp+C_RS]
        cmp eax, ecx
        jb .data
        mov edi, edx            ; behind them: nothing but our FIN can go
        xor ecx, ecx
        push 1
        pop rsi                 ; (and nothing of a frame of our own: see `.seg`)
        mov al, 0x10
        test byte [rbp+C_FLG], F_CLOSED
        jnz .close
        popad
        ret
.data:  xor edx, edx
        div dword [TXM]         ; eax = which record, edx = how far into it
        push rdx
        push rdi
        mov esi, eax
        imul esi, [TXP]         ; the response's bytes before that record,
        mov ecx, [TXL]
        sub ecx, esi            ; and from it on: a record's worth of them
        cmp ecx, [TXP]
        jbe .n
        mov ecx, [TXP]
.n:     add esi, [TXBLOB]
        add eax, [rbp+C_SR]
        xchg eax, edx           ; the record's number
        lea rbx, [rbp+C_KIV]
        mov edi, OB
        mov al, 23              ; (what it holds: application data)
        clc
        call seal
        pop rdx                 ; the sequence number
        pop rsi
        mov ecx, edi
        sub ecx, OB
        sub ecx, esi            ; so many bytes go,
        add esi, OB
.fl:    lea edi, [rdx+rcx]      ; and up to here
        mov al, 0x10
        cmp edi, [TXEND]
        jne .go
        mov al, 0x18            ; (the last of it: push)
        test byte [rbp+C_FLG], F_CLOSED
        jz .go
.close: or al, 1                ; our FIN, which takes a number too
        or byte [rbp+C_FL2], F_FIN
        inc edi
.go:    push rdi                ; C_SND moves on if this is further. (Sequence numbers go
        sub edi, [rbp+C_SND]    ; round: which of two is further says the sign of their
        dec edi                 ; difference, not a comparison. A `jle` here stopped a
        pop rdi                 ; response for ever where it crossed 2^31.)
        js .seg
        mov [rbp+C_SND], edi
.seg:   call ackno
        test esi, esi
        jnz .one
        call tcp_big            ; (many records in a frame of our own, from `sendrun`: the
        call txkick             ; device is told at once, there is a round trip's worth in it)
        jmp .sent
.one:   call tcp_seg
.sent:  or byte [abs P_EV], E_SENT
        popad
        ret

; sendrun: more of the response in hand goes out, from eax = C_SND on. If the card cuts
; frames into segments for us (TSO): all the records that begin before TXLIM, which is as
; far as the client takes it for now, up to as many as a frame of 64 KiB holds, in one
; frame. A record is a segment, so the card cuts where we would have, and what is lost on
; the way is one record, made again as ever (`sendseg`). If it does not, or there is only
; one record to go: `sendseg`. Keeps all registers.
sendrun:
        cmp byte [TSO], 0
        je sendseg
        pushad
        mov ecx, [TXM]
        mov esi, eax            ; From here on:
        mov eax, [TXLIM]
        sub eax, esi            ; what the client takes for now,
        mov edx, BIGPAY + 1
        sub edx, ecx
        cmp eax, edx
        cmova eax, edx          ; or what a frame holds,
        dec eax
        xor edx, edx
        div ecx
        inc eax
        imul eax, ecx           ; in whole records,
        mov edx, [TXEND]
        sub edx, esi
        cmp eax, edx
        cmova eax, edx          ; or what is left of the response
        cmp eax, ecx
        ja .many
        popad                   ; (one record: as ever)
        jmp sendseg
.many:  push rax                ; (so many bytes)
        call txbig              ; ebx = a frame of this processor's own
        mov eax, [rbp+C_SND]
        sub eax, [rbp+C_RS]
        xor edx, edx
        div ecx                 ; The first of them is this record of the response (we
        mov esi, eax            ; send whole records: C_SND is where one begins),
        imul esi, [TXP]
        add esi, [TXBLOB]       ; its bytes are here,
        add eax, [rbp+C_SR]
        xchg eax, edx           ; and this is its number
        lea edi, [rbx+54]
        pop rcx
        push rbx
        add ecx, edi
        push rcx                ; (where the frame will end)
        lea rbx, [rbp+C_KIV]
.rec:   mov ecx, [rsp]
        sub ecx, edi            ; What is left to fill: a record of it,
        mov eax, [TXM]
        cmp ecx, eax
        cmova ecx, eax
        sub ecx, 22             ; of which so many bytes are the response's
        mov al, 23
        clc
        call seal               ; (edi moves on)
        add esi, ecx
        inc edx
        call bdrain             ; (a frame of records takes its time: what comes in meanwhile
        cmp edi, [rsp]          ; goes on to the rings)
        jb .rec
        pop rcx
        pop rbx                 ; The frame,
        sub ecx, ebx
        sub ecx, 54             ; how many bytes lie in it,
        mov edx, [rbp+C_SND]    ; and their sequence number
        xor esi, esi            ; (nothing is to be copied)
        jmp sendseg.fl

; record: one record from the client of connection rbp, at rsi (edx bytes with its header).
; If it is not what the client's next record would be under its key, it is nothing to us:
; the client's Finished (which has other keys), anything forged, anything a second time.
; If it is, it counts. And if it is a request, the response it asks for becomes the one in
; hand (see `tcp.tx`): for GET and HEAD the one the site has for the path, or the one
; that says there is none; for what else begins like a request, the one that says no and
; closes the connection. CF: that can't be yet, because the client has not acknowledged
; all of the response before: the record is then to be taken as not arrived. Keeps all
; registers.
record: pushad
        cmp byte [rsi], 23      ; application data: what everything encrypted says it is
        jne .no
        lea ecx, [rdx-21]       ; what it holds, between its header and its tag
        test ecx, ecx
        jle .no
        add esi, 5
        lea rbx, [rbp+C_KIV+44] ; the client's key,
        mov edx, [rbp+C_ST]
        dec edx                 ; and the number this record must have
        mov edi, VB
        stc
        call seal               ; VB = what it says, and behind that the tag it should have:
        movdqu xmm0, [rdi-16]   ; all 16 bytes are looked at, whatever they are
        movdqu xmm1, [rsi+rcx]
        pxor xmm0, xmm1
        ptest xmm0, xmm0
        jne .no
        mov esi, VB             ; It is the client's. Behind what it says comes the byte that
.pad:   dec ecx                 ; says what that is, and after it there may be zeros
        js .count
        cmp byte [rsi+rcx], 0
        je .pad
        cmp byte [rsi+rcx], 23
        jne .count              ; (an alert: the client is leaving)
        xor ebx, ebx
        cmp dword [rsi], "GET "
        je .get
        cmp dword [rsi], "HEAD"
        jne .other
        cmp byte [rsi+4], ' '
        jne .other
        mov bh, 0x80            ; (only the head)
        inc esi
        dec ecx
.get:   add esi, 4
        sub ecx, 4
        mov edi, 0x811C9DC5     ; The path, up to a space, a question mark or the end, and
        xor edx, edx            ; its hash (FNV-1a)
.pc:    cmp edx, ecx
        jae .pe
        movzx eax, byte [rsi+rdx]
        cmp al, ' '
        jbe .pe
        cmp al, '?'
        je .pe
        xor edi, eax
        imul edi, edi, 0x01000193
        inc edx
        jmp .pc
.pe:    mov r9d, ecx            ; (what is left of the request, the path included)
        mov eax, edi            ; The site's table of paths (tools/pack.py): from the place
.pr:    and eax, PT_MASK        ; the hash names on, until one is empty
        mov ecx, [SITE+rax*8+4]
        jrcxz .nf
        cmp [SITE+rax*8], edi
        jne .nx
        cmp [SITE+rcx+2], dx
        jne .nx
        pushad
        lea edi, [SITE+rcx+4]
        mov ecx, edx
        repe cmpsb
        popad
        je .hit
.nx:    inc eax
        jmp .pr
.hit:   movzx eax, word [SITE+rcx] ; The response for that path. Of its forms, the one for
        add esi, edx            ; this client: the header lines behind the path say which
        mov ecx, r9d
        sub ecx, edx
        call pick
        jmp .have
.other: xor edx, edx            ; Not a request we answer. One that begins like a request
.word:  mov al, [rsi+rdx]       ; (a word in capitals, a space) is told so
        inc edx
        cmp al, ' '
        je .said
        sub al, 'A'
        cmp al, 25
        ja .count
        cmp dl, 8
        jb .word
        jmp .count
.said:  dec edx
        jz .count
        mov eax, A_405
        jmp .have
.nf:    mov eax, A_404
.have:  or eax, ebx
        call geom               ; Has the client all of the response before?
        mov ecx, [TXEND]
        cmp ecx, [rbp+C_ACK]
        jne .wait
        mov ecx, [TXN]
        add [rbp+C_SR], ecx     ; The new one's records are numbered on from its,
        mov [rbp+C_AS], ax
        mov ecx, [rbp+C_SND]
        mov [rbp+C_RS], ecx     ; and it begins where we are
        and byte [rbp+C_FLG], ~F_DUP3
        cmp byte [rbp+C_CW], WIN ; (and it starts with no fewer segments on their way
        jae .win                ; than any connection may start with,
        mov byte [rbp+C_CW], WIN
.win:   cmp byte [rbp+C_CW], 44 ; and no more than 64 KB of them, whatever the one before
        jbe .w44                ; got to: all at once, they would be lost in heaps)
        mov byte [rbp+C_CW], 44
.w44:   and eax, 0x7FFF
        shl eax, 4
        test byte [SITE+AT_OFF+rax+12], 1
        jnz .last               ; One after which we close. And so we do when our key has
        cmp dword [rbp+C_SR], 1 << KEYLIFE ; sealed 2^24 records: it should not seal more
        jb .count               ; than 2^24.5 (RFC 8446, 5.5; the response in hand may
.last:  or byte [rbp+C_FLG], F_CLOSED ; take 2^22.4), and we have no way to change it
.count: inc dword [rbp+C_ST]
.no:    clc
        popad
        ret
.wait:  stc
        popad
        ret

; pick: the form of response eax that the client who asks for it is to get. A file can be
; in the site several times (tools/pack.py; its flags say how): as it is, and compressed,
; for a client whose Accept-Encoding names the way (brotli before gzip); and behind each
; of these, the answer for a client that has it already: one whose If-None-Match names
; its ETag, which that answer has at a known place. The request's header lines are the ecx
; bytes at rsi. Returns eax. (Header names are looked for at the start of a line, their
; letters small or capital; what a name's line holds is looked through as far as it goes.)
pick:   pushad
        mov ebp, eax
        shl eax, 4
        mov bl, [SITE+AT_OFF+rax+12]
        mov r10d, esi
        mov r11d, ecx
        test bl, 6
        jz .inm
        mov edi, H_AE
        push H_INM - H_AE
        pop rdx
        call .line
        jc .inm
        test bl, 4
        jz .gz
        mov edi, T_BR
        mov dl, 2
        call .tok
        jc .gz
        add ebp, 4
        jmp .inm
.gz:    mov edi, T_GZ
        mov dl, 4
        call .tok
        jc .inm
        inc ebp
        inc ebp
.inm:   test bl, 8
        jz .done
        mov edi, H_INM
        push T_BR - H_INM
        pop rdx
        call .line
        jc .done
        lea eax, [rbp+1]        ; (the "not modified" of the form picked: the ETag in it)
        shl eax, 4
        mov edi, [SITE+AT_OFF+rax]
        add edi, SITE + ETAG_AT
        mov dl, ETAG_LEN
        mov bh, 10
        call seek
        jc .done
        inc ebp
.done:  mov [rsp+48], ebp
        popad
        ret
.line:  mov esi, r10d           ; (rsi, ecx = what follows the header name at rdi, if the
        mov ecx, r11d           ; request has a line that begins with it; else CF)
        mov bh, 0
        jmp seek
.tok:   push rsi                ; (CF unless the line at rsi names the way of compressing
        push rcx                ; at rdi, and not as one it does not want: "q=0")
        mov bh, 10
        call seek
        jc .t
        cmp dword [rsi], ";q=0"
        clc
        jne .t
        stc
.t:     pop rcx
        pop rsi
        ret

; seek: CF unless the edx bytes at rdi are among the ecx bytes at rsi, before a byte bh (a
; line's end; 0: none). The bytes at rsi count with their bit 5 set, so that a letter is
; found small or capital (and a line end as the "*" the header names begin with). If
; found: rsi = behind them, ecx = how many bytes follow. (Clobbers al, r8.)
seek:   cmp ecx, edx
        jb .ret
        xor r8d, r8d
.c:     mov al, [rsi+r8]
        or al, 0x20
        cmp al, [rdi+r8]
        jne .nx
        inc r8d
        cmp r8d, edx
        jb .c
        add esi, edx
        sub ecx, edx
.ret:   ret
.nx:    cmp [rsi], bh
        stc
        je .ret
        inc esi
        dec ecx
        jmp seek

; tarm: connection rbp is owed something: an ack is outstanding, or it has more to get than
; its client takes for now. It joins this processor's queue of such connections, as the
; first 64 bytes of the frame in hand (which say who the client is and how to reach it)
; with, in place of what is of no use in them, the time, the client's ack as it is, and how
; often in a row it has been sent to in vain (TQTRY). `tqrun` looks at them when the
; processor has nothing else to do. A connection is in the queue once (F_ARMED); if the
; queue is full, it does not join, and its next packet tries again.
tarm:   pushad
        mov eax, [TQT]
        mov edx, eax
        sub edx, [TQH]
        cmp edx, [TMMASK]
        ja .full
        call tqslot
        xor esi, esi            ; FR
        push 8
        pop rcx
        rep movsq
        mov edx, [TNOW]
        mov [rax+T_TIME], edx
        mov edx, [rbp+C_ACK]
        mov [rax+T_ACK], edx
        mov dl, [TQTRY]
        mov [rax+T_TRY], dl
        inc dword [TQT]
        or byte [rbp+C_FL2], F_ARMED
.full:  popad
        ret
tqslot: and eax, [TMMASK]
        shl eax, 6
        add eax, [TQB]
        mov edi, eax
        ret

; tqrun: the connection that has been in that queue the longest (if there is one). If it
; has not waited a quarter of a second yet (twice as long for each time it has been sent
; to in vain, up to 16 s), it goes to the back. If it has: its frame
; is put where a frame from its client would be, and if the client then has everything,
; that is that; if its ack has moved since, it joins the queue afresh; if not, what it
; asks for is sent again, as for a client that asks (E_RTO in `tcp.tx`). Only when there
; is nothing else to do: while frames wait in our ring, the client's ack may be one of
; them. And not for ever: after six times in vain, a client from which nothing at all has
; come for a minute or two (C_AGE) is told that its connection is no more, and it is no
; more. (Or every client that vanished in the middle of a response would be sent to every
; 16 s for as long as we are up, and keep one of the queue's 4 n places: with all of them
; taken, nobody's timer runs.) (Clobbers everything.)
tqrun:  mov eax, [TQH]
        cmp eax, [TQT]
        je .none
        inc dword [TQH]
        call tqslot
        xchg eax, esi
        mov edx, [TNOW]         ; (`tidle` has just read the clock)
        sub edx, [rsi+T_TIME]
        mov cl, [rsi+T_TRY]
        shr edx, cl
        push 8
        pop rcx
        cmp edx, 512
        jae .due
        mov eax, [TQT]
        inc dword [TQT]
        call tqslot
        rep movsq
.none:  ret
.due:   xor edi, edi            ; FR
        rep movsq
        xor ebx, ebx
        mov [rbx+P_ADV], ebx
        mov word [rbx+P_MORE], E_RTO << 8
        call find
        jc .none                ; (the connection is no more,
%ifdef RACE
%if RACE = 1
        RACEWAIT [rbp+C_AGE]
%endif
%endif
        call hold               ; or its slot another's by now.) In use from here on, as
        jne .none               ; for a packet of its client's. But this is none: when the
        push rax                ; client was last heard is kept, and put back at the end
%ifdef RACE
%if RACE = 2
        RACEWAIT [rsp]
%endif
%endif
        and byte [rbp+C_FL2], ~F_ARMED
        call sm
        jnc .back               ; (another connection of that client's)
        call geom
        mov eax, [TXEND]
        test byte [rbp+C_FL2], F_FIN
        jz .nf
        inc eax
.nf:    mov edx, [rbp+C_ACK]
        cmp eax, edx
        je .back                ; (it has everything)
        mov cl, [rbx+T_TRY]
        cmp edx, [rbx+T_ACK]
        je .vain
        mov [rbx+P_EV], bl      ; (it is getting on: nothing is sent again)
        mov cl, -1
.vain:  inc ecx
        cmp cl, 6
        jbe .t
        mov cl, 6               ; (16 s at a time from here on.) And a client that has said
        mov al, [NOW]           ; nothing at all for a minute or two while we sent to it in
        sub al, [rsp]           ; vain has gone: that was the connection. (One that takes
        cmp al, 2               ; no more for now, and says so each time it is sent to,
        jb .t                   ; stays.)
        pop rax
        jmp tcp.reset
.t:     mov [TQTRY], cl
        call tcp.tx
        mov byte [TQTRY], 0
.back:  pop rax                 ; The slot, if it still is this connection's (that may have
        call own                ; been its end), says again when its client was last heard:
        jne .kept               ; a slot the timer alone keeps busy is a quiet one, to be
        mov [rbp+C_AGE], al     ; taken when there is no room
.kept:  ret
; The one thing we send unasked: a SYN-ACK again. We keep no connection for a SYN, so a
; lost SYN-ACK costs the client a second, and after that a retransmission timeout of
; seconds for the rest of the connection (it has sent its SYN twice, so it has no round
; trip to go by). Instead the SYNs of late are kept: 4 n places (see TABV), a client's
; picked by its hash, whatever was there is gone. A connection made takes its SYN out
; (`.make`). A polling loop with no frame to handle goes round the places, 8 a turn
; (`tidle`), and a SYN that is still there after a quarter of a second
; goes through `tcp` once more, as if it had just come, three times at most.
; Only then: while frames wait in our ring, the client's answer may be one of them (under
; more load than we can take, they wait longer than that). No more than one such a tick
; (1/2048 s): a flood of SYNs from made-up addresses gets one SYN-ACK each as before,
; and at most two thousand a second on top.
; tnote: keep the SYN in FR, if it is no longer than 120 bytes (they are 74)
tnote:  pushad
        mov ecx, [RXLEN]
        cmp ecx, 120
        ja .no
        movzx eax, byte [TTRY]
        test eax, eax
        jnz .ours
        mov al, 4               ; (the client's own: it may be answered three times more)
.ours:  dec eax
        jz .no
        mov edx, [HKO+12]
        and edx, [TMMASK]
        mov edi, [TMT]
        mov esi, [TNOW]
        or esi, 1
        mov [rdi+rdx*4], esi
        shl edx, 7
        add edx, [TMF]
        mov [rdx], al
        mov [rdx+1], cl
        lea edi, [rdx+8]
        xor esi, esi            ; (FR)
        push 15
        pop rcx
        rep movsq
        mov eax, [rdx+8+P_SEQ]  ; (as it came: `tcp` has turned these two round)
        bswap eax
        mov [rdx+8+P_SEQ], eax
        mov eax, [rdx+8+P_ACK]
        bswap eax
        mov [rdx+8+P_ACK], eax
.no:    popad
        ret

; tidle: the next 8 places of this processor's: a SYN that has waited long enough? Then it
; is answered again (one at most). (Clobbers everything.)
tidle:  call clock
        xchg eax, edx
        push 8
        pop rsi
.next:  mov eax, [abs NCPUM]
        inc eax
        imul eax, [THAND]
        inc dword [THAND]
        add eax, [CPUN]
        and eax, [TMMASK]
        mov edi, [TMT]
        lea rdi, [rdi+rax*4]
        mov ecx, edx
        sub ecx, [rdi]          ; how long it has been there, if anything is (signed: one
        cmp ecx, 512            ; noted this very tick may be a tick ahead)
        jl .young
        cmp dword [rdi], 0
        jne .due
.young: dec esi
        jnz .next
        ret
.due:   cmp edx, [TLAST]
        je .no
        mov [TLAST], edx
        and dword [rdi], 0
        count 4
        shl eax, 7
        add eax, [TMF]
        mov cl, [rax]
        mov [TTRY], cl
        movzx ecx, byte [rax+1]
        mov [RXLEN], ecx
        lea esi, [rax+8]
        xor edi, edi
        push 15
        pop rcx
        rep movsq
        xor ebx, ebx
        movzx ecx, word [rbx+16]
        xchg cl, ch
        sub ecx, 20             ; (as `tcp` has it where the checksum has been found right)
        call tcp.sums
        mov byte [TTRY], 0
.no:    ret

; tsc: rax = 64-bit cycle counter (clobbers rdx)
tsc:    rdtsc
        shl rdx, 32
        or rax, rdx
        ret

; clock: eax (and TNOW) = the time in ticks of 1/2048 s; NOW = in units of 64 s (clobbers rdx)
clock:  call tsc
        mul qword [TSCM]
        mov [TNOW], edx
        mov eax, edx
        shr rdx, 17
        mov [NOW], dl
        ret

; find: ebp = the slot of the connection the packet in FR belongs to. If it has none: CF, and
; ebp = the slot a new one would get, or 0 if there is no room for it.
; A connection is in one of two buckets of BUCKET slots, picked by two words of the keyed
; hash of its address and ports (`prf`; clients can't aim at each other's buckets). A new one
; goes into the bucket with more free slots. If both are full, it takes the place of the
; connection in them that has been quiet for the longest, if that is longer than IDLE (about
; an hour): such a client has probably gone without saying so. If none has, the new one is
; refused.
; The processors take slots from each other, and a slot changes hands in one step: its
; first eight bytes (address, port, flags, C_AGE) become the new connection's if they still
; are as they were seen here (`tcp.make`). The processor whose connection it was says "in
; use" in one step as well, by changing C_AGE, before it does anything else with that
; connection, and then looks whether the slot still is that connection's (`hold`, which
; `tcp` and `tqrun` call after us). So one of the two finds out: the new connection that
; the slot is not as it was, or the old one that it has none.
find:   pushad
        xor esi, esi
        call prf
        movdqa [HKO], xmm0
.again: mov esi, PT             ; the table for port 80,
        push PSLOT
        pop rcx
        cmp byte [abs P_PORTS+2], 0
        je .tab
        mov esi, TT             ; or the one for TLS
        mov cl, TSLOT
.tab:   mov eax, [HKO+4]
        call .where
        push rbp                ; the second bucket
        mov eax, [HKO]
        call .where
        push rbp                ; the first
        mov eax, [abs P_IP]
        mov di, [abs P_PORTS]
        xor esi, esi            ; esi = the slot that has been quiet for longer than bh
        mov bh, IDLE
        call .scan
        mov bl, dl              ; free slots in the first bucket
        mov rbp, [rsp+8]
        call .scan
        pop rax
        pop rbp
        cmp dl, bl
        ja .pick                ; the second has more
        xchg rax, rbp
        mov dl, bl
.pick:  test dl, dl
        jnz .free
        mov rbp, rsi            ; no free slot in either
        jmp .miss
.free:
%ifdef RACE
%if RACE = 3                    ; (make RACE=3, for tools/racetest.py 3: the one free slot that
        test byte [abs P_FL], 2 ; was counted is another's by the time we get to it, as when
        jnz .walk               ; another processor has made a connection there meanwhile:
        cmp dl, 1               ; here a made-up one, and not for a SYN, which takes no slot)
        jne .walk
        push rbp
.gone:  cmp dword [rbp+C_IP], 0
        je .took
        add rbp, rcx
        jmp .gone
.took:  mov dword [rbp+C_IP], 0x0100007F
        pop rbp
.walk:
%endif
%endif
        mov dh, BUCKET          ; The first free slot of that bucket. If there is none any
.f:     mov rax, [rbp]          ; more (another processor has taken what was free when it
        test eax, eax           ; was counted), all of it again: the walk must not go on
        jz .mine                ; into the next bucket, or out of the table
        add rbp, rcx
        dec dh
        jnz .f
        jmp .again
.mine:  mov [CLAIMQ], rax       ; (what is there now: see `.make` in `tcp`)
.miss:  stc
.ret:   mov [rsp+16], rbp
        popad
        ret
.where: mul dword [rsi+8]       ; rbp = the bucket for hash eax: number (hash * buckets) >> 32
        imul rdx, rcx
        shl rdx, 4              ; (* BUCKET)
        add rdx, [rsi]
        mov rbp, rdx
        ret
.scan:  mov edx, BUCKET << 8    ; dh = slots to look at, dl = free ones seen
.s:     cmp [rbp+C_IP], eax
        jne .other
        cmp [rbp+C_PORT], di
        jne .other
        add rsp, 24             ; found (CF = 0): drop the return address and the buckets
        jmp .ret
.other: cmp dword [rbp+C_IP], 0
        jne .used
        inc edx
        jmp .nx
.used:  push rax
        mov rax, [rbp]          ; One look at it: what a new connection then asks for (`.make`
        push rax                ; in `tcp`) is the slot as it was found quiet, to the bit.
        shr rax, 56             ; (its C_AGE)
        sub al, [NOW]
        neg al                  ; How long it has been quiet: longer than the longest so far?
        cmp al, bh              ; (But not all of 255 units: the next packet of its own, a
        jbe .not                ; unit on, would leave C_AGE as it is, and it is by changing
        cmp al, 255             ; C_AGE that its processor says "in use": see `tcp`.)
        je .not
        mov bh, al
        mov rsi, rbp
        pop qword [CLAIMQ]
        jmp short .young
.not:   pop rax
.young: pop rax
.nx:    add rbp, rcx
        dec dh
        jnz .s
        ret

; hold: the slot at rbp, which `find` says is the connection's whose packet is in FR, is in
; use from here on: its C_AGE says now, and al = what it said (when the client was last
; heard). ZF unless the slot is another connection's by now.
; This is the owner's half of how a slot changes hands between processors (`find` has the
; taker's): before anything is done with a connection, for a packet of its client's or
; because its timer has run (`tqrun`), its processor says "in use", in one step (xchg), by
; changing one of the eight bytes a taker asks for. They are then not as a taker saw them,
; and it gets nothing; and whoever looks from now on sees a slot that is not quiet. Then,
; in one look, whether the slot still is this connection's: if a taker was quicker, there
; is no connection, and the packet is as good as lost.
; own: only that look. (ebx = 0; both clobber rdi.)
hold:   mov al, [NOW]
        xchg [rbp+C_AGE], al
own:    mov rdi, [rbp]
        cmp edi, [rbx+P_IP]
        jne .no
        shr rdi, 32
        cmp di, [rbx+P_PORTS]
.no:    ret

; prf: xmm0 = a keyed hash of the client's address and ports (and ours: twelve bytes of the
; frame at rsi; `find` keeps it in HKO): eleven rounds of AES, as the processor has them, with round keys that are simply
; random, made at boot (HKS). Its four words pick the two buckets (0, 1), make the cookie
; (2: W) and place a segment kept for later (3). (Clobbers esi and ecx.)
prf:    movdqu xmm0, [rsi+P_IP-FR]  ; the addresses and ports, and four bytes behind them
        pslldq xmm0, 4          ; that go again
        mov esi, HKS
        pxor xmm0, [rsi]
        push 10
        pop rcx
.r:     add esi, 16
        aesenc xmm0, [rsi]
        loop .r
        ret

; ckx: eax = 0 (and ZF) if the packet is the first after a SYN-ACK of ours: its ack is the
; cookie for its sequence number (see `.syn`). Bits HINT of eax are 0 if it acknowledges a
; SYN-ACK of ours at all.
ckx:    push rdx                ; (ebx = 0)
        mov eax, [rbx+P_SEQ]
        dec eax
        shl eax, 14
        xor eax, [HKO+8]
%ifdef ISNTOP                   ; (test builds: as `.syn` made it)
        and eax, ISNLOW
        or eax, ISNTOP & ~ISNLOW
%endif
        mov edx, [rbx+P_ACK]
        dec edx
        xor eax, edx
        and eax, -64            ; (the low six bits are what the SYN-ACK noted, not W)
        pop rdx
        ret

; respond: what port 80 says to every request (tools/pack.py: the page at /, or where to go
; instead), at edi, which moves on. (ebx = 0)
respond:
        push rsi
        push rcx
        mov esi, SITE + P80_OFF
        mov ecx, P80_LEN
        rep movsb
%ifdef DEBUG
        pushad
        mov al, [abs NCPUM]     ; (the first two digits: how many processors take frames,
        shl al, 4               ; less 1, and which one this is)
        or al, [CPUN]
        mov [DBG+1], al
        mov eax, [DBG+24]       ; (counter 1: cycles per frame)
        mov edx, [DBG+28]
        div dword [DBG+32]
        mov [DBG+4], eax
%if DEBUG > 1                   ; (make DEBUG=2: how busy, in place of counters 3 and 5)
        mov eax, [DBG+36]
        shr eax, 12
        mov [DBG+12], eax
        rdtsc
        shrd eax, edx, 24
        mov [DBG+20], eax
%endif
        dec edi                 ; (the page ends with a line end)
        mov esi, DBG + 24
        std
.dc:    sub esi, 4
        mov edx, [rsi]
        mov cl, 4
.dd:    mov al, dl
        and al, 15
        cmp al, 10              ; hex digit
        jb .dg
        add al, 7
.dg:    add al, '0'
        dec edi
        mov [rdi], al
        shr edx, 4
        loop .dd
        cmp esi, DBG
        ja .dc
        cld
        popad
%endif
        pop rcx
        pop rsi
        ret

; oohold: keep the segment in hand (ecx bytes at esi, sequence number P_SEQ, FIN or not)
; until what comes before it is here (`.reply` in `tcp`). There are n places (TABV) for such
; segments; a client's place is picked by its hash, and whatever was there is gone, unless
; it is an earlier segment of the same client.
oohold: pushad                  ; (ebx = 0)
        call ooent
        mov eax, [rbx+P_SEQ]
        jne .fill
        cmp eax, [rdx+OO_SEQ]
        jns .ret                ; the one kept comes first
.fill:  mov [rdx+OO_SEQ], eax
        mov eax, [HKO+12]
        mov [rdx+OO_TAG], eax
        mov [rdx+OO_LEN], ecx
        mov al, [rbx+P_FL]
        and al, 1
        mov [rdx+OO_FIN], al
        lea edi, [rdx+OO_DATA]
        rep movsb
.ret:   popad
        ret

; ooent: edx = the client's place for a segment kept for later; ZF if what is there is its own
ooent:  push rax
        mov eax, [HKO+12]
        mov edx, eax
        and edx, [HSMASK]
        shl edx, 11
        add edx, [OOBASE]
        cmp [rdx+OO_TAG], eax
        pop rax
        ret

; hsbuf: ebx = the handshake buffer of connection ebp; CF if it has none (any more)
hsbuf:  movzx ebx, word [rbp+C_HS]
        dec ebx
        js .none
        shl ebx, HS_SHIFT
        add ebx, HSP
        cmp [rbx+HS_OWNER], rbp
        je .ok
.none:  stc
.ok:    ret

; hsnew: ebx = a handshake buffer for connection rbp: the next in a circle that is not in
; use, which is to say: whose owner's slot no longer names it (the slot lets go of it when
; the client has the flight, and so does a slot that is given to another connection). If
; 16 in a row are in use, the 16th is taken all the same: its owner's ClientHello, if that
; was arriving in pieces, is then never finished, and its flight can't be sent a second time.
hsnew:  push rax
        push rcx
        push 16
        pop rcx
.t:     mov eax, [abs NCPUM]    ; (every processor has its own: one in so many)
        inc eax
        imul eax, [HSNEXT]
        inc dword [HSNEXT]
        add eax, [CPUN]
        and eax, [HSMASK]
        mov ebx, eax
        shl ebx, HS_SHIFT
        add ebx, HSP
        inc eax                 ; (what C_HS calls it)
        mov r8, [rbx+HS_OWNER]
        test r8, r8
        jz .take
        cmp [r8+C_HS], ax
        jne .take
        cmp dword [r8+C_IP], 0
        loopne .t
.take:  mov [rbx+HS_OWNER], rbp
        and dword [rbx+HS_FLEN], 0
        mov [rbp+C_HS], ax
        pop rcx
        pop rax
        ret

; tcp_send: ecx bytes at esi to the client of connection ebp, in segments, from our sequence
; number edx; flags al on the last. If it takes several segments, none of them acknowledges
; the last byte the client sent: the client then keeps sending that byte until it has all
; of the answer, whichever part gets lost, and it is acknowledged when its ack says so
; (F_DEFER, in `tcp`). Not when we close: then there is no later.
; (It was "none acknowledges what this packet brought". But an answer that goes out again
; because of a duplicate ack is sent for a packet that brought nothing: its segments then
; acknowledged everything, and if the one that filled the hole was lost again, and the
; client's next duplicate ack too, nobody had anything left to send. 1 handshake in 8,000
; at 3% loss with a flight of two segments.)
tcp_send:
        pushad
        movzx ebx, byte [rbp+C_FLG]
        shr ebx, 2
        and ebx, 3
        movzx ebx, word [MSSTAB+rbx*2]
        mov edi, [rbp+C_NXT]
        and byte [rbp+C_FLG], ~F_DEFER
        cmp ecx, ebx
        jbe .last
        test al, 1
        jnz .seg
        dec edi
        or byte [rbp+C_FLG], F_DEFER
.seg:   push rax
        push rcx
        mov ecx, ebx
        mov al, 0x10
        call tcp_seg
        pop rcx
        pop rax
        add esi, ebx
        add edx, ebx
        sub ecx, ebx
        cmp ecx, ebx
        ja .seg
.last:  call tcp_seg
        popad
        ret

; tcp_seg: send one segment to the sender of the frame in FR: ecx bytes at esi, flags al,
; sequence number edx, ack edi.
; tcp_big: the same for ecx bytes that lie in a frame of the caller's own already (`txbig`:
; at ebx, behind the place of the headers), and are more than a segment: the card cuts them
; into segments of TXM bytes, gives each these headers (the flags to the last), and sums
; each. (r8: the caller's frame, or 0.)
tcp_big: mov r8d, ebx
        jmp tcp_seg.in
tcp_seg: xor r8d, r8d
.in:    pushad
        mov ebp, ecx            ; payload length
        call txbuf              ; ebx = a frame for it; and the ring is ours until `txgo`
        test r8d, r8d
        cmovnz ebx, r8d
        bswap edx
        mov [rbx+38], edx
        bswap edi
        mov [rbx+42], edi
        mov dl, 0x50
        test al, 2
        jz .nopt
        lea edx, [rdx+rcx*4]    ; (a SYN's "payload" is its options: so much longer its header)
.nopt:  mov [rbx+46], dl
        mov [rbx+47], al
        xor eax, eax
        mov [rbx+50], eax       ; checksum (for now), nothing urgent
        dec eax
        mov [rbx+48], ax        ; window: we take whatever comes, at once
        test r8d, r8d
        jnz .hdr
        lea edi, [rbx+54]
        rep movsb
        mov [rdi], cl           ; zero pad byte for an odd length checksum
.hdr:   mov edi, ebx
        call ethhdr
        mov eax, 0x00450008     ; IPv4, a header of 20 bytes, nothing special
        stosd
        scasw                   ; (the length: below)
        mov eax, 0x00400000     ; no id: never to be fragmented
        stosd
        lea eax, [rbp+20]       ; where TTL, protocol and checksum go, first the rest of the
        xchg al, ah             ; pseudo header: 0, protocol, TCP length; the addresses follow
        shl eax, 16
        mov ah, 6
        stosd
        mov eax, OURIP
        stosd
        mov eax, [abs P_IP]
        stosd
        mov eax, [abs P_PORTS]
        rol eax, 16
        stosd
        lea esi, [rbx+22]
        lea ecx, [rbp+32]
        test r8d, r8d
        jz .sum
        ; A frame for the card to cut up. The 12 bytes in front of it say so: its sums are
        ; to be made (1), it is TCP segments over IPv4 (1) behind 54 bytes of headers, TXM
        ; bytes each; a sum covers what follows byte 34 and goes 16 bytes behind that.
        ; Where the sum goes we put what is ours to add: the pseudo header's, as it is.
        mov dword [rbx-12], 0x00360101
        mov eax, [TXM]
        mov [rbx-8], ax
        mov dword [rbx-6], 0x00100022
        push 12
        pop rcx
        call csum
        not eax
        jmp .sumd
.sum:   call csum
.sumd:  mov [rbx+50], ax
        lea ecx, [rbp+40]
        xchg cl, ch
        mov [rbx+16], cx        ; IP total length
        mov dword [rbx+22], 0x0640 ; TTL 64, TCP, checksum 0
        lea esi, [rbx+14]
        push 20
        pop rcx
        call csum
        mov [rbx+24], ax
        lea ecx, [rbp+54]
        call txgo
        popad
        ret

; csum: eax = internet checksum of ecx bytes at esi (clobbers ecx, edx, esi).
; dec leaves CF alone, so the end-around carry rides through the loop in adc.
csum:
        xor edx, edx
.l:     lodsw
        adc dx, ax
        dec ecx
        dec ecx
        jg .l
        adc dx, 0
        not edx
        xchg eax, edx
        ret

; ----------------------------------------------------------------------------
; handshake: ClientHello message at rsi (ecx bytes), connection at rbp.
; Writes ServerHello + encrypted flight to OB, returns edi = end. Clobbers all but rbp.
handshake:
        push rbp
        push rcx                ; (the ClientHello's length)
        movzx edx, byte [rsi+38] ; session id length
        lea eax, [rsi+rdx+41]   ; behind it the cipher suites (two bytes each), after their
        lea r8d, [rsi+rcx]      ; length, which counts as far as the ClientHello goes
        movzx ecx, word [rax-2]
        xchg cl, ch
        or edi, -1              ; Ours, 13 01 (AES-128-GCM), among the client's: SUITE is
        sub r8d, eax            ; 0 if it names it, -1 if not
        jbe .cse
        cmp ecx, r8d
        jbe .csn
        mov ecx, r8d
.csn:   shr ecx, 1
        jz .cse
.cs:    cmp word [rax], 0x0113
        je .cs1
        inc eax
        inc eax
        loop .cs
        jmp .cse
.cs1:   inc edi
.cse:   mov [SUITE], edi
        pop rcx
        mov edi, TR             ; The transcript. If this is the ClientHello we asked for
        test byte [rbp+C_FL2], F_HRR ; (below), it begins with what stands for the first
        jz .ch                  ; one, its hash, and with our request, which is made again
        mov eax, 0x200000FE     ; from this one (the two have the same session id and suites)
        stosd
        push rsi
        push rcx
        lea rsi, [rbp+C_KIV]
        push 4
        pop rcx
        rep movsq
        mov rsi, [rsp+8]
        call hrrmsg
        pop rcx
        pop rsi
.ch:    mov r10d, edi           ; the ClientHello
        push rsi
        rep movsb
        pop rsi
        mov ebx, edi            ; the ServerHello goes here
        ; What the client offers. Behind the session id, the cipher suites and the
        ; compression methods come the extensions: type, length, data (two bytes each for
        ; the first two). Three matter: the versions (43: TLS 1.3 must be among them), the
        ; groups (10: is x25519 among them?) and the key shares (51: group, length, key;
        ; ours is group 29 with 32 bytes). Every length is the client's: an extension
        ; counts if all of it lies inside the ClientHello, and what is looked at inside
        ; one lies inside that extension. (The key share was once found by searching for
        ; the four bytes 00 1d 00 20. A client's other key shares are a kilobyte of
        ; random-looking bytes these days: once in two million handshakes they held those
        ; four.)
        push rsi
        xor edx, edx            ; dl, bit 0: TLS 1.3 is offered, bit 1: x25519 is
        xor r11d, r11d          ; where the x25519 key share is (0: nowhere)
        lea edi, [r10+38]
        movzx ecx, byte [rdi]   ; session id (these two lengths are within reach in any case:
        lea edi, [rdi+rcx+1]    ; the transcript has room for a ClientHello of any size)
        movzx ecx, word [rdi]
        xchg cl, ch             ; cipher suites
        lea edi, [rdi+rcx+2]
        cmp edi, ebx
        jae .seen
        movzx ecx, byte [rdi]   ; compression methods, and the extensions' length
        lea edi, [rdi+rcx+3]
.ext:   lea esi, [rdi+4]
        cmp esi, ebx
        ja .seen
        movzx eax, word [rdi+2]
        xchg al, ah
        add esi, eax            ; where this extension ends
        cmp esi, ebx
        ja .seen
        movzx ecx, word [rdi]   ; which it is
        add edi, 5              ; The versions (after a length of one byte): is TLS 1.3
        mov ax, 0x0403          ; among them?
        mov dh, 1
        cmp cx, 0x2b00
        je .list
        inc edi                 ; The groups (after a length of two bytes): is x25519?
        mov ax, 0x1d00
        mov dh, 2
        cmp cx, 0x0a00
        je .list
        cmp cx, 0x3300
        jne .nxt
.ks:    lea eax, [rdi+36]       ; The key shares: group, length, key
        cmp eax, esi
        ja .nxt
        cmp dword [rdi], 0x20001d00 ; (x25519, 32 bytes)
        jne .nks
        mov r11d, edi
.nks:   movzx eax, word [rdi+2]
        xchg al, ah
        lea edi, [rdi+rax+4]
        jmp .ks
.list:  lea ecx, [rdi+2]        ; (is the word ax among the words up to the extension's end?)
        cmp ecx, esi
        ja .nxt
        cmp [rdi], ax
        mov edi, ecx
        jne .list
        or dl, dh
.nxt:   mov edi, esi
        jmp .ext
        ; A client we can't serve is told so, and that is the connection: one that has no
        ; TLS 1.3 (an alert "protocol version"), one that does not name our cipher suite,
        ; one that has no x25519, or sent no share for it after being asked ("handshake
        ; failure"). It gets nothing that only looks like an answer.
.seen:  pop rsi
        mov al, 70
        test dl, 1
        jz .alert
        mov al, 40
        cmp dword [SUITE], 0
        jl .alert
        test r11d, r11d
        jnz .has
        test byte [rbp+C_FL2], F_HRR
        jnz .alert
        test dl, 2
        jnz .ask
.alert: mov edi, OB
        mov dword [rdi], 0x00030315 ; an alert record of two bytes:
        mov word [rdi+4], 0x0202 ;  fatal,
        mov [rdi+6], al         ;   and why
        add edi, 7
        or byte [rbp+C_FLG], F_CLOSED ; (our FIN goes with it: `tcp.fin`)
        pop rbp
        ret
        ; No share for x25519, but the client has it: it is asked for a ClientHello with
        ; one (a HelloRetryRequest, which is all of our flight this time). The connection
        ; goes on waiting for a ClientHello, and keeps, where its keys will be, the hash of
        ; this one: the transcript has that in its place.
.ask:   or byte [rbp+C_FL2], F_HRR
        dec dword [rbp+C_ST]
        push rsi
        mov esi, r10d
        mov ecx, ebx
        sub ecx, esi
        lea rdi, [rbp+C_KIV]
        call sha256
        pop rsi
        mov edi, OB
        mov dword [rdi], 0x00030316
        add edi, 5
        call hrrmsg
        mov eax, edi
        sub eax, OB + 5
        xchg al, ah
        mov [OB+3], ax
        pop rbp
        ret
.has:   mov eax, r11d
        push rax                ; (the key is 4 bytes on from there)
        push rsi
        mov esi, HT             ; the transcript's hash starts over
        mov edi, TSH
        push 8
        pop rcx
        rep movsd
        mov dword [TPOS], TR
        pop rsi
        mov edi, E              ; a fresh secret: our X25519 scalar
        mov cl, 4
        call rand
        movzx edx, byte [rsi+38] ; session id length
        mov edi, ebx
        lea ecx, [rdx+39]
        rep movsb               ; ServerHello: as the ClientHello up to its session id,
        lea edi, [rbx+6]
        mov cl, 4
        call rand               ; but with a random of our own, ...
        lea edi, [rbx+rdx+39]
        mov esi, SHTAIL
        mov cl, 19
        rep movsb               ; ... + suite, extensions, key share header ...
        pop rsi
        lodsd
        call xdh                ; ... + our key share; R_X = the shared secret
        lea eax, [rdx+86]
        shl eax, 24
        mov al, 2
        mov [rbx], eax          ; type 2, length

        mov ebp, SLOTS + 128    ; key schedule: what comes before the shared secret is the
        push rbx                ; same every time (boot made it)
        lea ebx, [rbp+S_D1]
        mov esi, R_X
        mov cl, 32
        mov edi, ebp
        call hmac               ; handshake secret
        pop rbx
        lea eax, [rbx+rdx+90]   ; P1 = end of ServerHello
        call thash
        push rbx
        push rdx
        mov ebx, ebp
        mov esi, L_SHTS
        lea edx, [rbp+S_TH]
        lea edi, [rbp+S_TS]
        call expand             ; server handshake traffic secret
        pop rdx
        pop rbx
        xchg eax, edi           ; EncryptedExtensions + Certificate
        mov esi, EECERT
        mov ecx, EECERT_LEN
        rep movsb
        xchg eax, edi           ; eax = P2
        call thash
        push rax
        mov edi, CVB            ; CertificateVerify content: 64 spaces | context | hash
        mov al, 0x20
        mov cl, 64
        rep stosb
        mov esi, CVCTX
        mov cl, 34
        rep movsb
        lea esi, [rbp+S_TH]
        mov cl, 32
        rep movsb
        mov esi, CVB
        mov cl, 130
        call sha256             ; the hash to sign (behind the content)
        mov esi, edi
        call sign               ; r and s
        pop rsi                 ; P2. The CertificateVerify message: 0f 00 00 n+6 | 04 03 |
        lea edi, [rsi+10]       ; 00 n+2 | 30 n | r | s, the two as DER INTEGERs (n bytes)
        push rsi
        mov esi, R_X
        call derint
        add esi, 32
        call derint
        pop rsi
        mov eax, edi
        sub eax, esi
        sub eax, 10
        mov dword [rsi], 0x0F
        mov dword [rsi+4], 0x0304
        mov byte [rsi+8], 0x30
        mov [rsi+9], al
        add al, 2
        mov [rsi+7], al
        add al, 4
        mov [rsi+3], al
        xchg eax, edi           ; eax = P3 = end of CertificateVerify

        mov edi, OB             ; ServerHello record
        mov dword [rdi], 0x00030316
        lea ecx, [rdx+90]
        mov [rdi+4], cl
        add edi, 5
        mov esi, ebx
        rep movsb
        push rsi                ; P1 = end of ServerHello = start of the encrypted part
        push rdi                ; output position
        lea ebx, [rbp+S_TS]
        mov edi, KH
        call keys               ; handshake key and iv

        mov esi, L_FIN
        xor edx, edx
        lea edi, [rbp+S_D]
        call expand
        mov ebx, edi            ; finished key
        call thash
        xchg eax, edi
        mov eax, 0x20000014
        stosd
        lea esi, [rbp+S_TH]
        mov cl, 32              ; (ecx = 0 after the copy above)
        call hmac
        add edi, ecx
        xchg eax, edi           ; eax = the end of the transcript so far

        pop rdi                 ; output position
        pop rsi                 ; P1
        mov ecx, eax
        sub ecx, esi
        mov ebx, KH
        push rax
        mov al, 0x16            ; what the record holds: handshake messages
        xor edx, edx            ; (its number; and CF = 0: encrypt)
        call seal               ; edi = end of output
        pop rax

        call thash              ; application traffic secret
        push rdi
        mov ebx, ebp
        mov esi, L_DER
        lea edx, [rbp+S_EH]
        lea edi, [rbp+S_D]
        call expand
        mov ebx, edi
        lea esi, [rbp+S_Z]
        push 32
        pop rcx
        lea edi, [rbp+S_ES]
        call hmac               ; master secret
        mov ebx, edi
        mov esi, L_CATS
        lea edx, [rbp+S_TH]
        lea edi, [rbp+S_D]
        call expand             ; client application traffic secret
        mov ecx, edi
        mov esi, L_SATS
        lea edi, [rbp+S_TS]
        call expand             ; server application traffic secret
        mov ebx, edi
        pop rax                 ; end of output
        pop rbp
        mov edi, KA
        call keys
        mov ebx, ecx
        add edi, 44
        call keys
        mov esi, KA             ; (`keys` writes 20 bytes too many: not into the connection)
        lea rdi, [rbp+C_KIV]
        push 22
        pop rcx
        rep movsd
        and byte [rbp+C_FL2], 0xF0 ; (the window's shift stays)
        xchg eax, edi
        ret

; hrrmsg: a HelloRetryRequest for the ClientHello at rsi, to rdi (which moves on): a
; ServerHello as we make them, as that ClientHello up to its session id, but with the
; random that says what it is, SHA-256("HelloRetryRequest"), and after our cipher suite, of
; the key share only the group we want one for. (Clobbers eax, ecx, edx.)
hrrmsg: push rsi
        movzx edx, byte [rsi+38]
        lea ecx, [rdx+39]
        mov eax, edi
        rep movsb
        add edx, 52
        shl edx, 24
        mov dl, 2
        mov [rax], edx          ; type 2, length
        push rdi
        lea edi, [rax+6]
        mov esi, L_HRR
        push 17
        pop rcx
        call sha256
        pop rdi
        mov esi, SHTAIL
        rep movsb               ; (17 of its 19 bytes: no key follows)
        mov byte [rdi-13], 12   ; twelve bytes of extensions,
        mov byte [rdi-3], 2     ; two of key share
        pop rsi
        ret

; derint: the 32-byte number at rsi (little-endian) as a DER INTEGER to rdi, which moves on:
; no more bytes than it takes, and a zero byte in front if the first has its top bit set
; (clobbers eax, ecx)
derint: push 32
        pop rcx
.z:     cmp byte [rsi+rcx-1], 0
        jne .nz
        loop .z
        inc ecx
.nz:    mov al, 2
        stosb
        mov al, cl
        test byte [rsi+rcx-1], 0x80
        jz .len
        inc eax
        stosb
        mov al, 0
.len:   stosb
.b:     mov al, [rsi+rcx-1]
        stosb
        loop .b
        ret

; thash: TH slot = SHA256(transcript up to eax). The transcript is hashed as it grows:
; TSH is its state after the whole blocks before TPOS, and each call takes in the whole
; blocks that have come since, then finishes a copy of that state.
thash:
        pushad
        mov edx, eax
        sub edx, TR             ; the transcript's length
        mov esi, [TPOS]
        mov ecx, eax
        sub ecx, esi
        push rcx
        push rdx
        shr ecx, 6
        mov edi, TSH
        call shablk
        mov [TPOS], esi
        push rsi
        mov esi, edi
        mov edi, SH
        push 8
        pop rcx
        rep movsd
        pop rsi
        pop rdx
        pop rcx
        and ecx, 63
        call shaend
        mov rbp, [rsp+16]
        lea edi, [rbp+S_TH]
        call shaout
        popad
        ret
%endif

; keys: edi = key | iv from traffic secret ebx: 32 bytes of key (of which AES-128 uses
; 16), 12 of iv (+20 junk bytes: expand writes 32)
keys:
        pushad
        xor edx, edx
        mov esi, L_KEY
        call expand
        add edi, 32
        mov esi, L_IV
        call expand
        popad
        ret

; ----------------------------------------------------------------------------
; sha256: edi = SHA-256 of ecx bytes at esi (which are left alone)
sha256:
        pushad
        push rdi
        push rsi
        push rcx
        mov esi, HT
        mov edi, SH
        push 8
        pop rcx
        rep movsd
        pop rcx
        pop rsi
        mov edx, ecx
        call shaend
        pop rdi
        call shaout
        popad
        ret

; shaout: the hash whose state is at SH to edi (clobbers eax, ecx, esi; edi moves on)
shaout: mov esi, SH
        push 8
        pop rcx
.o:     lodsd
        bswap eax
        stosd
        loop .o
        ret

; shaend: the state at SH takes in the ecx bytes at rsi, which end a message of edx bytes: the
; whole blocks of them, then what is left with the padding (0x80, zeros, the length in
; bits), made in PADB. Clobbers all registers.
shaend: push rdx
        push rcx
        shr ecx, 6
        mov edi, SH
        call shablk
        pop rcx
        and ecx, 63
        mov edi, PADB
        rep movsb
        mov al, 0x80
        stosb
        lea ecx, [rdi+8+63-PADB] ; one block, or two if the length doesn't fit the first
        shr ecx, 6
        mov esi, ecx
        shl ecx, 6
        add ecx, PADB - 8
        sub ecx, edi
        xor eax, eax
        rep stosb
        pop rax
        shl rax, 3
        bswap rax
        stosq
        mov ecx, esi
        mov esi, PADB
        mov edi, SH
        ; fall through
        HOT 0x00FC00E4
; shablk: the state at rdi (8 dwords) takes in the ecx blocks of 64 bytes at rsi (rsi moves
; on; ecx may be 0). Clobbers rax, rcx, rdx, rbx, rbp, r8-r15.
; a-h are eax ebx ecx edx r8d-r11d; the 64 words of the message schedule are on the stack.
shablk: test ecx, ecx
        jz .ret
.blk:   push rcx
        sub rsp, 256
        mov eax, [rdi]
        mov ebx, [rdi+4]
        mov ecx, [rdi+8]
        mov edx, [rdi+12]
        mov r8d, [rdi+16]
        mov r9d, [rdi+20]
        mov r10d, [rdi+24]
        mov r11d, [rdi+28]
        xor r15d, r15d          ; round
.rnd:   cmp r15d, 16
        jae .sch
        mov r12d, [rsi+r15*4]
        bswap r12d
        jmp .w
.sch:   mov r12d, [rsp+r15*4-8] ; s1(w[i-2]) + w[i-7] + s0(w[i-15]) + w[i-16]
        rorx r13d, r12d, 17
        rorx r14d, r12d, 19
        xor r13d, r14d
        shr r12d, 10
        xor r12d, r13d
        add r12d, [rsp+r15*4-28]
        mov r13d, [rsp+r15*4-60]
        rorx r14d, r13d, 7
        rorx ebp, r13d, 18
        xor r14d, ebp
        shr r13d, 3
        xor r14d, r13d
        add r12d, r14d
        add r12d, [rsp+r15*4-64]
.w:     mov [rsp+r15*4], r12d
        add r12d, [KT+r15*4]
        add r12d, r11d          ; h + k + w
        rorx r13d, r8d, 6
        rorx r14d, r8d, 11
        xor r13d, r14d
        rorx r14d, r8d, 25
        xor r13d, r14d
        add r12d, r13d          ; + S1(e)
        mov r13d, r10d
        xor r13d, r9d
        and r13d, r8d
        xor r13d, r10d
        add r12d, r13d          ; + ch(e, f, g): t1
        rorx r13d, eax, 2
        rorx r14d, eax, 13
        xor r13d, r14d
        rorx r14d, eax, 22
        xor r13d, r14d          ; S0(a)
        mov r14d, eax
        xor r14d, ebx
        mov ebp, ebx
        xor ebp, ecx
        and r14d, ebp
        xor r14d, ebx           ; maj(a, b, c) = ((a ^ b) & (b ^ c)) ^ b
        add r13d, r14d          ; t2
        mov r11d, r10d
        mov r10d, r9d
        mov r9d, r8d
        lea r8d, [rdx+r12]      ; e = d + t1
        mov edx, ecx
        mov ecx, ebx
        mov ebx, eax
        lea eax, [r12+r13]      ; a = t1 + t2
        inc r15d
        cmp r15b, 64
        jb .rnd
        add rsp, 256
        add [rdi], eax
        add [rdi+4], ebx
        add [rdi+8], ecx
        add [rdi+12], edx
        add [rdi+16], r8d
        add [rdi+20], r9d
        add [rdi+24], r10d
        add [rdi+28], r11d
        add rsi, 64
        pop rcx
        dec ecx
        jnz .blk
.ret:   ret

; hmac: edi = HMAC-SHA256(key = 32 bytes at ebx, ecx <= 64 bytes at esi)
hmac:
        pushad
        push rdi
        push rcx
        mov edi, HB+64
        rep movsb
        mov esi, ebx
        mov edi, HB
        mov cl, 64
.k:     xor eax, eax
        cmp cl, 32
        jbe .z
        lodsb
.z:     xor al, 0x36
        stosb
        loop .k
        pop rcx
        add ecx, 64
        mov esi, HB
        lea edi, [rsi+64]
        call sha256             ; inner hash
        mov cl, 64
.o:     xor byte [HB+rcx-1], 0x36 ^ 0x5c
        loop .o
        mov cl, 96
        pop rdi
        call sha256             ; outer hash
        popad
        ret

; expand: edi = HKDF-Expand-Label(secret ebx, label esi = {L, len, text}, context edx or 0), 32 bytes
expand:
        pushad
        push rdi
        mov edi, INFO
        mov al, 0
        stosb
        movsb                   ; output length
        lodsb
        add al, 6
        stosb
        push rsi
        mov esi, TLS13
        movsd
        movsw
        pop rsi
        sub al, 6
        movzx ecx, al
        rep movsb
        xor eax, eax
        test edx, edx
        jz .e
        mov al, 32
.e:     stosb
        jz .n
        mov esi, edx
        xchg eax, ecx
        rep movsb
.n:     mov al, 1
        stosb
        lea ecx, [rdi-INFO]
        mov esi, INFO
        pop rdi
        call hmac
        popad
        ret

; ----------------------------------------------------------------------------
; Elliptic curves: 256-bit arithmetic mod m in four limbs of 64 bits, weakly reduced, in a
; 16-register machine. tools/ec.py has the programs, the bounds that make this safe, and a
; model of all of it. rbp points at the field in use (F_...; all three are built at boot).
; None of this branches on, or indexes with, anything secret.
R_E0    equ REGS + 0*32         ; a table entry lands here; the client's u; the hash to sign
R_E1    equ REGS + 1*32         ; our public key after xdh's XPOST
R_X     equ REGS + 3*32         ; the point at hand; the shared secret; r after `sign`
R_Y     equ REGS + 4*32         ; s after `sign`
R_Z     equ REGS + 5*32
R_T0    equ REGS + 7*32
R_T1    equ REGS + 8*32
R_ONE   equ REGS + 12*32
R_A24   equ REGS + 13*32
R_D     equ REGS + 14*32
R_C     equ REGS + 15*32

        HOT 0x00FFE0C0
; xdh: our X25519 key share for the secret E to rdi (which moves on 32 bytes), and R_X = the
; secret we share with the client whose key share is at rsi. E is used as it is, unclamped:
; the other side only needs it to be the same number in our share and in the secret.
; Our share is E times the base point: 64 additions from the table TABE. The secret is E
; times the client's point: the ladder. Both end in a division, which they share.
; (Keeps the eight old registers, as do `sign` and the hashes: r8-r15 are scratch.)
xdh:    pushad
        mov ebp, F25519
        push rdi
        push rsi
        mov esi, X_INITED
        call vm
        mov esi, TABE
        push 96
        pop rcx
        mov edx, X_MADDED
        mov ebx, E
        call comb
        mov esi, X_KEYED
        call vm
        pop rsi
        mov edi, R_E0
        push 4
        pop rcx
        rep movsq               ; the client's u,
        and byte [rdi-1], 0x7F  ; which has 255 bits (RFC 7748)
        mov esi, X_INIT25519
        call vm
        xor edx, edx            ; The ladder, from the top bit down. The two points change
        mov ecx, 255            ; places when a bit differs from the one before it.
.l:     test cl, 63
        jnz .step
        call bdrain             ; (four times on the way: see `drain`)
.step:  xor eax, eax
        bt [E], ecx
        adc eax, eax
        push rax
        push rcx
        xor edx, eax
        call cswap
        mov esi, X_STEP25519
        call vm
        pop rcx
        pop rdx
        dec ecx
        jns .l
        call cswap
        mov esi, X_XPRE
        call vm
        push rsi                ; (XPOST follows XPRE)
        mov esi, R_T0
        call inv
        pop rsi
        call vm
        pop rdi
        mov esi, R_E1
        call freeze
        mov [rsp], rdi
        mov edi, R_X
        mov esi, edi
        call freeze
        popad
        ret

        HOT 0x7FFFFFFC
; cswap: swap (X, Y) with (Z, T) if edx = 1, not if edx = 0 (clobbers rax, rcx, rdx, rdi)
cswap:  neg rdx
        mov edi, R_X
        push 8
        pop rcx
.s:     mov rax, [rdi]
        xor rax, [rdi+64]
        and rax, rdx
        xor [rdi], rax
        xor [rdi+64], rax
        scasq
        loop .s
        ret

; freeze: the number at rsi (four limbs, below 2^256) mod 2^255 - 19, to rdi (which moves on)
freeze: mov r8, [rsi]
        mov r9, [rsi+8]
        mov r10, [rsi+16]
        mov r11, [rsi+24]
        mov rax, r11            ; bit 255 is worth 19
        shr rax, 63
        imul eax, eax, 19
        btr r11, 63
        add r8, rax
        adc r9, 0
        adc r10, 0
        adc r11, 0              ; below 2^255 + 19 now. If that plus 19 reaches 2^255, it was
        mov rax, r8             ; 2^255 - 19 or more, and that sum less 2^255 is the answer
        mov rcx, r9
        mov rdx, r10
        mov r12, r11
        add rax, 19
        adc rcx, 0
        adc rdx, 0
        adc r12, 0
        btr r12, 63
        cmovc r8, rax
        cmovc r9, rcx
        cmovc r10, rdx
        cmovc r11, r12
        ; fall through
; put4: the four limbs r8-r11 to rdi (which moves on)
put4:    mov [rdi], r8
        mov [rdi+8], r9
        mov [rdi+16], r10
        mov [rdi+24], r11
        add rdi, 32
        ret

; sign: an ECDSA signature of the 32-byte hash at rsi under our key: r to R_X, s = (hash +
; r d) / k to R_Y, both canonical. The half that needs no hash, r = x(k G) and 1 / k for a
; fresh random nonce k, is taken from a stock that `stock` makes: each is used once.
sign:   pushad
        push rsi
.more:  mov eax, [POOLN]
        test eax, eax
        jnz .have
        call stock
        call bdrain
        jmp .more
.have:  dec eax
        mov [POOLN], eax
        shl eax, 5
        lea esi, [rax+POOLR]
        mov edi, R_X
        push 4
        pop rcx
        rep movsq
        lea esi, [rax+POOLK]
        mov edi, R_T1
        mov cl, 4
        rep movsq
        mov ebp, FN256
        pop rsi
        mov edi, R_E0
        mov cl, 32              ; the hash as a number
.rev:   mov al, [rsi+rcx-1]
        stosb
        loop .rev
        mov esi, X_SIGN
        call vm
        popad
        ret

; rand: ecx times 64 random bits to rdi (which moves on), from the processor's generator:
; every secret there is but the key in the image. (Clobbers rax; ecx = 0 after.) Each is
; compared with the one before it. A generator that says the same twice is stuck, and then
; this is the machine's end: every nonce would be the same, which gives the key away. (It
; has happened: processors were sold in 2019 whose rdrand said all ones every time, and
; that this was a success. The first draw is compared with zero, which is what a generator
; stuck there would say.)
rand:   rdrand rax
        jnc rand
%ifdef WXTEST
%if WXTEST = 8                  ; (make WXTEST=8, for tools/wxtest.sh: a generator that is
        or rax, -1              ; stuck the way those were)
%endif
%endif
        cmp rax, [RLAST]
        je .stuck
        mov [RLAST], rax
        stosq
        loop rand
        ret
.stuck: ud2

; stock: one step towards the next NPOOL nonces k with their r = x(k G) (POOLR) and R^2 / k
; (POOLK): either one more k and its k G, or, when all are there, the divisions: two for
; all of them (`binv`). The polling loop does a step whenever it has nothing else to do and
; the stock is empty, `sign` as many as it takes. Clobbers everything.
; k G is 64 additions from the table TABP, which holds (j + 1) 16^i G: starting from 2^255 G
; (an entry itself), for the nibbles of k - 2^255 - 0x1111...1 (ec.py says why). k is 256
; random bits, whatever number that is.
stock:  mov ebx, [POOLFILL]
        cmp ebx, NPOOL * 32
        je .all
        lea edi, [rbx+POOLK]
        push 4
        pop rcx
        call rand
%ifdef HOST
        mov al, [HKSET]         ; (the tests choose the nonce that is used first: HKSET = 1;
        mov esi, HK             ; or all of them: 2, and then they are at HK in the order
        cmp al, 2               ; they are made in, the one used first last)
        jne .one
        add esi, ebx
        jmp .mine
.one:   cmp ebx, (NPOOL - 1) * 32
        jne .k
        test al, al
        jz .k
.mine:  lea edi, [rbx+POOLK]
        mov cl, 4
        rep movsq
.k:
%endif
        add dword [POOLFILL], 32
        push rbx
        mov ebp, FN256
        lea esi, [rbx+POOLK]
        mov edi, KD
        mov ebx, KOFFV
        inc ecx
        call fas
        mov ebp, FP256
        mov esi, TABP + (63 * 16 + 7) * 64
        mov edi, R_E0
        push 8
        pop rcx
        rep movsq
        mov esi, X_INIT256
        call vm
        mov esi, TABP
        push 64
        pop rcx
        mov edx, X_MADD256
        mov ebx, KD
        call comb
        pop rbx
        lea edi, [rbx+POOLR]    ; X and Z of k G: r = X / Z^2 is still to come
        mov esi, R_X
        push 4
        pop rcx
        rep movsq
        lea edi, [rbx+POOLZ]
        mov esi, R_Z
        mov cl, 4
        rep movsq
        ret
.all:   mov ebp, FP256
        mov ebx, POOLZ
        call binv
        xor ebx, ebx
.r:     push rbx
        lea esi, [rbx+POOLZ]
        mov edi, R_T1
        push 4
        pop rcx
        rep movsq
        lea esi, [rbx+POOLR]
        mov edi, R_X
        mov cl, 4
        rep movsq
        mov esi, X_FIN256
        call vm
        pop rbx
        lea edi, [rbx+POOLR]
        mov esi, R_X
        push 4
        pop rcx
        rep movsq
        add ebx, 32
        cmp ebx, NPOOL * 32
        jb .r
        mov ebp, FN256
        mov ebx, POOLK
        call binv
        mov dword [POOLN], NPOOL
        and dword [POOLFILL], 0
        ret

; binv: each of the NPOOL numbers at rbx (four limbs) becomes what `inv` makes of it in the
; field at rbp, with one `inv` for all: of their product (Montgomery's trick). POOLP gets
; the products of the first 1, 2, 3, ... of them; then, from the last one down, the
; inverse of the product so far times the product of those before is that one's inverse,
; and times the number itself the inverse of the product before. Clobbers everything.
binv:   mov esi, ebx
        mov edi, POOLP
        push 4
        pop rcx
        rep movsq
        mov ebx, esi
.f:     lea rsi, [rdi-32]
        call fmul
        add ebx, 32
        add edi, 32
        cmp edi, POOLP + NPOOL * 32
        jb .f
        lea esi, [rdi-32]
        push rbx
        call inv
        pop rbx
        mov edx, POOLP + (NPOOL - 1) * 32
.b:     sub ebx, 32
        sub edx, 32
        push rbx
        push rdx
        mov ebx, edx
        mov edi, R_T0
        mov esi, R_T1
        call fmul
        mov rbx, [rsp+8]
        mov edi, R_T1
        mov esi, edi
        call fmul
        mov edi, ebx
        mov esi, R_T0
        push 4
        pop rcx
        rep movsq
        pop rdx
        pop rbx
        cmp edx, POOLP
        ja .b
        lea edi, [rbx-32]
        mov esi, R_T1
        push 4
        pop rcx
        rep movsq
        ret

        HOT 0xE0F80E0F
; comb: to the point in X.. are added, for i = 0 .. 63, entry number (nibble i of the 32 bytes
; at rbx) of the 16 entries (ecx bytes each) of window i of the table at rsi, each by the
; program at rdx. Clobbers all but rbp.
comb:   xor eax, eax
.w:     push rax
        push rdx
        push rbx
        mov edx, eax
        shr edx, 1
        movzx edx, byte [rbx+rdx]
        test al, 1              ; (which nibble of the byte: no secret)
        jz .lo
        shr edx, 4
.lo:    and edx, 15
        call select             ; (leaves rsi at the next window)
        push rsi
        push rcx
        mov rsi, [rsp+24]
        call vm
        pop rcx
        pop rsi
        pop rbx
        pop rdx
        pop rax
        inc eax
        cmp al, 64
        jb .w
        ret

        HOT 0xFFE1F8FF
; select: entry number edx of the 16 entries (ecx bytes each, a multiple of 16) at rsi to the
; registers from E0 on. All 16 are read, and what is kept is picked with masks: which one it
; was shows neither in time nor in what the cache holds. rsi moves on past the 16; clobbers
; rax, rdx, rdi, xmm0-xmm4.
select: mov edi, REGS
        push rcx
        xor eax, eax
        rep stosb
        pop rcx
        mov edi, REGS
        movd xmm0, edx
        pshufd xmm0, xmm0, 0    ; the number wanted
        pxor xmm1, xmm1         ; the number of the entry at hand
        pcmpeqd xmm2, xmm2
        psrld xmm2, 31          ; 1
        mov dl, 16
.e:     movdqa xmm3, xmm1
        pcmpeqd xmm3, xmm0      ; all ones for the one wanted
        xor eax, eax
.c:     movdqa xmm4, [rsi]
        pand xmm4, xmm3
        por xmm4, [rdi+rax]
        movdqa [rdi+rax], xmm4
        add rsi, 16
        add eax, 16
        cmp eax, ecx
        jb .c
        paddd xmm1, xmm2
        dec dl
        jnz .e
        ret

        HOT 0x40F70000
; vm: run the program at rsi in the field at rbp. Returns rsi = after the program; clobbers
; all else but rbp. In the image a program is 2 bytes per operation (a << 4 | b, op << 4 |
; dst; a zero byte ends it: tools/ec.py); what runs is what boot made of that (`ecinit`,
; from XP on, X_name for each): the three registers' addresses and the operation less 1,
; a dword each, and a zero dword to end it.
vm:     mov edi, [rsi]
        test edi, edi
        jz .end
        mov ebx, [rsi+8]
        mov ecx, [rsi+12]       ; 0 add, 1 subtract, 2 multiply
        push rsi
        mov esi, [rsi+4]
        cmp ecx, 2
        je .mul
        call fas
        jmp .next
.mul:   call fmul
.next:  pop rsi
        add rsi, 16
        jmp vm
.end:   add rsi, 4
        ret

        HOT 0xF9FFC3FE
; fas: the four limbs at rdi = those at rsi + those at rbx if ecx = 0, minus them if ecx = 1,
; in the field at rbp: weakly reduced, as its operands are. (Clobbers rax, rcx, rdx, rsi,
; r8-r15.) If the sum left [0, 2^256) (a carry adding, a borrow subtracting), M is taken
; off, which is adding 2^256 - M, or put back; and once more if that was not enough,
; which shows in the carry of that correction (ec.py: it can take two). Both corrected
; values are made whatever the case, and one of the three is kept.
fas:    mov r8, [rsi]
        mov r9, [rsi+8]
        mov r10, [rsi+16]
        mov r11, [rsi+24]
        mov rdx, rbp            ; (2^256 - M, to add)
        test ecx, ecx
        jnz .sub
        add r8, [rbx]
        adc r9, [rbx+8]
        adc r10, [rbx+16]
        adc r11, [rbx+24]
        jmp .fix
.sub:   sub r8, [rbx]
        sbb r9, [rbx+8]
        sbb r10, [rbx+16]
        sbb r11, [rbx+24]
        lea rdx, [rbp+F_M]
.fix:   sbb eax, eax            ; -1: out of range
        mov r12, r8
        mov r13, r9
        mov r14, r10
        mov r15, r11
        add r12, [rdx]
        adc r13, [rdx+8]
        adc r14, [rdx+16]
        adc r15, [rdx+24]
        sbb esi, esi            ; that correction's carry: adding, it says "still too much",
        neg ecx                 ; subtracting, "enough"
        xor esi, ecx
        test eax, eax
        cmovnz r8, r12
        cmovnz r9, r13
        cmovnz r10, r14
        cmovnz r11, r15
        add r12, [rdx]
        adc r13, [rdx+8]
        adc r14, [rdx+16]
        adc r15, [rdx+24]
        and eax, esi
        cmovnz r8, r12
        cmovnz r9, r13
        cmovnz r10, r14
        cmovnz r11, r15
        mov [rdi], r8
        mov [rdi+8], r9
        mov [rdi+16], r10
        mov [rdi+24], r11
        ret

; fmul: the four limbs at rdi = those at rsi times those at rbx in the field at rbp: mod
; 2^255 - 19, or divided by 2^256 mod M for the Montgomery fields; below 2^256 either way.
; (Clobbers rax, rcx, rdx, rsi, r8-r15.)
; ROW: %5:%4:%3:%2:%1 = %4:%3:%2:%1 + rdx * the four limbs at rsi, with two chains of
; carries at once (adcx, adox); %5 is not looked at before. (Clobbers rax, rcx.)
%macro ROW 5
        xor %5, %5
        mulx rcx, rax, [rsi]
        adcx %1, rax
        adox %2, rcx
        mulx rcx, rax, [rsi+8]
        adcx %2, rax
        adox %3, rcx
        mulx rcx, rax, [rsi+16]
        adcx %3, rax
        adox %4, rcx
        mulx rcx, rax, [rsi+24]
        adcx %4, rax
        adox %5, rcx
        adc %5, 0
%endmacro
        HOT 0xCF07FE0F
fmul:   mov r13, rsi
        mov rsi, rbx
        mov rdx, [r13]          ; the product, eight limbs, a row for each limb of the one
        mulx r9, r8, [rsi]      ; factor: r8 r9 r10 r11 | r12 r14 r15 r13
        mulx r10, rax, [rsi+8]
        add r9, rax
        mulx r11, rax, [rsi+16]
        adc r10, rax
        mulx r12, rax, [rsi+24]
        adc r11, rax
        adc r12, 0
        mov rdx, [r13+8]
        ROW r9, r10, r11, r12, r14
        mov rdx, [r13+16]
        ROW r10, r11, r12, r14, r15
        mov rdx, [r13+24]
        ROW r11, r12, r14, r15, r13
        mov rdx, [rbp+F_INV]
        test rdx, rdx
        jnz .mont
        mov dl, 38              ; 2^255 - 19: what is above 2^256 counts 38 times,
        xor eax, eax
        mulx rcx, rax, r12
        adcx r8, rax
        adox r9, rcx
        mulx rcx, rax, r14
        adcx r9, rax
        adox r10, rcx
        mulx rcx, rax, r15
        adcx r10, rax
        adox r11, rcx
        mulx rcx, rax, r13
        adcx r11, rax
        mov eax, 0
        adox rcx, rax
        adcx rcx, rax
        imul ecx, ecx, 38       ; and so does what that brought above it,
        add r8, rcx
        adc r9, rax
        adc r10, rax
        adc r11, rax
        sbb eax, eax            ; and the last carry (to a number that is small now)
        and eax, 38
        add r8, rax
        jmp .done
.mont:  push r13                ; Montgomery: four times, add the multiple of M that makes
        push r15                ; the lowest limb zero, and drop that limb (the high half
        push r14                ; comes in from the stack, a limb at a time)
        push r12
        lea rsi, [rbp+F_M]
        xor r14d, r14d          ; (the carry out of the top)
        mov r15b, 4
.r:     mov rdx, r8
        imul rdx, [rbp+F_INV]
        ROW r8, r9, r10, r11, r12
        mov r8, r9
        mov r9, r10
        mov r10, r11
        pop r11
        xor eax, eax
        add r12, r14
        adc eax, eax
        add r11, r12
        adc eax, 0
        mov r14d, eax
        dec r15b
        jnz .r
        neg r14                 ; below 2^256 + M: if it left 2^256, take M off
        mov r12, [rbp]
        mov r13, [rbp+8]
        mov r15, [rbp+24]
        and r12, r14
        and r13, r14
        and r15, r14
        and r14, [rbp+16]
        add r8, r12
        adc r9, r13
        adc r10, r14
        adc r11, r15
.done:  mov [rdi], r8
        mov [rdi+8], r9
        mov [rdi+16], r10
        mov [rdi+24], r11
        ret

        HOT 0x07CFF071
; inv: T1 = (the four limbs at rsi) ^ (m - 2) in the field at rbp: the inverse, or for a
; Montgomery field R^2 / it of a raw number, 1 / it of a stored one. Clobbers T0 and all
; registers but rbp. (The exponent is no secret.)
inv:    mov edi, R_T0
        push 4
        pop rcx
        rep movsq               ; T0 = x
        lea rsi, [rdi-32]
        mov cl, 4
        rep movsq               ; T1 = x (bit 0 of m - 2 is set)
        inc ecx                 ; bit 1
.l:     push rcx
        mov edi, R_T0
        mov esi, edi
        mov ebx, edi
        call fmul               ; T0 = T0^2
        pop rcx
        bt [rbp+F_EXP], ecx
        jnc .s
        push rcx
        mov edi, R_T1
        mov esi, edi
        call fmul               ; T1 = T1 * T0
        pop rcx
.s:     inc cl
        jnz .l
        ret

; ecinit (boot): the three fields, the constant registers and the two tables.
; A field is: 2^256 - M | M | -1/M mod 2^64 (0 for 2^255 - 19, which is reduced its own
; way and has M = 2^256 - 38, twice the prime) | m - 2, the exponent that inverts.
ecinit: mov edi, BSWAPM         ; (and what GHASH needs: how pshufb reverses 16 bytes)
        mov al, 15
.bs:    stosb
        dec al
        jns .bs
        mov esi, INIT25519      ; the programs, unpacked for `vm`: they follow each other
        mov edi, XP             ; in the image
        mov dl, NPROG
.op:    lodsb
        movzx ebx, al
        test ebx, ebx
        jz .pe
        lodsb
        movzx ecx, al
        call .reg               ; dst,
        mov eax, ebx
        shr eax, 4
        call .reg               ; a,
        xchg eax, ebx
        call .reg               ; b,
        xchg eax, ecx
        shr eax, 4
        dec eax
        stosd                   ; and what to do with them
        jmp .op
.pe:    xchg eax, ebx
        stosd
        dec dl
        jnz .op
        mov edi, F25519 + F_M
        or rax, -1
        push 4
        pop rcx
        rep stosq
        mov byte [rdi-32], -38
        add edi, FSIZE - 32     ; p of P-256: 2^64 - 1, 2^32 - 1, 0, 2^64 - 2^32 + 1
        stosq
        mov eax, eax
        stosq
        scasq
        neg rax
        stosq
        inc byte [rdi]          ; (-1/p = 1)
        add edi, FSIZE - 32     ; n of P-256: its low half is data, then 2^64 - 1, 2^64 - 2^32
        mov esi, NLOW
        movsq
        movsq
        or rax, -1
        stosq
        shl rax, 32
        stosq
        movsq                   ; (-1/n)
        mov edi, F25519
        mov bl, 3
.f:     xor edx, edx            ; for each: 2^256 - M and M - 2
        mov cl, 4
        stc
.n:     mov rax, [rdi+F_M+rdx*8]
        mov [rdi+F_EXP+rdx*8], rax
        not rax
        adc rax, 0
        mov [rdi+rdx*8], rax
        inc edx
        loop .n
        sub byte [rdi+F_EXP], 2
        add edi, FSIZE
        dec bl
        jnz .f
        mov byte [F25519+F_EXP], -21 ; (not 2^256 - 40 but 2^255 - 21)
        mov byte [F25519+F_EXP+31], 0x7F
        mov edi, KOFFV          ; what a nonce loses before its nibbles are looked up
        mov al, 0x11
        mov cl, 32
        rep stosb
        mov byte [rdi-1], 0x91
        inc byte [R_ONE]
        mov dword [R_A24], 121665
        ; The table for edwards25519: window i has j 16^i B for j = 0 .. 15, as
        ; (y + x, y - x, 2 d x y). One row is: the point 16^i B as such an entry in E0-E2,
        ; then 16 times: the sum so far to the table, and that point added to it.
        mov ebp, F25519
        mov edi, R_X            ; X, Y, Z = B (Z = 1), then our key's D, then C = 2 d
        mov cl, 8               ; (esi = EDC, after NLOW)
        rep movsq
        inc byte [rdi]
        mov edi, R_D
        mov cl, 8
        rep movsq
        mov edi, TABE
        mov bl, 64
.erow:  push rdi
        mov edi, R_E0
        call .epre
        pop rdi
        mov esi, X_INITED
        call .vm
        mov bh, 16
.eent:  call .epre
        mov esi, X_MADDED
        call .vm
        dec bh
        jnz .eent
        dec bl
        jnz .erow
        ; The table for P-256: window i has (j + 1) 16^i G for j = 0 .. 15, as (x, y) times R.
        ; One row is: 16 times the sum so far to the table, and 16^i G added to it (the
        ; first time that is a doubling, the last time it is left out).
        mov ebp, FP256
        mov esi, ebp            ; C = R mod p = 2^256 - p
        mov edi, R_C
        push 4                  ; (the multiplications leave nothing of rcx)
        pop rcx
        rep movsq
        mov esi, REGC           ; G
        mov edi, R_E0
        mov cl, 8
        rep movsq
        mov esi, X_INIT256
        call vm
        mov edi, TABP
        mov bl, 64
.prow:  mov bh, 16
.pent:  mov esi, X_TOAFF
        call .conv
        mov esi, R_T0
        cmp bh, 16
        jne .pcp
        push rdi
        mov edi, R_E0           ; (the first of a row is what the others add)
        push 8
        pop rcx
        rep movsq
        pop rdi
        mov esi, R_T0
.pcp:   push 8
        pop rcx
        rep movsq
        mov esi, X_DBL256
        cmp bh, 16
        je .pgo
        mov esi, X_MADD256
        cmp bh, 1
        je .pno
.pgo:   call .vm
.pno:   dec bh
        jnz .pent
        dec bl
        jnz .prow
        ret
; (the point in X.. as a table entry of edwards25519 to rdi, which moves on)
.epre:  mov esi, X_TOPRE
        call .conv
        mov esi, R_T0
        push 12
        pop rcx
        rep movsq
        ret
; (a register's address, for its number in the low four bits of eax, to edi, which moves on)
.reg:   and eax, 15
        shl eax, 5
        add eax, REGS
        stosd
        ret
; (T1 = 1 / Z, then the program at rsi; keeps rdi and rbx, as .vm does)
.conv:  push rsi
        push rdi
        push rbx
        mov esi, R_Z
        call inv
        pop rbx
        pop rdi
        pop rsi
.vm:    push rdi
        push rbx
        call vm
        pop rbx
        pop rdi
        ret

%ifdef HOST
bdrain: ret                     ; (the tests have no device)
echost: pushad                  ; (for the tests: C wants its registers back)
        call ecinit
        popad
        ret
; (for test/bench.c: one operation, or one program, in the field number ecx)
        global hfmul, hfas, hfsub, hvm, hinv, F25519, HK, HKSET, POOLN, hstock, HAAD, HAADN
HK      equ BSS + 0x18000       ; (nonces for the signatures after the next `stock`: see there)
HKSET   equ HK + NPOOL * 32
HAAD    equ HKSET + 16          ; (16 bytes to make a tag over in place of a record's header,
HAADN   equ HAAD + 16           ; if HAADN is not 0: then so many of them count, less 1)
; haad (`seal`, before it makes the tag of the ebp blocks at rsi; rax = where the lengths
; are): Wycheproof's vectors for AES-128-GCM have data of their own where a record has
; its header, or none: then the header's block is not part of what is hashed.
haad:   movzx edx, byte [HAADN]
        dec edx
        js .no
        jnz .some
        add esi, 16
        dec ebp
.some:  movdqu xmm5, [HAAD]
        movdqa [SB], xmm5
        shl edx, 3
        mov [rax+7], dl
.no:    ret
hstock: pushad
        call stock
        popad
        ret
hfield: imul ebp, ecx, FSIZE
        add ebp, F25519
        ret
hfmul:  pushad
        call hfield
        call fmul
        popad
        ret
hfas:   pushad
        call hfield
        xor ecx, ecx
        call fas
        popad
        ret
hfsub:  pushad
        call hfield
        push 1
        pop rcx
        call fas
        popad
        ret
hvm:    pushad
        call hfield
        call vm
        popad
        ret
hinv:   pushad
        call hfield
        call inv
        popad
        ret
%endif

; ----------------------------------------------------------------------------
        HOT 0xE0000007
; seal: a TLS 1.3 record at rdi for the ecx bytes at rsi and, behind them inside it, the
; byte al that says what they are, under AES-128-GCM; key | iv at rbx (the key's 16
; bytes, 16 more, and 12), number edx. Returns rdi = the record's end.
; With CF set it is the other way round: the ecx bytes at rsi are what a record held between
; its header and its tag. They are decrypted to rdi, and behind them goes the tag that
; record should have had, for the caller to compare (rdi = behind that).
; A key stream 64 bytes at a time, xored straight onto what was given, and a tag over
; header | ciphertext | lengths, lined up in SB.
seal:   pushad
        sbb r12, r12            ; -1: decrypt (what we were given is the ciphertext)
        bswap edx               ; (the number goes on the nonce's last four bytes)
        mov edi, NB             ; the counter block: iv ^ number | counter
        mov rax, [rbx+32]
        stosq
        mov eax, [rbx+40]
        xor eax, edx
        stosd
        mov eax, 0x01000000     ; 1 for the tag, then 2, 3, ... (big-endian)
        stosd
        mov rsi, rbx
        call aeskey
        movdqa xmm7, [BSWAPM]
        movdqa xmm1, [NB]
        movdqa xmm4, xmm1
        pshufb xmm4, xmm7       ; reversed: the counter is a plain dword at the bottom
        push 1
        pop rax
        movd xmm0, eax
        paddd xmm4, xmm0        ; 2, for the first block of key stream
        pxor xmm0, xmm0
        mov r8, 0xC200000000000000
        movq xmm6, r8
        call aes4               ; H = AES(0), and what the tag's hash is masked with
        movdqa [TAGM], xmm1
        pshufb xmm0, xmm7       ; As a number (bytes reversed) H is kept times x: one bit
        movq rax, xmm0          ; to the left, and the bit that leaves at the top comes
        pextrq rdx, xmm0, 1     ; back as 0xC2..01; then H^2, H^3 and H^4, for four blocks
        add rax, rax            ; at a time
        adc rdx, rdx
        sbb rcx, rcx
        sub rax, rcx
        and rcx, r8
        xor rdx, rcx
        movq xmm2, rax
        pinsrq xmm2, rdx, 1
        mov ebx, HTAB
        mov edi, ebx
        mov cl, 4
.hp:    movdqa [rdi], xmm2
        pshufd xmm0, xmm2, 0x4E
        pxor xmm0, xmm2
        movdqa [rdi+64], xmm0
        dec cl
        jz .sb
        movdqa xmm0, xmm2
        mov eax, 16
        call gh1
        add edi, 16
        jmp .hp
.sb:    mov rdi, [rsp]          ; o
        mov rsi, [rsp+8]        ; m
        mov ebx, [rsp+40]       ; n
        mov rdx, r12
        pxor xmm0, xmm0
        mov ebp, SB             ; SB = header, 0 pad | ciphertext, 0 pad | lengths
        movdqa [rbp], xmm0
        mov dword [rbp], 0x030317
        lea eax, [rbx+rdx+17]   ; the record's length: with the tag, and with the byte we add
        xchg al, ah             ; if we do
        mov [rbp+3], ax
        test edx, edx
        jnz .go
        mov eax, [rbp]          ; encrypting: the record starts with that header
        stosd
        mov al, [rbp+4]
        stosb
.go:    add ebp, 16
.bulk:  cmp ebx, 64             ; 64 bytes at a time, in registers, while there are that many,
        jb .tail
        call ks64
        movdqu xmm5, [rsi]
        movdqu xmm8, [rsi+16]
        movdqu xmm9, [rsi+32]
        movdqu xmm10, [rsi+48]
        pxor xmm0, xmm5
        pxor xmm1, xmm8
        pxor xmm2, xmm9
        pxor xmm3, xmm10
        movdqu [rdi], xmm0
        movdqu [rdi+16], xmm1
        movdqu [rdi+32], xmm2
        movdqu [rdi+48], xmm3
        test edx, edx
        jnz .bdec
        movdqa xmm5, xmm0
        movdqa xmm8, xmm1
        movdqa xmm9, xmm2
        movdqa xmm10, xmm3
.bdec:  movdqa [rbp], xmm5
        movdqa [rbp+16], xmm8
        movdqa [rbp+32], xmm9
        movdqa [rbp+48], xmm10
        add rsi, 64
        add rdi, 64
        add ebp, 64
        sub ebx, 64
        jmp .bulk
.tail:  mov ecx, ebx            ; and the rest (at most 64 bytes, with the byte we add)
        push rdi
        mov edi, ebp
        rep movsb
        test edx, edx
        jnz .tlen
        mov al, [rsp+56]
        stosb
        inc ebx
.tlen:  pop rdi
        test ebx, ebx
        jz .done
        call ks64
        mov esi, KS
        movdqa [rsi], xmm0
        movdqa [rsi+16], xmm1
        movdqa [rsi+32], xmm2
        movdqa [rsi+48], xmm3
        xor ecx, ecx
.tx:    mov al, [rbp+rcx]
        xor al, [rsi+rcx]
        mov [rdi+rcx], al
        test edx, edx
        jnz .tn
        mov [rbp+rcx], al
.tn:    inc ecx
        cmp ecx, ebx
        jb .tx
        add rdi, rcx
        add ebp, ecx
.done:  pxor xmm0, xmm0
        movdqu [rbp], xmm0
        movdqu [rbp+16], xmm0
        lea ecx, [rbp-(SB+16)]
        lea eax, [rbp+15]
        and eax, -16            ; SB+16 is 16-aligned
        mov byte [rax+7], 40    ; the header's length and the ciphertext's, in bits,
        lea edx, [rcx*8]        ; big-endian
        bswap rdx
        mov [rax+8], rdx
        lea ebp, [rax+16-SB]
        shr ebp, 4              ; blocks to hash
        mov esi, SB
%ifdef HOST
        call haad               ; (the tests may have other bytes hashed than a header's)
%endif
        ; GHASH of the ebp blocks at SB, up to four at a time: (y ^ b0) H^m ^ ... ^ b_{m-1} H
        ; in GF(2^128), reduced once.
        mov ebx, HTAB
        pxor xmm2, xmm2
.g4:    mov eax, 4
        cmp ebp, eax
        cmovb eax, ebp
        sub ebp, eax
        shl eax, 4
        movdqa xmm0, [rsi]
        pshufb xmm0, xmm7
        pxor xmm0, xmm2
        call gh1
        test ebp, ebp
        jnz .g4
        pshufb xmm2, xmm7
        pxor xmm2, [TAGM]
        movdqu [rdi], xmm2
        add rdi, 16
        mov [rsp], rdi
        popad
        ret

; ks64: the next 64 bytes of key stream, in xmm0-xmm3
ks64:   push 1
        pop rax
        movd xmm5, eax
        movdqa xmm0, xmm4
        paddd xmm4, xmm5
        movdqa xmm1, xmm4
        paddd xmm4, xmm5
        movdqa xmm2, xmm4
        paddd xmm4, xmm5
        movdqa xmm3, xmm4
        paddd xmm4, xmm5
        pshufb xmm0, xmm7
        pshufb xmm1, xmm7
        pshufb xmm2, xmm7
        pshufb xmm3, xmm7
        jmp aes4

        HOT 0xFFB39FFF
; gh1: xmm2 = sum of eax/16 products (xmm0, then blocks from rsi+16) with H^m .. H^1 at rbx,
; three multiplies each (Karatsuba), reduced once (xmm6 = 0xC2..00, xmm7 = BSWAPM)
gh1:    pxor xmm1, xmm1
        pxor xmm2, xmm2
        pxor xmm3, xmm3
        jmp .gm
.gn:    movdqa xmm0, [rsi]
        pshufb xmm0, xmm7
.gm:    add rsi, 16
        sub eax, 16
        movdqa xmm5, xmm0
        pclmulqdq xmm5, [rbx+rax], 0x00
        pxor xmm1, xmm5
        movdqa xmm5, xmm0
        pclmulqdq xmm5, [rbx+rax], 0x11
        pxor xmm2, xmm5
        pshufd xmm5, xmm0, 0x4E
        pxor xmm0, xmm5
        pclmulqdq xmm0, [rbx+rax+64], 0x00
        pxor xmm3, xmm0
        jnz .gn
        pxor xmm3, xmm1
        pxor xmm3, xmm2
        movdqa xmm0, xmm1
        pclmulqdq xmm0, xmm6, 0x00
        pshufd xmm1, xmm1, 0x4E
        pxor xmm1, xmm3
        pxor xmm1, xmm0
        movdqa xmm0, xmm1
        pclmulqdq xmm0, xmm6, 0x00
        pshufd xmm1, xmm1, 0x4E
        pxor xmm2, xmm1
        pxor xmm2, xmm0
        ret

        HOT 0xFFFF0F3D
; aeskey: the eleven round keys of the AES-128 key at rsi, to RK (clobbers eax, ecx, edi,
; xmm0-xmm2)
aeskey: movdqu xmm0, [rsi]
        mov edi, RK
        push 1                  ; the round constant: 1, and times x in GF(2^8) each round
        pop rax
        mov cl, 10
.k:     movdqa [rdi], xmm0
        add edi, 16
        aeskeygenassist xmm1, xmm0, 0
        pshufd xmm1, xmm1, 0xFF ; the last word, substituted and rotated, in all four words,
        movd xmm2, eax
        pshufd xmm2, xmm2, 0
        pxor xmm1, xmm2         ; with the round constant,
        movdqa xmm2, xmm0       ; on w0, w0 ^ w1, w0 ^ w1 ^ w2, ...
        pslldq xmm2, 4
        pxor xmm0, xmm2
        pslldq xmm2, 4
        pxor xmm0, xmm2
        pslldq xmm2, 4
        pxor xmm0, xmm2
        pxor xmm0, xmm1
        add al, al
        jnc .n
        xor al, 0x1B
.n:     dec cl
        jnz .k
        movdqa [rdi], xmm0
        ret

        HOT 0xFFFFF79F
; aes4: xmm0-xmm3 = AES of xmm0-xmm3 under the round keys at RK (clobbers eax, xmm5)
aes4:   mov eax, RK
        movdqa xmm5, [rax]
        pxor xmm0, xmm5
        pxor xmm1, xmm5
        pxor xmm2, xmm5
        pxor xmm3, xmm5
.r:     add eax, 16
        movdqa xmm5, [rax]
        aesenc xmm0, xmm5
        aesenc xmm1, xmm5
        aesenc xmm2, xmm5
        aesenc xmm3, xmm5
        cmp eax, RK + 144
        jb .r
        movdqa xmm5, [rax+16]
        aesenclast xmm0, xmm5
        aesenclast xmm1, xmm5
        aesenclast xmm2, xmm5
        aesenclast xmm3, xmm5
        ret


; ----------------------------------------------------------------------------

codend:                          ; (what follows is only read: see the page tables in `start`)
%ifndef HOST
CODEPG    equ 0x100 + ((codend - mb + 0xFFF) >> 12) ; the page behind the last one with code
%endif
TWO32:  dd 0x4F800000            ; 2^32 as a float

L_DER:  db 32, 7, "derived"
L_SHTS: db 32, 12, "s hs traffic"
L_SATS: db 32, 12, "s ap traffic"
L_CATS: db 32, 12, "c ap traffic"
L_FIN:  db 32, 8, "finished"
L_KEY:  db 16, 3, "key"
L_IV:   db 12, 2, "iv"
TLS13:  db "tls13 "

%ifndef HOST
CVCTX:  db "TLS 1.3, server CertificateVerify", 0
L_HRR:  db "HelloRetryRequest"
%include "regs.inc"
; The segments. Their table's first ten bytes, all zero, are also what every processor is
; given as its table of interrupt handlers (`start`, `apstart`): read as such a table's
; length and place they say "of length nothing". There are no handlers: whatever faults
; can't be delivered, nor can that, and the machine starts over. A processor that is not
; told so has the table the BIOS left it, or the one it is started up with: at address 0,
; which is where the frame in hand lies. A fault would then go where sixteen bytes of a
; client's packet say (tools/wxtest.sh, 6 and 7).
GDT:    dq 0
        dq 0x00209A0000000000   ; 8: code, 64-bit
        dq 0x0000920000000000   ; 16: data
GDTR:   dw 23
        dd GDT
%include "gen.inc"
H_AE:   db "*accept-encoding:"   ; header names as `seek` sees them, the line end in front
H_INM:  db "*if-none-match:"
T_BR:   db "br"
T_GZ:   db "gzip"
SYNOPT: db 2, 4, 1460 >> 8, 1460 & 255 ; maximum segment size: what fits an Ethernet frame
        db 1, 3, 3, 0           ; (padding,) window scale: ours is not shifted
MSSTAB: dw 216, 536, 1220, 1440 ; the sizes we cut our segments to (the client's, rounded down)
SHTAIL: db 0x13, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04
        db 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20
%else
%include "regs.inc"
%endif
%include "ec.inc"         ; curve programs
%ifndef HOST
        times -(($ - mb) > 0x10000) db 0 ; (the code must end below 1 MiB + 64 KiB: see LOW)
; The site: what tools/pack.py made of the folder that is served. A table of the paths,
; a table of the responses, and the responses themselves, as they are sent.
SITE:   incbin "site.bin"
%endif
