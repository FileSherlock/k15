; os.asm - bare-metal HTTPS server, flat image loaded at 1 MiB (nasm -f bin)
;
; Boot: by src/boot.asm from a disk, or as a multiboot v1 "a.out kludge" kernel (GRUB,
;       `qemu -kernel`). Sets up long mode, its own segments, stack and zeroed memory.
; CPU:  64-bit, with rdrand (secrets) and the AES instructions (the hash that places connections).
; NIC:  virtio-net (modern PCI interface), polled. Our IP is baked in (OURIP).
; TCP:  ports 443 (TLS) and 80 (the same page without); see `tcp`.
; TLS:  1.3, TLS_CHACHA20_POLY1305_SHA256, X25519, ecdsa_secp256r1_sha256.
; Like k2, and unlike k1, this one is meant to be secure: a fresh X25519 key and a fresh ECDSA nonce per
; handshake (rdrand), a real certificate chain, and client records are authenticated before
; they get an answer. See CLAUDE.md for the shortcuts that remain.
;
; Convention: every routine preserves all registers (pushad/popad) unless it
; says otherwise. All buffers live at fixed addresses in zeroed RAM at 2 MiB.
;
; Memory, as the page tables built at boot show it (2 MiB pages): the first 16 MiB as they
; are, and behind them, in one piece, all the other RAM the loader's memory map names,
; wherever it is (also above 4 GiB): the "table space", which the handshake buffers and
; the two connection tables fill. So a slot's address takes 64 bits; everything else is
; below 4 GiB, and 32-bit registers do for it.

%include "conf.inc"             ; CHAIN_LEN

%ifdef HOST
default abs
BSS     equ 0x200000
%else
default rel
BSS     equ mb + 0x100000   ; 2 MiB (said relative to the image, so that the assembler reaches
%endif                      ; what is there relative to the instruction pointer: a byte less)
FR      equ 0               ; the Ethernet frame being handled. At address 0 (old real-mode
                            ; IVT, unused), so `xor reg, reg` loads it and its fields are a
P_IP    equ FR + 26         ; byte away: the client's address,
P_PORTS equ FR + 34         ;   its port and ours (as on the wire),
P_SEQ   equ FR + 38         ;   its sequence number (in host order once `tcp` has started;
                            ;   moved on past bytes we already had)
P_ACK   equ FR + 42         ;   its ack (the same)
P_FL    equ FR + 47         ;   its flags
P_MORE  equ FR + 48         ;   (in place of the window) 1: its data is to be acknowledged now
PML4    equ 0x110000        ; page tables (built at boot): the top one,
PDPT0   equ PML4 + 0x1000   ;   the one for the first 512 GiB,
PDDEV   equ PML4 + 0x2000   ;   the page directory for the card's structures,
PDT     equ 0x120000        ;   and page directories: 8 bytes for each 2 MiB that is mapped
PDT_END equ 0x1E0000        ;   (room for 192 GiB)
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
TXLOCK  equ 0x8F00          ; held from `txbuf` to `txgo`
NCPUM   equ 0x8F04          ; how many processors take frames, less 1 (a power of two, less 1)
APMEM   equ 0x900000        ; for each other processor 32 KiB: four page tables, its page 0,
APBSS   equ 0xA00000        ; and 2 MiB: its BSS
RING    equ BSS + 0x140000  ; Frames for this processor (the first one writes them there,
RHEAD   equ RING - 16       ;   in this processor's own BSS): 256 of 2 KiB, length first; how
RTAIL   equ RING - 8        ;   many have been written, and how many read
TR      equ BSS + 0x20000   ; handshake transcript
VB      equ BSS + 0x30000   ; what a client record should look like (for its tag)
SB      equ BSS + 0x40000   ; seal scratch: Poly1305 input
OB      equ BSS + 0x50000   ; our answer to one packet (OBMAX bytes)
HB      equ BSS + 0x0C900   ; HMAC buffer (key pad | message)
INFO    equ HB + 64         ; HKDF info is built right where HMAC wants its message
SH      equ BSS + 0x0CB00   ; SHA-256: the state of the hash being made,
TSH     equ SH + 32         ;   the state of the handshake transcript's hash (see `thash`),
PADB    equ SH + 64         ;   and the end of a message with its padding (two blocks)
ST      equ BSS + 0x0CD40   ; ChaCha20 state
KS      equ BSS + 0x0CD80   ; ChaCha20 key stream block (64-byte aligned)
PK      equ BSS + 0x0CDC0   ; ChaCha20 block 0: the Poly1305 key (r, then s)
RK      equ BSS + 0x0CE00   ; AES-128: the eleven round keys of the record at hand,
NB      equ RK + 176        ;   its counter block (nonce | counter),
TAGM    equ NB + 16         ;   what its tag is masked with,
BSWAPM  equ TAGM + 16       ;   and how pshufb reverses 16 bytes (made at boot)
SLOTS   equ BSS + 0x0D500   ; key schedule values, 8 x 32 bytes, addressed from ebp
KH      equ BSS + 0x0D600   ; handshake traffic key | 0 counter | iv
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
KST     equ VST + 184       ;   reset knock: 1 after the first port (development builds)
NV      equ BSS + 0x0F200
RXLEN   equ NV              ; the length of the frame in FR
HSNEXT  equ NV + 4          ; handshake buffers looked at so far (`hsnew`)
NOW     equ NV + 8          ; when the frame came, in units of 2^37 cycles (a byte: see C_AGE)
HSMASK  equ NV + 56         ; n - 1 (see TABV)
OOBASE  equ NV + 60         ; where the places for early segments are
TXK     equ NV + 12         ; 1: frames are queued that the device has not been told about
TT      equ NV + 16         ; the table of TLS connections: address (a qword), number of buckets
PT      equ NV + 32         ; the table of connections to port 80: the same
TPOS    equ NV + 48         ; how far the transcript has been hashed (see `thash`)
SUITE   equ NV + 52         ; the handshake's cipher: 0 ChaCha20-Poly1305, 1 AES-128-GCM
POOLN   equ NV + 64         ; how many of the nonces made are left
POOLFILL equ NV + 68        ; how far the next ones are (32 for each k G there is)
CPUN    equ NV + 72         ; which processor this is (0: the one that booted)
CLAIMQ  equ NV + 80         ; the first 8 bytes of the slot `find` chose for a new connection
HKS     equ BSS + 0x0F400   ; the eleven round keys of `prf`, made at boot
HKO     equ HKS + 176       ;   and its output
KA      equ BSS + 0x0F300   ; application keys as `keys` makes them (2 x 48 bytes + 20 of junk)
VQ      equ 0x400000        ; the two rings, 64 KiB apart (enough for queues of 1024)
RXB     equ 0x500000        ; receive buffers, 2 KiB each (12-byte virtio header + frame)
TXB     equ 0x700000        ; transmit buffers, the same
%ifndef OURIP
%define OURIP 0x0F02000A    ; 10.0.2.15, as it is on the wire (make IP=a.b.c.d)
%endif
OO_TAG  equ 0               ; A segment that came early (see `oohold`): whose it is: a word of
OO_SEQ  equ 4               ;   the client's hash (0: nobody's), its sequence number,
OO_LEN  equ 8               ;   length
OO_FIN  equ 12              ;   and whether it had a FIN
OO_DATA equ 16
TABV    equ 0x1000000       ; The table space: from 16 MiB up (see the top of this file). Boot
                            ; divides it: n handshake buffers, n places of 2 KiB for early
                            ; segments (n a power of two: about 1/32 and 1/64 of it), then
                            ; the two connection tables: the one for TLS, the one for port 80.
HSP     equ TABV            ; Handshake buffers (see `hsnew`): each holds
%assign HS_SHIFT 12
%rep 4
%if CHAIN_LEN + 512 > (1 << HS_SHIFT) - 16
%assign HS_SHIFT HS_SHIFT + 1
%endif
%endrep
%if CHAIN_LEN + 512 > (1 << HS_SHIFT) - 16
%error "the certificate chain is too long for a handshake buffer"
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
%endif                      ; 2^37 cycles: 40 to 70 minutes) may be replaced when a new one finds no room
HINT    equ 0x3FC           ; see the cookie in `tcp`
OBMAX   equ 0x40000         ; room for one answer at OB
%ifndef HOST
RL      equ RESP_LEN + 21   ; a response as a record: header, response and content type, tag
%endif

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
F_CLOSED equ 1              ;   (bits 2-3: MSSTAB), on port 80 whether a line has just ended (bit 7)
F_DEFER equ 2               ; F_CLOSED: FINs exchanged, but the client lacks something
F_DEFER_BIT equ 1           ; F_DEFER: its data is not acknowledged before it has our answer
F_SYN   equ 16              ; F_SYN: a SYN has come for it since its last ack that fitted
C_AGE   equ 7               ; when its last packet came (NOW; a byte, so after 256 units of
                            ; silence a connection looks young again for a while)
C_NXT   equ 8               ; next sequence number we expect from the client
C_SND   equ 12              ; our next sequence number
C_ACK   equ 16              ; the client's last ack
PSLOT   equ 20
C_ST    equ 20              ; 0 = waiting for the ClientHello, else 1 + the number of requests
                            ; answered (the next record's sequence number, both directions)
C_LEN   equ 24              ; ClientHello bytes so far; then see the record walk in `tcp`
C_HS    equ 28              ; its handshake buffer + 1 (a word; if that still says so itself)
C_HDRN  equ 30              ; a byte: see the record walk
C_KIV   equ 32              ; our application key | 0 counter | iv, then the client's
TSLOT   equ 128

; What 32-bit code calls pushad and popad: all eight registers of old, in that order (so
; the one a routine returns is at twice the offset it had: ebx at [rsp+32], ebp at
; [rsp+16], edi at [rsp])
%macro pushad 0
        push rax
        push rcx
        push rdx
        push rbx
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
        pop rbx
        pop rdx
        pop rcx
        pop rax
%endmacro
; (Routines that k2 reached through interrupt gates, to save bytes: plain calls now.)
%define icall call
%define fret ret
; Development builds (make DEBUG=1) count things in DBG and show six counters, four hex
; digits each, in place of the end of the page on port 80: `count n` adds one to counter n.
; 0: frames with a bad length or checksum, 1: cycles per frame handled (an average, made when
; shown), 2: connections refused for lack of room, 3: segments that came early, 4: resends,
; 5: RSTs sent.
DBG     equ BSS + 0x0F500
%macro count 1
%ifdef DEBUG
        inc dword [DBG + 4 * %1]
%endif
%endmacro

%ifdef HOST
BITS 64
        section .text
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
        mov edi, PML4           ; need of it. Nothing else is assumed: our own page tables,
        mov ecx, (PDT_END - PML4) / 4 ; segments and stack, and memory we zero ourselves.
        xor eax, eax            ; The top table and the next one have one entry each for now
        rep stosd               ; (the rest is filled in from long mode), and the first page
        mov dword [PML4], PDPT0 + 3 ; directory maps the first 16 MiB as they are
        mov dword [PDPT0], PDT + 3
        mov dword [PDPT0+DEVG*8], PDDEV + 3
        mov edi, PDT
        mov al, 0x83            ; present, writable, a page of 2 MiB
.low:   stosd
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
        or ah, 1                ; long mode, once paging is on
        wrmsr
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
.piece: add rax, 0x1FFFFF       ; in whole pages
        and rax, -0x200000
        and r8, -0x200000
        mov al, 0x83
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
        lea rcx, [rbx + TABV - BSS]
        shr rcx, 3
        xor eax, eax
        mov edi, BSS
        rep stosq               ; zero everything from 2 MiB up
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
        shl eax, 11
        add eax, edx            ; rax = where the tables start
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
        mov [rbp+12], eax       ; plain frames behind a 12-byte header
        dec eax
        mov [rbp+8], eax
        mov [rbp+12], eax
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
        push 44
        pop rcx
.hk:    rdrand eax
        jnc .hk
        stosd
        loop .hk

        ; The other processors, should there be any (up to MAXCPU - 1): each gets page
        ; tables (as ours, but for BSS and page 0) and a copy of BSS as it is now: all the
        ; constants, and nothing yet of what must not be the same on two processors (the
        ; nonces of `stock`: none have been made).
        mov esi, tramp
        mov edi, TRAMP
        push TRAMPLEN
        pop rcx
        rep movsb
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
        lea edi, [r8+0x2000]
        mov ch, 2
        rep movsq               ; a copy of our first page directory, whose first 2 MiB
        lea eax, [r8+0x3003]    ; are in pages of 4 KiB,
        mov [r8+0x2000], rax
        mov eax, ebx
        shl eax, 21
        add eax, APBSS - 0x200000 + 0x83
        mov [r8+0x2008], rax    ; and whose next 2 MiB are its own
        lea edi, [r8+0x3000]
        push 3
        pop rax
        mov ch, 2
.pt:    stosq
        add eax, 0x1000
        loop .pt
        lea eax, [r8+0x4003]
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
        mov dword [rsi], 0x000C4500
        call .wait
        mov dword [rsi], 0x000C4600 + (TRAMP >> 12)
        call .wait
        mov dword [rsi], 0x000C4600 + (TRAMP >> 12)
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
        jmp .poll
.wait:  rdtsc                   ; (2^25 cycles: 10 ms or so)
        mov ecx, eax
.w:     pause
        rdtsc
        sub eax, ecx
        bt eax, 25
        jnc .w
        ret

.poll:  mov esi, [Q0+8]         ; used ring: anything new?
        mov eax, [Q0+Q_SEEN]
        cmp ax, [rsi+2]
        jne .frame
        call txkick             ; no: time to tell the device what we have queued for it,
        cmp dword [POOLN], 0    ; and to get on with the next signatures if there are none
        jne .idle
        call stock
        jmp .poll
.idle:  pause
        jmp .poll
.frame: inc dword [Q0+Q_SEEN]
        and eax, [Q0+12]
        mov edx, [rsi+4+rax*8]  ; buffer id
        mov ecx, [rsi+8+rax*8]  ; bytes written, header included
        mov esi, edx
        and esi, [Q0+12]        ; (id and length are the device's: keep both inside our buffers)
        shl esi, 11
        add esi, RXB + 12
        sub ecx, 12
        and ecx, 2047
        xor edi, edi            ; FR
        xor ebp, ebp            ; (1: not for us)
        mov eax, [abs NCPUM]    ; Whose is it? A connection is one processor's: which, the
        test eax, eax           ; hash of its addresses and ports says (the bits that also
        jz .ours                ; pick the place of an early segment: those are then one
        push rsi                ; processor's too)
        push rcx
        call prf
        pop rcx
        pop rsi
        mov eax, [HKO+12]
        and eax, [abs NCPUM]
        jz .ours
        inc ebp
        shl eax, 21
        add eax, APBSS - 0x200000 ; that one's BSS, where its ring is
        mov ebx, eax
        mov edi, [rbx+RHEAD-BSS]
        mov eax, edi
        sub eax, [rbx+RTAIL-BSS]
        cmp eax, 256
        jae .give               ; (full: the frame is lost)
        cmp ecx, 2044
        ja .give                ; (and so is one that would not fit its place there)
        movzx edi, dil
        shl edi, 11
        lea edi, [rbx+rdi+RING-BSS]
        mov eax, ecx
        stosd
        rep movsb
        inc dword [rbx+RHEAD-BSS]
        jmp .give
.ours:  mov [RXLEN], ecx
        rep movsb
.give:  mov esi, [Q0+4]         ; give the buffer back
        movzx eax, word [rsi+2]
        and eax, [Q0+12]
        mov [rsi+4+rax*2], dx
        inc word [rsi+2]
        mov esi, [Q0+8]
        test byte [rsi], 1      ; the device says when it doesn't need to be told
        jnz .nk
        mov rdx, [Q0+Q_NOTE]
        mov word [rdx], 0
.nk:    test ebp, ebp
        jnz .more
%ifdef DEBUG
        rdtsc                   ; (cycles spent on frames, and how many frames)
        push rax
        call tcp
        rdtsc
        pop rdx
        sub eax, edx
        add [DBG+24], eax
        adc dword [DBG+28], 0
        inc dword [DBG+32]
%else
        call tcp
%endif
.more:  test byte [Q0+Q_SEEN], 31 ; (if frames keep coming, every 32 of them)
        jnz .poll
        call txkick
        jmp .poll

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
        or ah, 1
        wrmsr
        mov eax, cr0
        and eax, 0x9FFFFFFF     ; (caches on: a processor starts with them off)
        or eax, 0x80000001
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
.poll:  mov eax, [RTAIL]
        cmp eax, [RHEAD]
        je .idle
        movzx eax, al
        shl eax, 11
        lea esi, [rax+RING]
        lodsd
        mov ecx, eax
        mov [RXLEN], ecx
        xor edi, edi
        rep movsb
        inc dword [RTAIL]
        call tcp
        test byte [RTAIL], 31
        jnz .poll
        call txkick
        jmp .poll
.idle:  call txkick
        cmp dword [POOLN], 0
        jne .rest
        call stock
        jmp .poll
.rest:  pause
        jmp .poll

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
        jmp .full
.room:  and eax, [Q1+12]        ; buffer = descriptor = ring position
        shl eax, 11
        add eax, TXB + 12
        mov [rsp+32], rax
        popad
        ret

; txgo: queue the frame of ecx bytes that was built where txbuf said (it goes out with txkick)
txgo:   pushad
        mov ebx, [Q1+4]
        movzx eax, word [rbx+2]
        and eax, [Q1+12]
        mov [rbx+4+rax*2], ax
        shl eax, 4
        add eax, [Q1]
        add ecx, 12
        mov [rax+8], ecx        ; length with the header (12 zero bytes: nobody writes there)
        inc word [rbx+2]
        mov byte [TXK], 1
        mov byte [abs TXLOCK], 0
        popad
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
; handshake flight: our side of a connection is a function of its keys (the flight, then one
; record of RL bytes per request answered), so anything a client turns out not to have is
; built again from the byte its ack names (`.resend`). There is no timer. Two things tell us
; that a packet of ours was lost:
;   - the client sends old data again, with an ack below C_SND: its request is not
;     acknowledged because the answer, which carries our ack, did not arrive;
;   - the client repeats an ack below C_SND without data: it got something after a hole.
; So that the first always works, an answer of several segments does not acknowledge the
; client's data (`tcp_send`): that happens when the client's ack says it has all of it.
;
; Connections live in two hashed tables (`find`): one for port 443, one with small slots for
; port 80, which is the same without TLS (a request ends with an empty line, and its
; "record" is the response as it is). A SYN gets a SYN-ACK and no slot (`.syn`); the first
; packet that acknowledges it makes the connection. A segment that comes before its
; predecessor is kept (`oohold`).
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
        call txgo
        ret
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
        sub ecx, 20             ; TCP length
        cmp ecx, 20
        jb .bad
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
        mov byte [KST], 1
.kb:    cmp eax, KNOCK_B
        jne .nok
        cmp byte [KST], 1
        jne .nok
        mov al, 0xFE
        out 0x64, al            ; keyboard controller: pulse the reset line
        lidt [KST+4]            ; (and if that does nothing: no IDT, then a fault)
        int3
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
        rdtsc                   ; the time, in units of 2^37 cycles (40 to 70 seconds)
        shr edx, 5
        mov [NOW], dl
        mov [rbx+P_MORE], bl
        mov dl, [rbx+P_FL]
        call find               ; ebp = the connection's slot; or, if it has none, eax = -1
        sbb eax, eax            ; and ebp = a slot for a new one (0: there is no room)
        test dl, 4
        jz .nrst
        inc eax                 ; RST: if it is the next thing its connection expects, that
        jz .ret                 ; was the connection
        mov eax, [rbx+P_SEQ]
        cmp eax, [rbp+C_NXT]
        jne .ret
.free:  and dword [rbp+C_IP], 0
        ret
.nrst:  test dl, 2
        jz .nsyn
        test dl, 16
        jnz .ret
        ; SYN. It gets a SYN-ACK and no slot: the slot is made when an ack shows that the
        ; client received it (`.miss`), so only clients that really are at their address can
        ; take up slots. For that our initial sequence number is a "cookie", made of W, a
        ; keyed hash of the client's address and ports (`prf`):
        ;   bits 10-31: W xor the low bits of the client's initial sequence number, so that
        ;               the packet that follows the SYN-ACK is recognised as the first;
        ;   bits 2-9:   W (HINT): tells a packet that acknowledges a SYN-ACK of ours, first
        ;               or not, from one of a connection we don't know;
        ;   bits 0-1:   which of four segment sizes the client takes (MSSTAB).
        inc eax
        jz .nos
        or byte [rbp+C_FLG], F_SYN ; (for a connection we have: its client may be starting
        jmp .syn                ; over, see `.odd`)
.nos:   test rbp, rbp
        jz .deny                ; (no room where this connection would go: say so now)
.syn:   movzx ecx, byte [rbx+46] ; its options: how much the client takes in one segment
        shr ecx, 4
        lea ecx, [rcx*4-20]
        lea esi, [rbx+54]
        mov edx, 536            ; (what one that doesn't say must take)
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
        jne .onx
        cmp edi, 3
        jne .onx
        movzx edx, word [rsi+1]
        xchg dl, dh
.onx:   add esi, edi
        sub ecx, edi
        jmp .opt
.optd:  mov eax, [rbx+P_SEQ]
        lea edi, [rax+1]        ; (the SYN takes a sequence number, and so does ours)
        shl eax, 10
        xor eax, [HKO+8]
        and al, 0xFC
        cmp edx, 536            ; the largest of the four sizes that is not more than the
        sbb eax, -1             ; client's
        cmp edx, 1220
        sbb eax, -1
        cmp edx, 1440
        sbb eax, -1
        xchg eax, edx
        mov al, 0x12            ; SYN|ACK, with what we take in one segment as its only option
        mov esi, SYNOPT
        push 4
        pop rcx
.seg:   call tcp_seg
        ret
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
        movzx edi, word [rbx+P_PORTS] ; The slot becomes this connection's in one step, if
        shl rdi, 32             ; it still is as `find` saw it: another processor may have
        mov eax, [rbx+P_IP]     ; taken it since, for a connection of its own. (Then this
        or rdi, rax             ; packet is as good as lost, and will come again.)
        mov rax, [CLAIMQ]
        lock cmpxchg [rbp], rdi
        jne .ret
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
        mov [rbp+C_SND], eax
        mov [rbp+C_ACK], eax
        dec eax
        and al, 3
        shl al, 2
        mov [rbp+C_FLG], al     ; (the segment size the SYN-ACK noted)

.est:   mov al, [NOW]
        mov [rbp+C_AGE], al
        ; The client's ack counts if it is in [C_ACK, C_SND]. edx = 1: it lacks something we
        ; sent, 2: and says so with the same ack as before, 0: neither
        xor edx, edx
        mov eax, [rbx+P_ACK]
        sub eax, [rbp+C_ACK]    ; how much further than before
        mov edi, [rbp+C_SND]
        sub edi, [rbp+C_ACK]    ; how much there is to acknowledge
        cmp eax, edi
        ja .odd
        jb .ak0
        test byte [rbp+C_FLG], F_CLOSED
        jnz .free               ; it has all we sent, our FIN included: done
        cmp [rbx+P_PORTS+2], bl
        je .nhs
        cmp [rbp+C_ST], ebx
        je .nhs
        mov [rbp+C_HS], bx      ; (it has our flight: the handshake buffer can go to another)
.nhs:   btr dword [rbp+C_FLG], F_DEFER_BIT ; If that was an answer of several segments, its
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
        and byte [rbp+C_FLG], ~F_SYN
.ak:    test byte [rbp+C_FLG], F_CLOSED
        jz .open
        test edx, edx           ; closed, but the client lacks something (our FIN at least):
        jz .ret                 ; if it asks, by sending anything but a plain new ack, it gets
        cmp dl, 2               ; that again
        je .resend
        test byte [rbx+P_FL], 1
        jnz .resend
        test ecx, ecx
        jnz .resend
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
.ack:   mov esi, OB
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
        ret

.new:   mov edi, OB             ; edi = end of our answer
.more:  add [rbp+C_NXT], ecx    ; ecx new bytes at esi, in order
        cmp [rbx+P_PORTS+2], bl
        je .plain
        cmp [rbp+C_ST], ebx
        jne .walk
        mov eax, [rbp+C_LEN]    ; waiting for the ClientHello: collect it in a handshake buffer
        lea edx, [rax+rcx]      ; bytes so far, these included
        cmp edx, CHMAX          ; (a ClientHello must fit its buffer, and the transcript)
        ja .junk
        test eax, eax
        jnz .part
        test ecx, ecx
        jz .reply
        call hsnew
        jmp .buf
.part:  call hsbuf
        jc .reset               ; (its first part is gone: the buffer was needed for others)
.buf:   mov [rbp+C_LEN], edx
        push rdi
        lea edi, [rbx+HS_CH+rax]
        rep movsb
        pop rdi
        cmp edx, 5
        jb .reply
        movzx eax, word [rbx+HS_CH+3]
        xchg al, ah
        add eax, 5              ; record length
        cmp edx, eax
        jb .reply               ; not all there yet
        push rsi                ; (the end of this segment)
        push rdx
        push rax
        push rbx
        inc dword [rbp+C_ST]
        lea esi, [rbx+HS_CH+5]
        lea ecx, [rax-5]
        icall handshake         ; edi = end of our flight
        pop rbx
        mov ecx, edi            ; keep the flight, where the ClientHello was: a client that
        sub ecx, OB             ; sends its ClientHello again has to get this one again (it
        mov [rbx+HS_FLEN], ecx  ; may have got it already)
        push rdi
        mov esi, OB
        lea edi, [rbx+HS_FL]
        rep movsb
        pop rdi
        pop rax
        pop rcx
        pop rsi
        sub ecx, eax            ; (anything behind the ClientHello is the first record:
        sub esi, ecx            ; the end of this segment)
        xor ebx, ebx
        mov [rbp+C_LEN], ebx
        jmp .walk
.junk:  mov dword [rbp+C_LEN], CHMAX + 1 ; no ClientHello will come of this
        jmp .reply

        ; Records. C_LEN bytes of a record that is not looked at are still to come; or, if
        ; C_HDRN is not 0, so many bytes of a record header are in C_LEN. Only an application
        ; record that is all in this segment, has more than a tag and carries the tag of the
        ; client's next record counts, and then it gets one response (so the client's
        ; Finished, which has other keys, and anything forged are skipped like the junk they are).
.walk:  test ecx, ecx
        jz .reply
        movzx eax, byte [rbp+C_HDRN]
        test eax, eax
        jnz .hdr
        mov eax, [rbp+C_LEN]
        test eax, eax
        jz .rec
        cmp eax, ecx
        jbe .skip
        mov eax, ecx
.skip:  add esi, eax
        sub ecx, eax
        sub [rbp+C_LEN], eax
        jmp .walk
.hdr:   mov dl, [rsi]           ; the rest of a header that began in an earlier segment
        inc esi
        dec ecx
        cmp al, 4
        je .hend
        mov [rbp+C_LEN+rax], dl
        inc byte [rbp+C_HDRN]
        jmp .walk
.hend:  mov dh, [rbp+C_LEN+3]   ; its last byte: the record's length, which is skipped
        movzx eax, dx
        mov [rbp+C_LEN], eax
        mov [rbp+C_HDRN], bl
        jmp .walk
.rec:   cmp ecx, 5
        jae .whole
.some:  mov dl, [rsi]           ; a header that goes on in the next segment
        mov [rbp+C_LEN+rax], dl
        inc esi
        inc eax
        loop .some
        mov [rbp+C_HDRN], al
        jmp .reply
.whole: movzx eax, word [rsi+3]
        xchg al, ah
        add eax, 5              ; record length
        cmp eax, ecx
        jbe .here
        sub eax, ecx            ; it goes on in later segments: skipped
        mov [rbp+C_LEN], eax
        jmp .reply
.here:  cmp byte [rsi], 23      ; application_data
        jne .next
        cmp eax, 22
        jb .next
        cmp edi, OB + OBMAX - RL
        ja .next                ; (no room for another response: pipelined beyond reason)
        mov edx, [rbp+C_ST]     ; sequence number + 1, the same in both directions
        dec edx
        pushad
        lea ecx, [rax-21]
        add esi, 5
        lea rbx, [rbp+C_KIV+48]
        mov edi, VB
        stc
        icall seal              ; the record as it should be, tag included
        movdqu xmm0, [rdi-16]   ; its tag and the one that came: all 16 bytes are looked at,
        movdqu xmm1, [rsi+rcx]  ; whatever they are
        pxor xmm0, xmm1
        ptest xmm0, xmm0
        popad
        jne .next
        inc dword [rbp+C_ST]
        call respond
.next:  add esi, eax
        sub ecx, eax
        jmp .walk

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
        cmp edi, OB + OBMAX - RL
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
.out:   mov esi, OB             ; our answer is at OB, up to edi; it follows what we sent before
        mov ecx, edi
        sub ecx, esi
        mov al, 0x10            ; ACK
        jz .fin
        mov al, 0x18            ; ACK|PSH
.fin:   test byte [rbx+P_FL], 1
        jz .send
        inc dword [rbp+C_NXT]   ; the client's FIN takes a sequence number and gets ours with
        or al, 1                ; the answer
.send:  mov edx, [rbp+C_SND]
        add [rbp+C_SND], ecx
        test al, 1
        jz .sq
        inc dword [rbp+C_SND]   ; (ours takes one too)
        or byte [rbp+C_FLG], F_CLOSED
        mov edi, [rbx+P_ACK]    ; If the client had all we sent and there was nothing more to
        sub edi, edx            ; say, that was the connection (should our FIN get lost, the
        or edi, ecx             ; client's next one is told that there is none). If not, the
        jnz .sq                 ; slot stays until the client has the rest.
        call tcp_send
        jmp .free
.sq:    call tcp_send
        ret

        ; The client lacks the end of what we sent, from its ack on: build that again and
        ; send it: the last of our records (as many as OB has room for: whether more is
        ; missing its next ack will say), and before them the end of the flight if it lacks
        ; that too.
.resend:
        count 4
        mov edi, OB
        mov eax, [rbp+C_SND]
        sub eax, [rbx+P_ACK]    ; so many bytes (our FIN, if it lacks that, is not one)
        test byte [rbp+C_FLG], F_CLOSED
        jz .rsz
        dec eax
.rsz:   mov ecx, RESP_LEN - 1   ; in records of this length: on port 80 the bare response
        cmp [rbx+P_PORTS+2], bl
        je .recs
        mov ecx, RL
        mov edx, [rbp+C_ST]
        dec edx
        imul edx, ecx           ; all our records together
        cmp eax, edx
        jbe .recs
        sub eax, edx            ; more than those: the end of the flight, which is in the
        call hsbuf              ; handshake buffer, unless that has gone to another
        jc .reset               ; connection since
        mov esi, [rbx+HS_FLEN]
        sub esi, eax
        jb .ret0                ; (more than we ever sent)
        lea esi, [rbx+rsi+HS_FL]
        push rcx
        xchg eax, ecx
        rep movsb
        pop rcx
        xor ebx, ebx
        xchg eax, edx           ; and then all the records
.recs:  mov esi, eax            ; eax = bytes of records, ecx = the length of one
        add eax, ecx
        dec eax
        xor edx, edx
        div ecx                 ; so many records, the last of them possibly not from its start
        push rax
        imul eax, ecx
        sub eax, esi
        xchg eax, esi           ; esi = how much of the first one the client has
        pop rcx
        mov edx, [rbp+C_ST]     ; (port 80 has no such thing, and doesn't care)
        dec edx
        sub edx, ecx            ; the first one's number
        jrcxz .none
.again: cmp edi, OB + OBMAX - RL
        ja .none                ; (as many as there is room for)
        call respond
        inc edx
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
.reset: mov al, 4               ; we can't go on with this connection: say so and forget it
        mov edx, [rbp+C_SND]
        xor ecx, ecx
        xor edi, edi
        call tcp_seg
        jmp .free

; find: ebp = the slot of the connection the packet in FR belongs to. If it has none: CF, and
; ebp = the slot a new one would get, or 0 if there is no room for it.
; A connection is in one of two buckets of BUCKET slots, picked by two words of the keyed
; hash of its address and ports (`prf`; clients can't aim at each other's buckets). A new one
; goes into the bucket with more free slots. If both are full, it takes the place of the
; connection in them that has been quiet for the longest, if that is longer than IDLE (about
; an hour): such a client has probably gone without saying so. If none has, the new one is
; refused.
find:   pushad
        xor esi, esi
        call prf
        mov esi, PT             ; the table for port 80,
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
.free:  mov rax, [rbp]
        test eax, eax
        jz .mine
        add rbp, rcx
        jmp .free
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
        mov al, [NOW]
        sub al, [rbp+C_AGE]     ; how long it has been quiet
        cmp al, bh
        jbe .young
        mov bh, al
        mov rsi, rbp
        mov rax, [rbp]
        mov [CLAIMQ], rax
.young: pop rax
.nx:    add rbp, rcx
        dec dh
        jnz .s
        ret

; prf: HKO = a keyed hash of the client's address and ports (and ours: twelve bytes of the
; frame at rsi): eleven rounds of AES, as the processor has them, with round keys that are simply
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
        movdqa [HKO], xmm0
        ret

; ckx: eax = 0 (and ZF) if the packet is the first after a SYN-ACK of ours: its ack is the
; cookie for its sequence number (see `.syn`). Bits HINT of eax are 0 if it acknowledges a
; SYN-ACK of ours at all.
ckx:    push rdx                ; (ebx = 0)
        mov eax, [rbx+P_SEQ]
        dec eax
        shl eax, 10
        mov edx, [rbx+P_ACK]
        dec edx
        xor eax, edx
        xor eax, [HKO+8]
        and eax, -4
        pop rdx
        ret

; respond: our response to request number edx of the connection ebp at edi (which moves on):
; as a record under the connection's key, or on port 80 as it is. (ebx = 0)
respond:
        push rsi
        push rcx
        mov esi, RESP
        mov ecx, RESP_LEN
        cmp [rbx+P_PORTS+2], bl
        jne .tls
        dec ecx                 ; port 80: without the byte that says what a record holds
        rep movsb
%ifdef DEBUG
        pushad
        mov eax, [DBG+24]       ; (counter 1: cycles per frame)
        mov edx, [DBG+28]
        div dword [DBG+32]
        mov [DBG+4], eax
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
        jmp .done
.tls:   push rbx
        lea rbx, [rbp+C_KIV]
        clc
        icall seal
        pop rbx
.done:  pop rcx
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
; what this packet brought (but what came before it): the client then keeps sending its data
; until it has all of the answer, whichever part gets lost, and it is acknowledged when its
; ack says so (F_DEFER, in `tcp`). Not when we close: then there is no later.
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
        mov edi, [abs P_SEQ]
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
; sequence number edx, ack edi
tcp_seg:
        pushad
        mov ebp, ecx            ; payload length
        call txbuf              ; ebx = the frame
        bswap edx
        mov [rbx+38], edx
        bswap edi
        mov [rbx+42], edi
        mov byte [rbx+46], 0x50
        test al, 2
        jz .nopt
        mov byte [rbx+46], 0x60 ; a SYN's "payload" is 4 bytes of options
.nopt:  mov [rbx+47], al
        xor eax, eax
        mov [rbx+50], eax       ; checksum (for now), nothing urgent
        dec eax
        mov [rbx+48], ax        ; window: we take whatever comes, at once
        lea edi, [rbx+54]
        rep movsb
        mov [rdi], cl           ; zero pad byte for an odd length checksum
        mov edi, ebx
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
        call csum
        mov [rbx+50], ax
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
        mov edi, TR             ; transcript: ClientHello
        push rsi
        rep movsb
        pop rsi
        mov ebx, edi            ; the ServerHello goes here
        mov eax, TR             ; find the client's x25519 key share (group, length). If it
        mov edx, 0x20001d00     ; sent none, this stops the search: we then answer
        mov [rdi], edx          ; with a "share" of junk, and the client gives up
.ks:    inc eax
        cmp [rax], edx
        jne .ks
        push rax
        push rsi
        mov esi, HT             ; the transcript's hash starts over
        mov edi, TSH
        mov cl, 8               ; (ecx = 0 after the copy above)
        rep movsd
        mov dword [TPOS], TR
        pop rsi
        mov edi, E              ; a fresh secret: our X25519 scalar
        mov cl, 4
.rnd:   rdrand rax
        jnc .rnd
        stosq
        loop .rnd
        movzx edx, byte [rsi+38] ; session id length
        lea eax, [rsi+rdx+41]   ; behind it the cipher suites (two bytes each), after their
        movzx ecx, word [rax-2] ; length, which counts as far as the ClientHello goes
        xchg cl, ch
        xor edi, edi            ; Ours: the first of the client's that is 13 03 (ChaCha20-
        lea r8d, [rsi+rbx-TR]   ; Poly1305: 0) or 13 01 (AES-128-GCM: 1); the first of these
        sub r8d, eax            ; if it names neither (and then gives up).
        jbe .cse
        cmp ecx, r8d
        jbe .csn
        mov ecx, r8d
.csn:   shr ecx, 1
        jz .cse
.cs:    cmp word [rax], 0x0313
        je .cse
        cmp word [rax], 0x0113
        je .csa
        inc eax
        inc eax
        loop .cs
        jmp .cse
.csa:   inc edi
.cse:   mov [SUITE], edi
        mov edi, ebx
        lea ecx, [rdx+39]
        rep movsb               ; ServerHello: as the ClientHello up to its session id,
        lea edi, [rbx+6]
        mov cl, 4
.rs:    rdrand rax              ; but with a random of our own, ...
        jnc .rs
        stosq
        loop .rs
        lea edi, [rbx+rdx+39]
        mov esi, SHTAIL
        mov cl, 19
        rep movsb               ; ... + suite, extensions, key share header ...
        mov eax, [SUITE]
        add eax, eax
        sub [rdi-18], al        ; (13 03, or 13 01)
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
        lea edi, [rbp+S_HS]
        call hmac               ; handshake secret
        pop rbx
        lea eax, [rbx+rdx+90]   ; P1 = end of ServerHello
        call thash
        push rbx
        push rdx
        lea ebx, [rbp+S_HS]
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
        mov byte [rdi], 0x16    ; inner content type: handshake
        xchg eax, edi

        pop rdi                 ; output position
        pop rsi                 ; P1
        lea ecx, [rax+1]
        sub ecx, esi
        mov ebx, KH
        xor edx, edx
        call seal               ; edi = end of output

        call thash              ; application traffic secret
        lea ebx, [rbp+S_HS]
        lea esi, [rbp+S_Z]
        push rdi
        lea edi, [rbp+S_ES]
        call stage              ; master secret
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
        add edi, 48
        call keys
        mov esi, KA             ; (`keys` writes 20 bytes too many: not into the connection)
        lea rdi, [rbp+C_KIV]
        push 24
        pop rcx
        rep movsd
        xchg eax, edi
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

; stage: edi = HKDF-Extract(Derive-Secret(ebx, "derived", ""), 32 bytes at esi)
stage:
        pushad
        push rsi
        push rdi
        mov esi, L_DER
        lea edx, [rbp+S_EH]
        lea edi, [rbp+S_D]
        call expand
        mov ebx, edi
        pop rdi
        pop rsi
        push 32
        pop rcx
        call hmac
        popad
        ret
%endif

; keys: edi = key | cipher | iv from traffic secret ebx: 32 bytes of key (of which AES-128
; uses 16), four bytes that say which cipher (`seal`), 12 of iv (+20 junk bytes: expand
; writes 32)
keys:
        pushad
        xor edx, edx
        mov esi, L_KEY
        mov eax, [SUITE]
        test eax, eax
        jz .k
        mov esi, L_KEY16
.k:     call expand
        add edi, 36
        mov [rdi-4], eax        ; (slots near 16 MiB hold SeaBIOS tables: not zero by themselves)
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
        icall sha256             ; inner hash
        mov cl, 64
.o:     xor byte [HB+rcx-1], 0x36 ^ 0x5c
        loop .o
        mov cl, 96
        pop rdi
        icall sha256             ; outer hash
        popad
        fret

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
        icall hmac
        popad
        fret

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
        call vm                 ; (leaves rsi at STEP25519)
        xor edx, edx            ; The ladder, from the top bit down. The two points change
        mov ecx, 255            ; places when a bit differs from the one before it.
.l:     push rsi
        xor eax, eax
        bt [E], ecx
        adc eax, eax
        push rax
        push rcx
        xor edx, eax
        call cswap
        mov rsi, [rsp+16]
        call vm
        pop rcx
        pop rdx
        pop rsi
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
        call rev32              ; the hash as a number
        mov esi, X_SIGN
        call vm
        popad
        ret

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
.rnd:   rdrand rax
        jnc .rnd
        stosq
        loop .rnd
%ifdef HOST
        cmp ebx, (NPOOL - 1) * 32 ; (the tests choose the nonce that is used first)
        jne .k
        cmp byte [HKSET], 0
        je .k
        mov esi, HK
        lea edi, [rbx+POOLK]
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

; addk: r8-r11 += the four limbs at rdx if rax = -1, not if rax = 0; CF = the carry
; (clobbers r12-r15)
addk:   mov r12, [rdx]
        mov r13, [rdx+8]
        mov r14, [rdx+16]
        mov r15, [rdx+24]
        and r12, rax
        and r13, rax
        and r14, rax
        and r15, rax
        add r8, r12
        adc r9, r13
        adc r10, r14
        adc r11, r15
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
        mov rax, r14            ; below 2^256 + M: if it left 2^256, take M off
        neg rax
        mov rdx, rbp
        call addk
.done:  mov [rdi], r8
        mov [rdi+8], r9
        mov [rdi+16], r10
        mov [rdi+24], r11
        ret

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

; rev32: the 32 bytes at rsi, reversed, to rdi (rdi += 32; clobbers al, ecx = 0)
rev32:  push 32
        pop rcx
.l:     mov al, [rsi+rcx-1]
        stosb
        loop .l
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
        not rax
        inc rax
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
echost: pushad                  ; (for the tests: C wants its registers back)
        call ecinit
        popad
        ret
; (for test/bench.c: one operation, or one program, in the field number ecx)
        global hfmul, hfas, hfsub, hvm, hinv, F25519, HK, HKSET, POOLN, hstock
HK      equ BSS + 0x18000       ; (a nonce for the first signature after the next `stock`)
HKSET   equ HK + 32
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
; chacha: edi = the ChaCha20 block of the 16-dword state at ST (its four rows in xmm0-xmm3:
; a quarter round does all four columns at once). Clobbers eax, xmm0-xmm4.
chacha: movdqa xmm0, [ST]
        movdqa xmm1, [ST+16]
        movdqa xmm2, [ST+32]
        movdqa xmm3, [ST+48]
        mov al, 10
.r:     call .qr
        pshufd xmm1, xmm1, 0x39 ; (the diagonals become the columns,
        pshufd xmm2, xmm2, 0x4E
        pshufd xmm3, xmm3, 0x93
        call .qr
        pshufd xmm1, xmm1, 0x93 ; and columns again)
        pshufd xmm2, xmm2, 0x4E
        pshufd xmm3, xmm3, 0x39
        dec al
        jnz .r
        paddd xmm0, [ST]
        paddd xmm1, [ST+16]
        paddd xmm2, [ST+32]
        paddd xmm3, [ST+48]
        movdqu [rdi], xmm0
        movdqu [rdi+16], xmm1
        movdqu [rdi+32], xmm2
        movdqu [rdi+48], xmm3
        ret
.qr:    paddd xmm0, xmm1        ; a += b; d ^= a; d <<<= 16
        pxor xmm3, xmm0
        pshuflw xmm3, xmm3, 0xB1
        pshufhw xmm3, xmm3, 0xB1
        paddd xmm2, xmm3        ; c += d; b ^= c; b <<<= 12
        pxor xmm1, xmm2
        movdqa xmm4, xmm1
        pslld xmm1, 12
        psrld xmm4, 20
        por xmm1, xmm4
        paddd xmm0, xmm1        ; a += b; d ^= a; d <<<= 8
        pxor xmm3, xmm0
        movdqa xmm4, xmm3
        pslld xmm3, 8
        psrld xmm4, 24
        por xmm3, xmm4
        paddd xmm2, xmm3        ; c += d; b ^= c; b <<<= 7
        pxor xmm1, xmm2
        movdqa xmm4, xmm1
        pslld xmm1, 7
        psrld xmm4, 25
        por xmm1, xmm4
        ret

; seal: TLS 1.3 record at edi for ecx plaintext bytes at esi (last byte = inner content type),
; key|0|iv at rbx, sequence number edx. Returns edi = end of record.
; With CF set the bytes at esi are copied instead of encrypted: the record a peer should have
; sent for that ciphertext, whose tag the caller compares.
; The key block says which cipher it is for (`keys`): where ChaCha20 has its block counter,
; which starts at 0, a 1 means AES-128-GCM. Both ciphers go the same way: a key stream 64
; bytes at a time, and a tag over header | ciphertext | lengths, lined up in SB.
seal:
        pushad
        sbb ebp, ebp            ; CF: the "plaintext" is ciphertext already, just make its tag
        push rdi                ; o
        push rcx                ; n
        push rsi                ; m
        bswap edx               ; (the sequence number goes on the nonce's last four bytes)
        cmp byte [rbx+32], 0
        jne .aes
        mov edi, ST             ; ChaCha state: constants | key | 0 counter | iv ^ seq
        mov esi, SIGMA
        movsq
        movsq
        mov rsi, rbx
        push 6
        pop rcx
        rep movsq
        xor [rdi-4], edx
        mov edi, PK
        call chacha             ; block 0: Poly1305 key
        jmp .sb
.aes:   mov rsi, rbx
        call aeskey
        mov edi, NB             ; the counter block: iv ^ seq | counter
        mov rax, [rbx+36]
        stosq
        mov eax, [rbx+44]
        xor eax, edx
        stosd
        mov eax, 0x01000000     ; 1 for the tag, then 2, 3, ... (big-endian)
        stosd
        movdqa xmm7, [BSWAPM]
        pxor xmm0, xmm0
        call aesblk             ; H = AES(0): what the tag's hash multiplies by. As a number
        pshufb xmm0, xmm7       ; (bytes reversed) it is kept times x: one bit to the left,
        mov r8, 0xC200000000000000 ; and the bit that leaves at the top comes back as 0xC2..01
        movq xmm6, r8
        movq rax, xmm0
        pextrq rdx, xmm0, 1
        add rax, rax
        adc rdx, rdx
        sbb rcx, rcx
        sub rax, rcx
        and rcx, r8
        xor rdx, rcx
        movq xmm5, rax
        pinsrq xmm5, rdx, 1
        movdqa xmm0, [NB]
        call aesblk
        movdqa [TAGM], xmm0     ; what the hash is masked with
        mov byte [NB+15], 2
.sb:    mov edi, SB             ; SB = header, 0 pad | ciphertext, 0 pad | lengths
        mov eax, 0x030317
        stosd
        mov ecx, [rsp+8]
        lea eax, [rcx+16]
        xchg al, ah
        mov [rdi-1], ax
        inc edi
        add ecx, 42             ; zero a bit more than needed: simpler than rounding
        xor eax, eax
        rep stosb
        pop rsi                 ; m
        mov ecx, [rsp]          ; n
        mov edi, SB+16
        test ebp, ebp
        jz .ks
        rep movsb
        jmp .d
.ks:    push rdi
        mov edi, KS             ; (64-byte aligned)
        mov edx, edi
        cmp byte [rbx+32], 0
        jne .aks
        inc dword [ST+48]       ; next counter
        call chacha
        jmp .kd
.aks:   movdqa xmm0, [NB]       ; four counter blocks
        mov eax, [NB+12]
        bswap eax
        inc eax
        bswap eax
        mov [NB+12], eax
        call aesblk
        stosq                   ; (16 bytes on: the block itself comes next)
        stosq
        movdqa [rdi-16], xmm0
        test edi, 63
        jnz .aks
.kd:    pop rdi
.x:     lodsb
        xor al, [rdx]
        inc edx
        stosb
        dec ecx
        jz .d
        test dl, 63
        jnz .x
        jmp .ks
.d:     pop rcx                 ; n
        lea edi, [rcx+SB+16+15]
        and edi, -16            ; SB+16 is 16-aligned
        lea ebp, [rdi+16-SB]
        shr ebp, 4              ; blocks to hash
        cmp byte [rbx+32], 0
        jne .alen
        mov byte [rdi], 5       ; Poly1305: the header's length, the ciphertext's
        mov [rdi+8], ecx
        jmp .out
.alen:  mov byte [rdi+7], 40    ; GCM: the same in bits, big-endian
        lea eax, [rcx*8]
        bswap rax
        mov [rdi+8], rax
.out:   pop rdi                 ; o
        mov esi, SB
        movsd                   ; record header
        movsb
        add esi, 11
        rep movsb               ; ciphertext
        mov esi, SB
        cmp byte [rbx+32], 0
        jne .ghash
        ; Poly1305 tag of the ebp 16-byte blocks at SB, key at PK (r, then s), to rdi.
        ; h is r8, r9, r10 (two limbs of 64 bits and what is above them); r is r11, r12,
        ; and r13 = r1 * 5/4 does for r1 where a product leaves 2^130 (which is 5).
        mov r11, [PK]
        mov r12, [PK+8]
        mov rax, 0x0FFFFFFC0FFFFFFF
        and r11, rax
        sub rax, 3
        and r12, rax
        mov r13, r12
        shr r13, 2
        add r13, r12
        xor r8d, r8d
        xor r9d, r9d
        xor r10d, r10d
.blk:   add r8, [rsi]           ; h += block + 2^128
        adc r9, [rsi+8]
        adc r10, 1
        mov rax, r8             ; h *= r: limb 0 is h0 r0 + h1 r1 5/4,
        mul r11
        mov rbx, rax
        mov rcx, rdx
        mov rax, r9
        mul r13
        add rbx, rax
        adc rcx, rdx
        mov rax, r8             ; limb 1 is h0 r1 + h1 r0 + h2 r1 5/4,
        mul r12
        mov r14, rax
        mov r15, rdx
        mov rax, r9
        mul r11
        add r14, rax
        adc r15, rdx
        mov rax, r10
        imul rax, r13
        add r14, rax
        adc r15, 0
        imul r10, r11           ; limb 2 is h2 r0
        mov r8, rbx
        add r14, rcx
        mov r9, r14
        adc r10, r15
        mov rax, r10            ; and what is above 2^130 comes back times 5
        shr rax, 2
        and r10d, 3
        lea rax, [rax+rax*4]
        add r8, rax
        adc r9, 0
        adc r10, 0
        add rsi, 16
        dec ebp
        jnz .blk
        mov rax, r8             ; h mod 2^130 - 5: if h + 5 reaches 2^130, that less 2^130
        mov rcx, r9
        add rax, 5
        adc rcx, 0
        adc r10, 0
        shr r10, 2
        cmovnz r8, rax
        cmovnz r9, rcx
        add r8, [PK+16]         ; tag = h + s mod 2^128
        adc r9, [PK+24]
        mov [rdi], r8
        mov [rdi+8], r9
.tag:   add rdi, 16
        mov [rsp], rdi
        popad
        ret
        ; GHASH of the ebp blocks at SB: y = (y ^ block) * H in GF(2^128), for each block.
        ; As numbers with their bytes reversed, the bits are in reverse too, and the
        ; product of two such numbers is the reversed product, one bit short, which is why
        ; xmm5 = H times x. xmm1, xmm3, xmm2 = the 256-bit product's low half, its middle
        ; (64 bits up), its high half; then twice: the lowest 64 bits, times 0xC2..00 and
        ; 64 bits further up, are worth the same and take their place (xmm6 = 0xC2..00).
.ghash: pxor xmm2, xmm2
.g:     movdqa xmm0, [rsi]
        pshufb xmm0, xmm7
        pxor xmm0, xmm2
        movdqa xmm1, xmm0
        pclmulqdq xmm1, xmm5, 0x00
        movdqa xmm2, xmm0
        pclmulqdq xmm2, xmm5, 0x11
        movdqa xmm3, xmm0
        pclmulqdq xmm3, xmm5, 0x10
        pclmulqdq xmm0, xmm5, 0x01
        pxor xmm3, xmm0
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
        add rsi, 16
        dec ebp
        jnz .g
        pshufb xmm2, xmm7
        pxor xmm2, [TAGM]
        movdqu [rdi], xmm2
        jmp .tag

; aeskey: the eleven round keys of the AES-128 key at rsi, to RK (clobbers eax, ecx, edi,
; r8, xmm0-xmm2)
aeskey: movdqu xmm0, [rsi]
        mov edi, RK
        mov al, 1               ; the round constant: 1, and times x in GF(2^8) each round
        mov cl, 10
.k:     movdqa [rdi], xmm0
        add edi, 16
        aeskeygenassist xmm1, xmm0, 0
        pshufd xmm1, xmm1, 0xFF ; the last word, substituted and rotated, in all four words,
        movzx r8d, al
        movd xmm2, r8d
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

; aesblk: xmm0 = AES of xmm0 under the round keys at RK (clobbers eax)
aesblk: mov eax, RK
        pxor xmm0, [rax]
.r:     add eax, 16
        aesenc xmm0, [rax]
        cmp eax, RK + 144
        jb .r
        aesenclast xmm0, [rax+16]
        ret


; ----------------------------------------------------------------------------

TWO32:  dd 0x4F800000            ; 2^32 as a float

L_DER:  db 32, 7, "derived"
L_SHTS: db 32, 12, "s hs traffic"
L_SATS: db 32, 12, "s ap traffic"
L_CATS: db 32, 12, "c ap traffic"
L_FIN:  db 32, 8, "finished"
L_KEY:  db 32, 3, "key"
L_KEY16: db 16, 3, "key"
L_IV:   db 12, 2, "iv"
TLS13:  db "tls13 "
SIGMA:  db "expand 32-byte k"

%ifndef HOST
CVCTX:  db "TLS 1.3, server CertificateVerify", 0
%include "regs.inc"
GDT:    dq 0
        dq 0x00209A0000000000   ; 8: code, 64-bit
        dq 0x0000920000000000   ; 16: data
GDTR:   dw 23
        dd GDT
%include "gen.inc"
SYNOPT: db 2, 4, 1460 >> 8, 1460 & 255 ; maximum segment size: what fits an Ethernet frame
MSSTAB: dw 216, 536, 1220, 1440 ; the sizes we cut our segments to (the client's, rounded down)
SHTAIL: db 0x13, 0x03, 0x00, 0x00, 0x2e, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04
        db 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20
%else
%include "regs.inc"
%endif
%include "ec.inc"         ; curve programs
