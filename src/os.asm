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
TR      equ BSS + 0x20000   ; handshake transcript
VB      equ BSS + 0x30000   ; what a client record should look like (for its tag)
SB      equ BSS + 0x40000   ; seal scratch: Poly1305 input
OB      equ BSS + 0x50000   ; our answer to one packet (OBMAX bytes)
HB      equ BSS + 0x0C900   ; HMAC buffer (key pad | message)
INFO    equ HB + 64         ; HKDF info is built right where HMAC wants its message
AW      equ BSS + 0x0CB00   ; SHA-256 a..h sliding down 64 dwords, with W[] stored above it
SH      equ AW + 0x124      ; SHA-256 chaining value (just above the window: short offsets)
ST      equ BSS + 0x0CD40   ; ChaCha20 state
KS      equ BSS + 0x0CD80   ; ChaCha20 key stream block (64-byte aligned)
PK      equ BSS + 0x0CDC0   ; Poly1305 key block
XT      equ BSS + 0x0CE00   ; Poly1305 h * r, 17 dwords
PH      equ BSS + 0x0D300   ; Poly1305 h: 17 limbs of 8 bits (the top one: 2) in dwords
RR      equ PH + 72         ; R[0..32] (R[-1] = PH + 68 is junk): see poly1305
SLOTS   equ BSS + 0x0D500   ; key schedule values, 8 x 32 bytes, addressed from ebp
KH      equ BSS + 0x0D600   ; handshake traffic key | 0 counter | iv
CVB     equ BSS + 0x0D680   ; CertificateVerify content to be signed (+ room for padding)
KT      equ BSS + 0x0D800   ; SHA-256 round constants (computed at boot), 64 dwords; 512-aligned
HT      equ KT + 0x104      ; SHA-256 initial hash (computed at boot), 8 dwords (+ 56 junk)
MT      equ BSS + 0x0E000   ; Montgomery product, 19 dwords
E       equ K - 32          ; our X25519 secret (32 bytes), then
K       equ REGS - 36       ; the ECDSA nonce (32 bytes, and 4 zero bytes: it is read as 9 limbs),
                            ; right in front of the registers: r is a short offset away
MN      equ BSS + 0x0E201   ; moduli (made at boot): 8 dwords | 0 | -1/m mod 2^32, and a zero
MP256   equ MN + 44         ; byte in front. n and p of P-256,
M25519  equ MP256 + 44      ; and 2^255 - 19
REGS    equ BSS + 0x0E400   ; the curve machine's 16 registers of 9 limbs (not in the image's
                            ; page: TCG takes a slow path for every write to a page with code)
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
HSNEXT  equ NV + 4          ; handshake buffers given out so far
NOW     equ NV + 8          ; when the frame came, in units of 2^37 cycles (a byte: see C_AGE)
TXK     equ NV + 12         ; 1: frames are queued that the device has not been told about
TT      equ NV + 16         ; the table of TLS connections: address (a qword), number of buckets
PT      equ NV + 32         ; the table of connections to port 80: the same
HKS     equ BSS + 0x0F400   ; the eleven round keys of `prf`, made at boot
HKO     equ HKS + 176       ;   and its output
KA      equ BSS + 0x0F300   ; application keys as `keys` makes them (2 x 48 bytes + 20 of junk)
VQ      equ 0x400000        ; the two rings, 64 KiB apart (enough for queues of 1024)
RXB     equ 0x500000        ; receive buffers, 2 KiB each (12-byte virtio header + frame)
TXB     equ 0x700000        ; transmit buffers, the same
%ifndef OURIP
%define OURIP 0x0F02000A    ; 10.0.2.15, as it is on the wire (make IP=a.b.c.d)
%endif
OOP     equ 0xC00000        ; segments that came early: OON places of 2 KiB (see `oohold`)
OON     equ 1024
OO_TAG  equ 0               ;   whose it is: a word of the client's hash (0: nobody's)
OO_SEQ  equ 4               ;   its sequence number,
OO_LEN  equ 8               ;   length
OO_FIN  equ 12              ;   and whether it had a FIN
OO_DATA equ 16
TABV    equ 0x1000000       ; the table space: from 16 MiB up (see the top of this file)
HSP     equ TABV            ; handshake buffers: HSN of 16 KiB, given out in a circle
HSN     equ 1024
HS_SHIFT equ 14
HS_OWNER equ 0              ;   the connection it belongs to (a qword)
HS_FLEN equ 8               ;   length of our flight (0: not sent yet)
HS_CH   equ 16              ;   the ClientHello record as far as it has arrived (up to CHMAX)
HS_FL   equ 0x1000          ;   our flight, as it was sent
CHMAX   equ 0xF00
%if CHAIN_LEN + 1024 > (1 << HS_SHIFT) - HS_FL
%error "the certificate chain is too long for a handshake buffer"
%endif
CONNS   equ HSP + (HSN << HS_SHIFT) ; the connection tables, from here to the end of the table
                            ; space (sized and zeroed at boot): first the one for TLS, then
                            ; the one for port 80
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

; A connection's slot. One for port 80 is the first PSLOT bytes; one for TLS has it all.
C_IP    equ 0               ; the client's address (0: the slot is free)
C_PORT  equ 4               ; and port (a word)
C_FLG   equ 6               ; a byte: F_CLOSED, F_DEFER, which segment size the client takes
F_CLOSED equ 1              ;   (bits 2-3: MSSTAB), on port 80 whether a line has just ended (bit 7)
F_DEFER equ 2               ; F_CLOSED: FINs exchanged, but the client lacks something
F_DEFER_BIT equ 1           ; F_DEFER: its data is not acknowledged before it has our answer
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
        global sha256, hmac, expand, seal, shaconst, x25519, sigr, signs
        global E, K, REGS
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
        sub rbx, CONNS - TABV   ; what the two tables have:
        mov rax, rbx            ; for TLS a share of that memory,
        shr rax, TSHARE + 11    ; in buckets (of BUCKET * TSLOT = 2048 bytes)
%ifdef CAP                      ; (make CAP=n: no more than n slots in each table, to test full ones)
        cmp rax, CAP / BUCKET
        jbe .tc
        mov eax, CAP / BUCKET
.tc:
%endif
        mov edi, TT
        mov dword [rdi], CONNS
        mov [rdi+8], eax
        shl rax, 11
        sub rbx, rax            ; and for port 80 the rest
        add rax, CONNS
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
        mov esi, REGC
        xor ecx, ecx
        mov edi, R_GX           ; the constant registers: x(G) R, 4b R, d R, 1
.cr:    mov cl, 32              ; three of them, 8 limbs each: the 9th stays 0
        rep movsb
        scasd
        bt edi, 8               ; that bit is first set at ONE (checked where REGS is laid out)
        jnc .cr
        inc byte [rdi]          ; ONE
        mov dword [rdi+R_A24+4-R_ONE], 4623270 ; 121665 R mod 2^255 - 19 (R = 2^288 = 38 * 2^32)
        mov byte [rdi+R_NINE-R_ONE], 9 ; the X25519 base point
        mov edi, MN             ; the moduli. n: its low half is data, then FFFFFFFF FFFFFFFF
        movsd                   ; 0 FFFFFFFF
        movsd
        movsd
        movsd
        or eax, -1
        stosd
        stosd
        scasd
        stosd
        scasd
        movsd                   ; -1/n
        scasd
        stosd                   ; p256: FFFFFFFF x 3, 0 x 3, 1, FFFFFFFF; -1/p = 1
        stosd
        stosd
        add edi, 12
        inc dword [rdi]
        scasd
        stosd
        scasd
        inc dword [rdi]
        scasd
        scasd
        push -19                ; 2^255 - 19; -1/p = 0x286BCA1B
        pop rax
        stosd
        or eax, -1
        mov cl, 6
        rep stosd
        shr eax, 1
        stosd
        scasd
        mov dword [rdi], 0x286BCA1B
%ifdef HOST
        popad
        ret
%else

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

.poll:  mov esi, [Q0+8]         ; used ring: anything new?
        mov eax, [Q0+Q_SEEN]
        cmp ax, [rsi+2]
        jne .frame
        call txkick             ; no: time to tell the device what we have queued for it
        pause
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
        mov [RXLEN], ecx
        xor edi, edi            ; FR
        rep movsb
        mov esi, [Q0+4]         ; give the buffer back
        movzx eax, word [rsi+2]
        and eax, [Q0+12]
        mov [rsi+4+rax*2], dx
        inc word [rsi+2]
        mov esi, [Q0+8]
        test byte [rsi], 1      ; the device says when it doesn't need to be told
        jnz .nk
        mov rdx, [Q0+Q_NOTE]
        mov word [rdx], 0
.nk:
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
        test byte [Q0+Q_SEEN], 31 ; (if frames keep coming, every 32 of them)
        jnz .poll
        call txkick
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
        mov ebx, [Q1+4]         ; available ring
        mov esi, [Q1+8]         ; used ring
        movzx eax, word [rbx+2]
.full:  mov edx, eax
        sub dx, [rsi+2]
        cmp dx, [Q1+12]
        jbe .room
        call txkick
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
        mov rax, [Q1+Q_NOTE]
        mov word [rax], 1       ; notify queue 1
.no:    pop rax
        ret

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
        jnz .syn
        test rbp, rbp
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
        push rcx
        mov rdi, rbp
        push PSLOT / 4
        pop rcx
        cmp [rbx+P_PORTS+2], bl
        je .mk
        mov cl, C_KIV / 4       ; (a slot of the TLS table goes on)
.mk:    xor eax, eax
        rep stosd
        pop rcx
        mov eax, [rbx+P_IP]
        mov [rbp+C_IP], eax
        mov eax, [rbx+P_PORTS]
        mov [rbp+C_PORT], ax
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
        btr dword [rbp+C_FLG], F_DEFER_BIT ; If that was an answer of several segments, its
        jnc .ak1                ; data is acknowledged only now
        inc byte [rbx+P_MORE]
        jmp .ak1
.odd:   call ckx                ; not an ack for this connection: for a new one from the same
        jz .make                ; address and port (whose predecessor we never saw end)?
        jmp .ak
.ak0:   inc edx
        test eax, eax
        jnz .ak1
        inc edx
.ak1:   add [rbp+C_ACK], eax
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
        push rdx
        push rax
        push rbx
        inc dword [rbp+C_ST]
        lea esi, [rbx+HS_CH+5]
        lea ecx, [rax-5]
        icall handshake         ; edi = end of our flight
        pop rbx
        mov ecx, edi            ; keep the flight: a client that sends its ClientHello again
        sub ecx, OB             ; has to get this one again (it may have got it already)
        mov [rbx+HS_FLEN], ecx
        push rdi
        mov esi, OB
        lea edi, [rbx+HS_FL]
        rep movsb
        pop rdi
        pop rax
        pop rcx
        sub ecx, eax            ; (anything behind the ClientHello is the first record)
        lea esi, [rbx+HS_CH+rax]
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
        sub edi, 16
        add esi, ecx
        push 16
        pop rcx
        repe cmpsb
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
.free:  cmp dword [rbp+C_IP], 0
        je .miss
        add rbp, rcx
        jmp .free
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
.young: pop rax
.nx:    add rbp, rcx
        dec dh
        jnz .s
        ret

; prf: HKO = a keyed hash of the client's address and ports (and ours: twelve bytes of the
; frame): eleven rounds of AES, as the processor has them, with round keys that are simply
; random, made at boot (HKS). Its four words pick the two buckets (0, 1), make the cookie
; (2: W) and place a segment kept for later (3). (Clobbers esi and ecx.)
prf:    movdqu xmm0, [abs P_IP]     ; the addresses and ports, and four bytes behind them
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
; until what comes before it is here (`.reply` in `tcp`). There are OON places for such
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
        and edx, OON - 1
        shl edx, 11
        add edx, OOP
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

; hsnew: ebx = a handshake buffer for connection ebp: the next in a circle. Whoever had it
; loses it (HS_OWNER says whose it is): a ClientHello that was arriving in pieces is then
; never finished, and a flight can't be sent a second time.
hsnew:  mov ebx, [HSNEXT]
        inc dword [HSNEXT]
        and ebx, HSN - 1
        inc ebx
        mov [rbp+C_HS], bx
        dec ebx
        shl ebx, HS_SHIFT
        add ebx, HSP
        mov [rbx+HS_OWNER], rbp
        and dword [rbx+HS_FLEN], 0
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
; handshake: ClientHello message at esi (ecx bytes), connection at ebp.
; Writes ServerHello + encrypted flight to OB, returns edi = end. Clobbers all but ebp.
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
        mov edi, E              ; fresh secrets: X25519 scalar and ECDSA nonce
        mov cl, 16              ; (ecx = 0 after the copy above)
.rnd:   rdrand eax
        jnc .rnd
        stosd
        loop .rnd
        mov edi, ebx
        movzx edx, byte [rsi+38] ; session id length
        lea ecx, [rdx+39]
        rep movsb               ; ServerHello: ClientHello's random + session id ...
        mov esi, SHTAIL
        mov cl, 19
        rep movsb               ; ... + suite, extensions, key share header ...
        mov esi, R_NINE
        icall x25519
        mov esi, R_X2
        mov cl, 8
        rep movsd               ; ... + our key share
        pop rsi
        lodsd
        icall x25519             ; X2 = the shared secret
        lea eax, [rdx+86]
        shl eax, 24
        mov al, 2
        mov [rbx], eax          ; type 2, length

        mov ebp, SLOTS + 128    ; key schedule up to the handshake secret
        push rbx
        mov esi, CVB            ; (ecx = 0 after the copy above)
        lea edi, [rbp+S_EH]
        icall sha256             ; SHA256("")
        lea ebx, [rbp+S_Z]
        mov esi, ebx
        mov cl, 32
        lea edi, [rbp+S_ES]
        icall hmac               ; early secret
        mov ebx, edi
        mov esi, R_X2
        lea edi, [rbp+S_HS]
        icall stage              ; handshake secret
        icall sigr               ; r and 1/k for the CertificateVerify (in X2 and T1)
        pop rbx

        mov edi, CVB            ; CertificateVerify content: 64 spaces | context | hash
        mov al, 0x20
        mov cl, 64
        rep stosb
        mov esi, CVCTX
        mov cl, 34
        rep movsb
        ; Grind our server random until s is a plain 32-byte DER INTEGER (0 < s[0] < 0x80),
        ; like r: about 2 tries, and the CertificateVerify has a fixed size. (r and the nonce
        ; stay: only the one signature that is sent ever leaves this machine.)
.retry: inc byte [rbx+6]
        lea eax, [rbx+rdx+90]   ; P1 = end of ServerHello
        icall thash
        push rbx
        push rdx
        lea ebx, [rbp+S_HS]
        mov esi, L_SHTS
        lea edx, [rbp+S_TH]
        lea edi, [rbp+S_TS]
        icall expand             ; server handshake traffic secret
        pop rdx
        pop rbx
        xchg eax, edi           ; EncryptedExtensions + Certificate (after thash: it pads in place)
        mov esi, EECERT
        mov ecx, EECERT_LEN
        rep movsb
        xchg eax, edi           ; eax = P2
        icall thash
        lea esi, [rbp+S_TH]
        mov edi, CVB+98
        mov cl, 32
        rep movsb
        mov esi, CVB
        mov cl, 130
        lea edi, [rax+46]
        icall sha256             ; the hash to sign (parked where s will go)
        pushad
        mov esi, edi
        mov edi, R_U
        icall rev32              ; as a number
        mov ebp, MN
        mov esi, SIGN
        call vm                 ; Z2 = s = (hash + r d) / k
        cmp byte [rdi+R_Z2+31-R_U-32], 0 ; (edi = U + 32 after rev32)
        popad                   ; (keeps the flags)
        jle .retry
        xchg eax, edi
        mov esi, CVT            ; 0f 00 00 4a | 04 03 | 00 46 | 30 44 02 20
        mov cl, 12
        rep movsb
        mov esi, R_X2
        icall rev32              ; r
        mov ax, 0x2002
        stosw
        add esi, 36
        icall rev32              ; s
        xchg eax, edi           ; eax = P3 = end of CertificateVerify

        mov edi, OB             ; ServerHello record (the random is final now)
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
        icall keys               ; handshake key and iv

        mov esi, L_FIN
        xor edx, edx
        lea edi, [rbp+S_D]
        icall expand
        mov ebx, edi            ; finished key
        icall thash
        xchg eax, edi
        mov eax, 0x20000014
        stosd
        lea esi, [rbp+S_TH]
        mov cl, 32              ; (ecx = 0 after the copy above)
        icall hmac
        add edi, ecx
        mov byte [rdi], 0x16    ; inner content type: handshake
        xchg eax, edi

        pop rdi                 ; output position
        pop rsi                 ; P1
        lea ecx, [rax+1]
        sub ecx, esi
        mov ebx, KH
        xor edx, edx
        icall seal               ; edi = end of output

        icall thash              ; application traffic secret
        lea ebx, [rbp+S_HS]
        lea esi, [rbp+S_Z]
        push rdi
        lea edi, [rbp+S_ES]
        icall stage              ; master secret
        mov ebx, edi
        mov esi, L_CATS
        lea edx, [rbp+S_TH]
        lea edi, [rbp+S_D]
        icall expand             ; client application traffic secret
        mov ecx, edi
        mov esi, L_SATS
        lea edi, [rbp+S_TS]
        icall expand             ; server application traffic secret
        mov ebx, edi
        pop rax                 ; end of output
        pop rbp
        mov edi, KA
        icall keys
        mov ebx, ecx
        add edi, 48
        icall keys
        mov esi, KA             ; (`keys` writes 20 bytes too many: not into the connection)
        lea rdi, [rbp+C_KIV]
        push 24
        pop rcx
        rep movsd
        xchg eax, edi
        fret

; thash: TH slot = SHA256(transcript up to eax)
thash:
        pushad
        mov esi, TR
        mov ecx, eax
        sub ecx, esi
        lea edi, [rbp+S_TH]
        icall sha256
        popad
        fret

; stage: edi = HKDF-Extract(Derive-Secret(ebx, "derived", ""), 32 bytes at esi)
stage:
        pushad
        push rsi
        push rdi
        mov esi, L_DER
        lea edx, [rbp+S_EH]
        lea edi, [rbp+S_D]
        icall expand
        mov ebx, edi
        pop rdi
        pop rsi
        push 32
        pop rcx
        icall hmac
        popad
        fret
%endif

; keys: edi = key(32) | 0(4) | iv(12) from traffic secret ebx (+20 junk bytes: expand writes 32)
keys:
        pushad
        xor edx, edx
        mov esi, L_KEY
        icall expand
        add edi, 36
        mov [rdi-4], edx        ; block counter 0 (slots near 16 MiB hold SeaBIOS tables)
        add esi, L_IV - L_KEY
        icall expand
        popad
        fret

; ----------------------------------------------------------------------------
; sha256: edi = SHA-256 of ecx bytes at esi. Pads in place: esi[ecx .. ecx+72) is clobbered.
sha256:
        pushad
        push rdi
        lea edi, [rsi+rcx]
        lea eax, [rcx+72]
        and al, 0xC0
        sub eax, ecx            ; padding bytes
        shl ecx, 3
        bswap ecx
        xchg eax, ecx           ; eax = bit length, big-endian
        push rax
        mov al, 0x80
        stosb
        dec ecx
        xor eax, eax
        rep stosb
        pop rax
        mov [rdi-4], eax
        push rdi                ; end of padded message
        push rsi
        mov esi, HT
        mov edi, SH
        mov cl, 8
        rep movsd
        pop rsi
.blk:   push rsi
        lea esi, [rdi-32]       ; SH: edi = SH + 32 here, from the copy above or the sum below
        sub edi, SH+32-(AW+256)
        mov cl, 8
        rep movsd
        pop rsi
        sub edi, 32             ; a..h at [edi]; W[i-k] sits at [edi+32+4k] (window slides down)
        push -64
        pop rbp                 ; round - 64
.rnd:   call wnext
        mov [rdi+32], eax       ; W[i], over the h that the previous round dropped
        add eax, [KT+256+rbp*4]
        add eax, [rdi+28]
        xchg eax, ebx           ; h + k + w
        mov eax, [rdi+16]
        mov ecx, 0x190B06       ; S1: ror 6, 11, 25
        call sigma
        add ebx, edx
        mov edx, [rdi+20]
        xor edx, [rdi+24]
        and edx, eax
        xor edx, [rdi+24]       ; ch(e, f, g)
        add ebx, edx            ; t1
        add [rdi+12], ebx       ; new e = d + t1
        mov eax, [rdi]
        mov ecx, 0x160D02       ; S0: ror 2, 13, 22
        call sigma
        add ebx, edx
        mov edx, [rdi+4]
        xor eax, edx
        xor edx, [rdi+8]
        and eax, edx
        xor eax, [rdi+4]        ; maj(a, b, c) = ((a ^ b) & (b ^ c)) ^ b
        add ebx, eax            ; (ecx is still 0 from sigma: no other temporary)
        sub edi, 4
        mov [rdi], ebx          ; new a = t1 + t2
        inc rbp
        jnz .rnd
        push rsi                ; chaining value += a..h
        mov esi, edi
        mov edi, SH
        mov cl, 8
.add:   lodsd
        add [rdi], eax
        scasd
        loop .add
        pop rsi
        cmp rsi, [rsp]
        jb .blk
        pop rax
        lea esi, [rdi-32]       ; SH
        pop rdi
        mov cl, 8
.out:   lodsd
        bswap eax
        stosd
        loop .out
        popad
        fret

; sigma: edx = xor of eax rotated by each count byte in ecx (count | 0x20 = shift instead)
sigma:
        xor edx, edx
.s:     push rax
        test cl, 0x20
        jnz .sh
        ror eax, cl
        jmp .x
.sh:    shr eax, cl
.x:     xor edx, eax
        pop rax
        shr ecx, 8
        jnz .s
        ret

; wnext: eax = message schedule word W[ebp + 64] (window at edi, message at esi)
wnext:  cmp ebp, 16-64
        jge .sch
        lodsd
        bswap eax
        ret
.sch:   mov eax, [rdi+92]       ; W[i-15]
        mov ecx, 0x231207       ; s0: ror 7, ror 18, shr 3
        call sigma
        push rdx
        mov eax, [rdi+40]       ; W[i-2]
        mov ecx, 0x2A1311       ; s1: ror 17, ror 19, shr 10
        call sigma
        pop rax
        add eax, edx
        add eax, [rdi+96]       ; W[i-16]
        add eax, [rdi+60]       ; W[i-7]
        ret

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
; Elliptic curves: 256-bit arithmetic mod m, lazily reduced, in a 16-register machine.
; tools/ec.py has the programs, the bounds that make this safe, and a model of all of it.
; A modulus is: m (8 dwords) | 0 | -1/m mod 2^32, with a zero byte in front; ebp points at it.
; (All three are built at boot.)
R_U     equ REGS + 0*36
R_X2    equ REGS + 1*36         ; r after sigr
R_Z2    equ REGS + 2*36         ; s after SIGN
R_GX    equ REGS + 5*36         ; 5-8: x(G) R, 4b R, d R, 1 (copied from the image at boot)
R_ONE   equ REGS + 8*36
R_A24   equ REGS + 9*36         ; 9, 10: set at boot
R_NINE  equ REGS + 10*36
R_T0    equ REGS + 12*36
R_T1    equ REGS + 13*36
%if ((0xE400 + 6*36) | (0xE400 + 7*36)) & 0x100 || ((0xE400 + 8*36) & 0x100) = 0
%error "REGS: bit 8 must first be set at R_ONE (boot copies the constants up to there)"
%endif

; x25519: X2 = X25519(E, 32 bytes at esi). E is used as it is, unclamped: the other side
; only needs it to be the same number in our key share and in the secret.
x25519: pushad
        mov edi, R_U
        push 8
        pop rcx
        rep movsd
        mov ebp, M25519
        lea ebx, [rdi+E-R_U-32]
        mov esi, INIT25519
        call smult
        popad
        fret

; sigr: the half of an ECDSA signature that needs no message. X2 = r = x(K G), where K is
; stepped until r is a plain 32-byte DER INTEGER (0 < r[0] < 0x80); T1 = R^2 / K mod n.
sigr:   pushad
        mov ebx, K
        mov ebp, MP256
.again: inc dword [rbx]
        mov esi, INIT256
        call smult
        cmp byte [rbx+R_X2+31-K], 0
        jle .again
        sub ebp, MP256 - MN
        mov esi, ebx
        icall inv
        popad
        fret

; smult: X2 = x of (256-bit number at ebx) * the base point, mod the modulus at ebp, canonical.
; esi = init program, followed by the ladder step program.
smult:  call vm
        xor ecx, ecx
        dec cl                  ; bit 255
.l:     bt [rbx], ecx
        sbb edx, edx
        call cswap              ; the step doubles (X2 : Z2) and adds it to (X3 : Z3)
        push rsi
        call vm
        pop rsi
        call cswap
        dec ecx
        jns .l
        mov esi, R_Z2
        icall inv
        mov esi, FIN            ; X2 = X2 / Z2
        ; fall through
; vm: run the program at esi (2 bytes per operation: a << 4 | b, op << 4 | dst; a zero
; byte ends it). Returns esi = after the program; keeps everything else but eax.
vm:     lodsb
        test al, al
        jz vmret
        inc esi
        pushad
        movzx edx, word [rsi-2]
        push vmnext             ; where the operation returns to
        push 3
        pop rcx
.r:     mov eax, edx
        and eax, 15
        imul eax, eax, 36
        add eax, REGS
        push rax
        shr edx, 4
        loop .r
        pop rdi                 ; dst
        pop rsi                 ; a
        pop rbx                 ; b
        dec edx
        jz vadd                 ; (ecx = 0)
        dec edx
        jnz montmul
        inc ecx
        call vadd               ; sub: a - b + 256 m (the modulus, read one byte early)
        dec ecx
        mov esi, edi
        lea ebx, [rbp-1]
        jmp vadd
vmnext: popad
        jmp vm

; vadd: 9 limbs at edi = those at esi + those at ebx if ecx = 0; minus them if ecx = 1
; (a - b = a + ~b + 1; not, jecxz, dec and lea leave the carry alone)
vadd:   pushad
        push 9
        pop rdx
        neg ecx                 ; CF = 1 to subtract
.l:     lodsd
        mov ebp, [rbx]
        jrcxz .a
        not ebp
.a:     adc eax, ebp
        stosd
        lea ebx, [rbx+4]
        dec edx
        jnz .l
        popad
vmret:  ret

; montmul: 9 limbs at edi = (those at esi) * (those at ebx) / 2^288 mod m, not fully reduced
montmul:
        pushad
        mov edi, MT
        push 19
        pop rcx
        xor eax, eax
        rep stosd
        sub edi, 76
        mov cl, 9
.i:     lodsd                   ; MT += a[i] * b * 2^32i
        push rsi
        mov esi, ebx
        call mulrow
        mov esi, ebp            ; then += m * whatever zeroes limb i
        mov eax, [rdi]
        imul eax, [rbp+36]
        call mulrow
        scasd
        pop rsi
        loop .i
        mov esi, edi            ; the upper half is the result
        mov edi, [rsp]
        mov cl, 9
        rep movsd
        popad
        ret

; mulrow: the 11 limbs at edi += eax * the 9 limbs at esi
mulrow: pushad
        xchg eax, ebp
        xor ebx, ebx            ; carry
        push 9
        pop rcx
.l:     lodsd
        mul ebp
        add eax, ebx
        adc edx, 0
        add [rdi], eax
        adc edx, 0
        mov ebx, edx
        scasd
        loop .l
        add [rdi], ebx
        adc dword [rdi+4], 0
        popad
        ret

; cswap: swap (X2, Z2) with (X3, Z3) if edx = -1, not if edx = 0
cswap:  pushad
        mov esi, R_X2
        lea edi, [rsi+72]
        push 18
        pop rcx
.s:     mov eax, [rsi]
        xor eax, [rdi]
        and eax, edx
        xor [rsi], eax
        xor [rdi], eax
        cmpsd
        loop .s
        popad
        ret

; inv: T1 = (9 limbs at esi) ^ (m - 2), which is R^2 / it for a stored value. Clobbers T0, T2.
inv:    pushad
        mov edi, R_T0
        push 9
        pop rcx
        rep movsd               ; T0 = x
        lea esi, [rdi-36]
        mov cl, 9
        rep movsd               ; T1 = x (bit 0 of m - 2 is set)
        mov esi, ebp            ; T2 = the exponent
        mov cl, 8
        rep movsd
        lea edx, [rdi-32]
        sub byte [rdx], 2       ; (no borrow: our moduli end in a byte >= 2)
        lea edi, [rdx-72]       ; T0
        mov esi, edi
        mov ebx, edi
        inc ecx                 ; bit 1
.l:     call montmul            ; T0 = T0^2
        bt [rdx], ecx
        jnc .s
        pushad
        add edi, 36
        mov esi, edi
        call montmul            ; T1 = T1 * T0
        popad
.s:     inc cl
        jnz .l
        popad
        fret

%ifdef HOST
signs:  pushad                  ; (test only: what the handshake does inline)
        mov ebp, MN
        mov esi, SIGN
        call vm
        popad
        ret
%endif

; rev32: the 32 bytes at esi, reversed, to edi (edi += 32; clobbers al, ecx = 0)
rev32:  push 32
        pop rcx
.l:     mov al, [rsi+rcx-1]
        stosb
        loop .l
        fret

; ----------------------------------------------------------------------------
; chacha: edi = ChaCha20 block of the 16-dword state at esi
chacha:
        pushad
        push rsi
        push rdi
        push 16
        pop rcx
        rep movsd
        pop rbp                 ; working state
        xor ecx, ecx            ; quarter round 0..79
.qr:    push rcx
        mov eax, ecx
        shl al, 2               ; column * 4 (masked below; al only, so no bit 8 sneaks in)
        and ecx, 4              ; diagonal rounds: shift the column by 4 bytes per row
        mov ebx, ebp
        mov dl, 4
.m:     and al, 12
        lea esi, [rbx+rax]
        push rsi
        add eax, ecx
        add ebx, 16
        dec dl
        jnz .m
        pop rdi                 ; d
        pop rdx                 ; c
        pop rbx                 ; b
        pop rsi                 ; a
        mov ecx, 0x07080C10
.st:    mov eax, [rbx]          ; P += Q; R ^= P; R <<<= n; then (P,Q,R) = (other,R,Q)
        add [rsi], eax
        mov eax, [rsi]
        xor [rdi], eax
        rol dword [rdi], cl
        xchg esi, edx
        xchg ebx, edi
        shr ecx, 8
        jnz .st
        pop rcx
        inc ecx
        cmp cl, 80
        jne .qr
        pop rsi
        mov edi, ebp
        mov cl, 16
.ad:    lodsd
        add [rdi], eax
        scasd
        loop .ad
        popad
        fret

; seal: TLS 1.3 record at edi for ecx plaintext bytes at esi (last byte = inner content type),
; key|0|iv at ebx, sequence number edx. Returns edi = end of record.
; With CF set the bytes at esi are copied instead of encrypted: the record a peer should have
; sent for that ciphertext, whose tag the caller compares.
seal:
        pushad
        sbb ebp, ebp            ; CF: the "plaintext" is ciphertext already, just make its tag
        push rdi                ; o
        push rcx                ; n
        push rsi                ; m
        mov edi, ST             ; ChaCha state: constants | key | 0 counter | iv ^ seq
        mov esi, SIGMA
        movsd
        movsd
        movsd
        movsd
        mov rsi, rbx
        push 12
        pop rcx
        rep movsd
        bswap edx
        xor [rdi-4], edx
        lea esi, [rdi-64]       ; ST
        add edi, 64             ; PK = ST + 128
        icall chacha             ; block 0: Poly1305 key
        mov edi, SB             ; SB = header, 0 pad | ciphertext, 0 pad | lengths
        mov al, 0x17
        stosb
        mov al, 3
        stosb
        stosb
        mov ecx, [rsp+8]
        lea eax, [rcx+16]
        xchg al, ah
        stosw
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
.ks:    push rsi
        push rdi
        mov esi, ST
        inc dword [rsi+48]      ; next counter
        lea edi, [rsi+64]       ; KS = ST + 64 (64-byte aligned)
        mov edx, edi
        icall chacha
        pop rdi
        pop rsi
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
        mov byte [rdi], 5       ; aad length
        mov [rdi+8], ecx        ; ciphertext length
        lea edx, [rdi+16-SB]
        shr edx, 4              ; Poly1305 blocks
        pop rdi                 ; o
        mov esi, SB
        movsd                   ; record header
        movsb
        add esi, 11
        rep movsb               ; ciphertext
        mov ebx, PK
        ; Poly1305 tag of the edx 16-byte blocks at SB, key at PK (r is clamped in place).
        ; h has 17 limbs of 8 bits (the top one 2, plus a little), in dwords. With R[16 + j] = r[j] and
        ; R[j - 1] = 320 r[j] (2^136 = 320 mod 2^130 - 5), limb k of h * r = sum_i h[i] * R[16 + k - i].
        push rdi                ; where the tag goes
        mov eax, 0x0FFFFFFF
        and [rbx], eax
        mov al, 0xFC
        and [rbx+4], eax
        and [rbx+8], eax
        and [rbx+12], eax
        mov edi, PH
        push 17
        pop rcx
        xor eax, eax
        rep stosd               ; h = 0
        mov esi, ebx
        add edi, 68             ; &R[16]
        mov cl, 16
.r:     lodsb                   ; (R[15] = 320 r[16] and R[32] = r[16] are 0: never written)
        stosd
        imul ebp, eax, 320
        mov [rdi-72], ebp
        loop .r
        mov ecx, edx            ; blocks
        mov esi, SB
.blk:   push rcx
        mov edi, PH             ; h += block + 2^128 (eax < 256 here)
        mov cl, 16
.m:     lodsb
        add [rdi], eax
        scasd
        loop .m
        inc dword [rdi]
        push rsi
        mov edi, XT             ; XT = h * r: under 2^30 per limb
        mov ebx, RR + 64
        mov cl, 17
.k:     push rcx
        mov esi, PH
        mov edx, ebx
        xor ebp, ebp
        mov cl, 17
.i:     lodsd
        imul eax, [rdx]
        add ebp, eax
        sub edx, 4
        loop .i
        xchg eax, ebp
        stosd
        add ebx, 4
        pop rcx
        loop .k
        xor ebx, ebx            ; carry XT back into h, then twice more in place: 2^130
        mov dl, 3               ; wraps as 5 (the 3rd pass only ripples a carry or two)
        mov esi, XT
.pass:  mov edi, PH
        mov cl, 16
.c:     lodsd
        add ebx, eax
        movzx eax, bl
        sar ebx, 8
        stosd
        loop .c
        lodsd
        add ebx, eax
        mov eax, ebx
        and eax, 3
        stosd                   ; (leaves eax < 4 for the next block's lodsb)
        sar ebx, 2
        lea ebx, [rbx+rbx*4]
        lea esi, [rdi-68]
        dec dl
        jnz .pass
        pop rsi
        pop rcx
        loop .blk
        pop rdi
        mov ebx, PK+16
        mov esi, PH
        mov cl, 16
        xor edx, edx
.t:     lodsd                   ; tag = h + s mod 2^128
        add edx, eax
        movzx eax, byte [rbx]
        inc ebx
        add edx, eax
        mov [rdi], dl
        inc edi
        shr edx, 8
        loop .t
        mov [rsp], edi
        popad
        fret


; ----------------------------------------------------------------------------

TWO32:  dd 0x4F800000            ; 2^32 as a float

L_DER:  db 32, 7, "derived"
L_SHTS: db 32, 12, "s hs traffic"
L_SATS: db 32, 12, "s ap traffic"
L_CATS: db 32, 12, "c ap traffic"
L_FIN:  db 32, 8, "finished"
L_KEY:  db 32, 3, "key"
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
