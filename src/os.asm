; os.asm - bare-metal HTTPS server, flat image loaded at 1 MiB (nasm -f bin)
;
; Boot: by src/boot.asm from a disk, or as a multiboot v1 "a.out kludge" kernel (GRUB,
;       `qemu -kernel`). Sets up its own segments, stack and zeroed memory.
; NIC:  virtio-net (modern PCI interface), polled. Our IP is baked in (OURIP).
; TCP:  ports 443 (TLS) and 80 (the same page without); see `tcp`.
; TLS:  1.3, TLS_CHACHA20_POLY1305_SHA256, X25519, ecdsa_secp256r1_sha256.
; Like k2, and unlike k1, this one is meant to be secure: a fresh X25519 key and a fresh ECDSA nonce per
; handshake (rdrand), a real certificate chain, and client records are authenticated before
; they get an answer. See CLAUDE.md for the shortcuts that remain.
;
; Convention: every routine preserves all registers (pushad/popad) unless it
; says otherwise. All buffers live at fixed addresses in zeroed RAM at 2 MiB.

BITS 32
%include "conf.inc"             ; CHAIN_LEN

BSS     equ 0x200000
FR      equ 0               ; the Ethernet frame being handled. At address 0 (old real-mode
                            ; IVT, unused), so `xor reg, reg` loads it and its fields are a
P_IP    equ FR + 26         ; byte away: the client's address,
P_PORTS equ FR + 34         ;   its port and ours (as on the wire),
P_SEQ   equ FR + 38         ;   its sequence number (in host order once `tcp` has started;
                            ;   moved on past bytes we already had)
P_ACK   equ FR + 42         ;   its ack (the same)
P_FL    equ FR + 47         ;   its flags
P_MORE  equ FR + 48         ;   (in place of the window) 1: its data is to be acknowledged now
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
IDT     equ M25519 + 40 - 1*8 ; interrupt gates, from vector 1 (built at boot)
REGS    equ BSS + 0x0E400   ; the curve machine's 16 registers of 9 limbs (not in the image's
                            ; page: TCG takes a slow path for every write to a page with code)
VST     equ BSS + 0x0F000   ; virtio-net driver state:
VCAP    equ VST + 96        ;   where the device's structures are, by type (1 common, 2 notify, 4 device)
VMUL    equ VST + 128       ;   (the dword read after each: for notify, its offset multiplier)
MAC     equ VST + 4         ;   our MAC address (6 bytes, from the device)
Q0      equ VST + 16        ;   receive queue: desc, avail, used (addresses), size - 1, used entries seen, notify address
Q1      equ VST + 48        ;   transmit queue, the same
KST     equ VST + 160       ;   reset knock: 1 after the first port (development builds)
NV      equ BSS + 0x0F200
RXLEN   equ NV              ; the length of the frame in FR
HSNEXT  equ NV + 4          ; handshake buffers given out so far
NOW     equ NV + 8          ; when the frame came, in units of 2^35 cycles (a byte: see C_AGE)
TT      equ NV + 12         ; the table of TLS connections: address, number of buckets
PT      equ NV + 20         ; the table of connections to port 80: the same
HKS     equ BSS + 0x0F400   ; ChaCha20 state for `prf`: constants, a key made at boot, input
HKO     equ HKS + 64        ;   and its output block
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
HSP     equ 0x1000000       ; handshake buffers: HSN of 16 KiB, given out in a circle
HSN     equ 1024
HS_SHIFT equ 14
HS_OWNER equ 0              ;   the connection it belongs to
HS_FLEN equ 4               ;   length of our flight (0: not sent yet)
HS_CH   equ 16              ;   the ClientHello record as far as it has arrived (up to CHMAX)
HS_FL   equ 0x1000          ;   our flight, as it was sent
CHMAX   equ 0xF00
%if CHAIN_LEN + 1024 > (1 << HS_SHIFT) - HS_FL
%error "the certificate chain is too long for a handshake buffer"
%endif
CONNS   equ 0x2000000       ; the connection tables, from here to the end of memory (sized and
                            ; zeroed at boot): first the one for TLS, then the one for port 80
BUCKET  equ 16              ; slots in a bucket (see `find`)
TSHARE  equ 3               ; the TLS table gets 1/2^TSHARE of that memory
%ifndef IDLE
%define IDLE 32             ; a connection that has been quiet for longer than this (in units of
%endif                      ; 2^35 cycles: 5 to 9 minutes) may be replaced when a new one finds no room
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
C_AGE   equ 7               ; when its last packet came (NOW; a byte)
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

; Routines that are called from several places and not from inner loops are reached through
; interrupt gates: `int n` is 2 bytes (int1 and int3: 1) where a call is 5, and a gate costs 2 bytes
; of table (boot builds the IDT). Such a routine returns with iret, so it can't return flags;
; flags do go in. The host test build calls them the ordinary way.
%ifdef HOST
%macro icall 1
        call %1
%endmacro
%define fret ret
%else
%macro icall 1
%if V_%1 = 3
        int3
%elif V_%1 = 1
        int1
%else
        int V_%1
%endif
%endmacro
%define fret iretd
%endif
GATED equ 0
; Development builds (make DEBUG=1) count things in DBG and show six of the counters, four
; hex digits each, in place of the end of the page on port 80: `count n` adds one to counter n.
DBG     equ BSS + 0x0F500
%macro count 1
%ifdef DEBUG
        inc dword [DBG + 4 * %1]
%endif
%endmacro
%macro gates 1-*
%assign v 1
%rep %0
V_%1    equ v
%assign v v+1
%rotate 1
%endrep
NGATES  equ %0
%endmacro
%macro gatetable 1-*
%rep %0
        dw %1 - mb
%rotate 1
%endrep
%endmacro
%if CHAIN_LEN > 1100            ; (tcp_out is only called, rather than fallen into, for a long chain)
%define GATELIST sha256, hmac, expand, thash, seal, keys, rev32, stage, x25519, inv, chacha, csum, handshake, sigr, tcp
%else
%define GATELIST sha256, hmac, expand, thash, seal, keys, rev32, stage, x25519, inv, chacha, csum, handshake, sigr, tcp
%endif
        gates GATELIST

%ifdef HOST
        section .text
        global sha256, hmac, expand, seal, shaconst, x25519, sigr, signs
        global E, K, REGS
%else
        org 0x100000
mb:     dd 0x1BADB002, 0x00010000, -(0x1BADB002 + 0x00010000)
        dd mb, mb, 0, 0, start

; ----------------------------------------------------------------------------
start:                          ; Entered in 32-bit protected mode by whoever loaded us at 1 MiB
        cli                     ; (boot.asm, GRUB's or QEMU's multiboot). Nothing else is
        cld                     ; assumed: our own segments (the interrupt gates name code
        mov ecx, 255 << 10      ; selector 8), our own stack, and memory we zero ourselves
        cmp eax, 0x2BADB002     ; (a loader, or the system that ran before a reboot, used it).
        jne .nomb               ; What the loader does tell us (multiboot) is how much memory
        test byte [ebx], 1      ; there is in one piece from 1 MiB up, in KiB; 255 MiB if not.
        jz .nomb
        mov ecx, [ebx+8]
.nomb:  lgdt [GDTR]
        jmp 8:.cs
.cs:    push 16
        pop eax
        mov ds, eax
        mov es, eax
        mov ss, eax
        mov esp, BSS            ; the stack grows down from 2 MiB (the image ends far below)
        mov eax, (3 << 20) - (CONNS >> 10) ; (no more than up to 3 GiB: these are 32 bits)
        sub ecx, (CONNS >> 10) - 1024 ; KiB from CONNS up
        cmp ecx, eax
        jbe .mem
        xchg eax, ecx
.mem:   shl ecx, 10             ; bytes from CONNS to the end of memory
        push ecx
        add ecx, CONNS - BSS
        shr ecx, 2
        xor eax, eax
        mov edi, BSS
        rep stosd               ; zero everything from 2 MiB up
        pop ecx
        mov eax, ecx            ; the tables: for TLS a share of that memory,
        shr eax, TSHARE + 11    ; in buckets (of BUCKET * TSLOT = 2048 bytes)
%ifdef CAP                      ; (make CAP=n: no more than n slots in each table, to test full ones)
        cmp eax, CAP / BUCKET
        jbe .tc
        mov eax, CAP / BUCKET
.tc:
%endif
        mov edi, TT
        mov dword [edi], CONNS
        mov [edi+4], eax
        shl eax, 11
        sub ecx, eax            ; and for port 80 the rest
        add eax, CONNS
        mov [edi+8], eax
        xchg eax, ecx
        xor edx, edx
        mov ecx, BUCKET * PSLOT
        div ecx
%ifdef CAP
        cmp eax, CAP / BUCKET
        jbe .pc
        mov eax, CAP / BUCKET
.pc:
%endif
        mov [edi+12], eax
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
.pr:    push ebx
        fild dword [esp]        ; p
        fld st0                 ; y = p
        mov cl, 40
.nw:    fld st0
        fmul st0, st0
        fdivr st0, st2          ; p / y^2
        fadd st0, st1
        faddp st1, st0
        fidiv dword [esp+4]     ; y = (2y + p/y^2) / 3
        loop .nw
        fmul dword [TWO32]
        fisttp qword [edi]      ; low dword = fraction bits (the next entry overwrites the rest)
        fsqrt                   ; (only the first 8 matter; the rest land in junk space)
        fmul dword [TWO32]
        fisttp qword [edi+HT-KT]
        pop eax
        scasd
        bt edi, 8               ; KT is 512-aligned: bit 8 first sets at KT+256
        jnc .np
        pop eax
        mov esi, REGC
        xor ecx, ecx
        mov edi, R_GX           ; the constant registers: x(G) R, 4b R, d R, 1
.cr:    mov cl, 32              ; three of them, 8 limbs each: the 9th stays 0
        rep movsb
        scasd
        bt edi, 8               ; that bit is first set at ONE (checked where REGS is laid out)
        jnc .cr
        inc byte [edi]          ; ONE
        mov dword [edi+R_A24+4-R_ONE], 4623270 ; 121665 R mod 2^255 - 19 (R = 2^288 = 38 * 2^32)
        mov byte [edi+R_NINE-R_ONE], 9 ; the X25519 base point
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
        inc dword [edi]
        scasd
        stosd
        scasd
        inc dword [edi]
        scasd
        scasd
        push -19                ; 2^255 - 19; -1/p = 0x286BCA1B
        pop eax
        stosd
        or eax, -1
        mov cl, 6
        rep stosd
        shr eax, 1
        stosd
        scasd
        mov dword [edi], 0x286BCA1B
%ifdef HOST
        popad
        ret
%else
        scasd                   ; the IDT (vectors 1 up) follows the moduli: offset | cs = 8,
        mov eax, 0x00080000     ; then 0x8E00 (interrupt gate) | 0x0010 (offset bits 16..31)
        mov cl, NGATES
.gt:    lodsw                   ; (esi = GATES, after NLOW)
        stosd
        mov dword [edi], 0x00108E00
        scasd
        loop .gt
        lidt [esi]

        ; virtio-net, modern interface (virtio 1.0; what a cloud's 1AF4:1041 speaks, and a
        ; transitional 1AF4:1000 too): the registers are memory, found through the device's
        ; PCI capabilities. Two queues (0 receive, 1 transmit); descriptor i always points
        ; at buffer i.
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
        pop eax
        call pcird
        or al, 7                ; command: I/O, memory, bus master
        out dx, ax
        push 0x34
        pop eax
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
        lea ebp, [VCAP+eax*4]
        cmp dword [ebp], 0      ; the first of each kind counts
        jne .nxt
        lea eax, [esi+4]
        call pcird
        movzx eax, al           ; which BAR
        lea eax, [eax*4+0x10]
        call pcird
        and eax, -16
        xchg eax, edi
        lea eax, [esi+8]
        call pcird              ; offset inside it
        add eax, edi
        mov [ebp], eax
        lea eax, [esi+16]
        call pcird              ; (notify: the multiplier for queue_notify_off)
        mov [ebp+VMUL-VCAP], eax
.nxt:   movzx esi, ch
        jmp .cap
.caps:  mov ebp, [VCAP+4]       ; common configuration
        mov byte [ebp+20], 0    ; status 0: reset
        mov byte [ebp+20], 3    ; ACKNOWLEDGE | DRIVER
        xor eax, eax
        inc eax
        mov [ebp+8], eax        ; features, word 1: VERSION_1 (bit 32), nothing else:
        mov [ebp+12], eax       ; plain frames behind a 12-byte header
        dec eax
        mov [ebp+8], eax
        mov [ebp+12], eax
        mov byte [ebp+20], 11   ; FEATURES_OK
        mov esi, [VCAP+16]      ; device configuration: the MAC comes first
        mov edi, MAC
        movsd
        movsw
        xor ebx, ebx            ; queue
.q:     mov [ebp+22], bx        ; select it
        movzx ecx, word [ebp+24] ; its size N (a power of two)
        cmp ecx, 1024
        jbe .n
        mov ecx, 1024           ; (what our ring area holds)
        mov [ebp+24], cx
.n:     mov esi, ebx
        shl esi, 5
        add esi, Q0             ; our notes on this queue
        mov edi, ebx
        shl edi, 16
        add edi, VQ
        mov [esi], edi          ; descriptors: 16 N bytes
        mov [ebp+32], edi
        lea eax, [ecx-1]
        mov [esi+12], eax
        mov eax, ecx
        shl eax, 4
        add eax, edi
        mov [esi+4], eax        ; available ring: flags, idx, N entries
        mov [ebp+40], eax
        lea eax, [eax+ecx*2+6+4095]
        and eax, -4096
        mov [esi+8], eax        ; used ring: flags, idx, N x (id, length)
        mov [ebp+48], eax
        push ecx
        imul eax, ebx, TXB - RXB
        add eax, RXB
        mov edx, ebx
        xor dl, 1
        shl edx, 1              ; receive buffers are for the device to write (flag 2)
.desc:  mov [edi], eax
        mov dword [edi+8], 2048
        mov [edi+12], edx
        add eax, 2048
        add edi, 16
        loop .desc
        pop ecx
        test ebx, ebx
        jnz .en
        mov edi, [esi+4]        ; receive: hand all N buffers to the device
        mov [edi+2], cx
        xor eax, eax
.av:    mov [edi+4+eax*2], ax
        inc eax
        cmp eax, ecx
        jb .av
.en:    movzx eax, word [ebp+30] ; where to notify the device about this queue
        imul eax, [VMUL+8]
        add eax, [VCAP+8]
        mov [esi+20], eax
        mov word [ebp+28], 1    ; enable
        inc ebx
        cmp bl, 2
        jb .q
        mov byte [ebp+20], 15   ; DRIVER_OK
        mov edx, [Q0+20]
        mov word [edx], 0       ; notify queue 0: there are buffers

        mov esi, SIGMA          ; the key for `prf`
        mov edi, HKS
        movsd
        movsd
        movsd
        movsd
        push 8
        pop ecx
.hk:    rdrand eax
        jnc .hk
        stosd
        loop .hk

.poll:  pause
        mov esi, [Q0+8]         ; used ring: anything new?
        mov eax, [Q0+16]
        cmp ax, [esi+2]
        je .poll
        inc dword [Q0+16]
        and eax, [Q0+12]
        mov edx, [esi+4+eax*8]  ; buffer id
        mov ecx, [esi+8+eax*8]  ; bytes written, header included
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
        movzx eax, word [esi+2]
        and eax, [Q0+12]
        mov [esi+4+eax*2], dx
        inc word [esi+2]
        mov esi, [Q0+8]
        test byte [esi], 1      ; the device says when it doesn't need to be told
        jnz .nk
        mov edx, [Q0+20]
        mov word [edx], 0
.nk:    pushad
        icall tcp
        popad
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
        movzx eax, word [ebx+2]
.full:  mov edx, eax
        sub dx, [esi+2]
        cmp dx, [Q1+12]
        ja .full
        and eax, [Q1+12]        ; buffer = descriptor = ring position
        shl eax, 11
        add eax, TXB + 12
        mov [esp+16], eax
        popad
        ret

; txgo: send the frame of ecx bytes that was built where txbuf said
txgo:   pushad
        mov ebx, [Q1+4]
        movzx eax, word [ebx+2]
        and eax, [Q1+12]
        mov [ebx+4+eax*2], ax
        shl eax, 4
        add eax, [Q1]
        add ecx, 12
        mov [eax+8], ecx        ; length with the header (12 zero bytes: nobody writes there)
        inc word [ebx+2]
        mov esi, [Q1+8]
        test byte [esi], 1
        jnz .nk
        mov edx, [Q1+20]
        mov word [edx], 1       ; notify queue 1
.nk:    popad
        ret

; ethhdr: at edi (which moves on) the start of a frame to the sender of the one in FR: to its
; address, from ours (clobbers esi)
ethhdr: push 6
        pop esi                 ; FR + 6
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
        cmp word [ebx+12], 0x0608
        jne .ip
        cmp word [ebx+20], 0x0100 ; ARP request for our address: answer it
        jne .ret
        cmp dword [ebx+38], OURIP
        jne .ret
        call txbuf
        mov edi, ebx
        call ethhdr
        push 12                 ; the request's type and header up to the operation,
        pop esi
        push 9
        pop ecx
        rep movsb
        mov al, 2               ; which is: reply. We are its sender,
        stosb
        mov esi, MAC
        movsd
        movsw
        mov eax, OURIP
        stosd
        push 22                 ; the request's sender is its target
        pop esi
        mov cl, 10
        rep movsb
        mov cl, 42
        call txgo
        fret
.ip:    cmp word [ebx+12], 0x0008 ; IPv4, no options, not a fragment, TCP, to us, all of it
        jne .ret                ; in this frame, both checksums right: nothing else gets
        cmp byte [ebx+14], 0x45 ; any further
        jne .ret
        test word [ebx+20], 0xFF3F
        jnz .ret
        cmp byte [ebx+23], 6
        jne .ret
        cmp dword [ebx+30], OURIP
        jne .ret
        movzx ecx, word [ebx+16]
        xchg cl, ch             ; IP total length
        lea eax, [ecx+14]
        cmp eax, [RXLEN]
        ja .bad
        sub ecx, 20             ; TCP length
        cmp ecx, 20
        jb .bad
        push ecx
        lea esi, [ebx+14]
        push 20
        pop ecx
        icall csum
        pop ecx
        test ax, ax
        jnz .bad
        mov [ebx+22], bl        ; the pseudo header, in place: 0, protocol, TCP length, addresses
        mov eax, ecx
        xchg al, ah
        mov [ebx+24], ax
        mov [ebx+ecx+34], bl    ; (a zero byte after an odd length)
        push ecx
        lea esi, [ebx+22]
        add ecx, 12
        icall csum
        pop ecx
        test ax, ax
        jz .sums
        count 1
        fret
.bad:   count 0
.ret:   fret
.sums:
%ifdef KNOCK_A                  ; development builds only (make KNOCK=a,b): a packet to port a,
        movzx eax, word [ebx+36] ; then one to port b, resets the machine, so a test server
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
        cmp word [ebx+36], 0xBB01 ; port 443: TLS
        je .port
        cmp word [ebx+36], 0x5000 ; port 80: the same without
        jne .ret
.port:  cmp [ebx+P_IP], ebx     ; (no client is 0.0.0.0: that marks a free slot)
        je .ret
        movzx eax, byte [ebx+46]
        shr eax, 4
        shl eax, 2              ; TCP header length
        cmp al, 20
        jb .ret
        sub ecx, eax            ; payload length
        jb .ret
        lea esi, [ebx+eax+34]   ; payload
        mov eax, [ebx+P_SEQ]
        bswap eax
        mov [ebx+P_SEQ], eax
        mov eax, [ebx+P_ACK]
        bswap eax
        mov [ebx+P_ACK], eax
        rdtsc                   ; the time, in units of 2^35 cycles (10 to 17 seconds)
        shr edx, 3
        mov [NOW], dl
        mov [ebx+P_MORE], bl
        mov dl, [ebx+P_FL]
        call find               ; ebp = the connection's slot; or, if it has none, eax = -1
        sbb eax, eax            ; and ebp = a slot for a new one (0: there is no room)
        test dl, 4
        jz .nrst
        inc eax                 ; RST: if it is the next thing its connection expects, that
        jz .ret                 ; was the connection
        mov eax, [ebx+P_SEQ]
        cmp eax, [ebp+C_NXT]
        jne .ret
.free:  and dword [ebp+C_IP], 0
        fret
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
        test ebp, ebp
        jz .deny                ; (no room where this connection would go: say so now)
.syn:   movzx ecx, byte [ebx+46] ; its options: how much the client takes in one segment
        shr ecx, 4
        lea ecx, [ecx*4-20]
        lea esi, [ebx+54]
        mov edx, 536            ; (what one that doesn't say must take)
.opt:   cmp ecx, 2
        jl .optd
        lodsb
        dec ecx
        cmp al, 1               ; padding
        je .opt
        jb .optd                ; end of options
        movzx edi, byte [esi]   ; length of this one, with the two bytes that say so
        dec edi
        jle .optd
        cmp edi, ecx
        ja .optd
        cmp al, 2
        jne .onx
        cmp edi, 3
        jne .onx
        movzx edx, word [esi+1]
        xchg dl, dh
.onx:   add esi, edi
        sub ecx, edi
        jmp .opt
.optd:  mov eax, [ebx+P_SEQ]
        lea edi, [eax+1]        ; (the SYN takes a sequence number, and so does ours)
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
        pop ecx
.seg:   call tcp_seg
        fret
.deny:  count 2
        mov al, 0x14            ; RST|ACK: connection refused
        mov edi, [ebx+P_SEQ]
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
        test eax, HINT
        jz .ret
        test dl, 1
        jnz .rst
        test ecx, ecx
        jz .ret
.rst:   count 5
        mov al, 4               ; RST, where the client's ack says
        mov edx, [ebx+P_ACK]
        xor ecx, ecx
        xor edi, edi
        jmp .seg
.full:  count 2                 ; there is no room for it: refused
        jmp .rst
.make:  test ebp, ebp
        jz .full
        push ecx
        mov edi, ebp
        push PSLOT / 4
        pop ecx
        cmp [ebx+P_PORTS+2], bl
        je .mk
        mov cl, C_KIV / 4       ; (a slot of the TLS table goes on)
.mk:    xor eax, eax
        rep stosd
        pop ecx
        mov eax, [ebx+P_IP]
        mov [ebp+C_IP], eax
        mov eax, [ebx+P_PORTS]
        mov [ebp+C_PORT], ax
        mov eax, [ebx+P_SEQ]
        mov [ebp+C_NXT], eax
        mov eax, [ebx+P_ACK]
        mov [ebp+C_SND], eax
        mov [ebp+C_ACK], eax
        dec eax
        and al, 3
        shl al, 2
        mov [ebp+C_FLG], al     ; (the segment size the SYN-ACK noted)

.est:   mov al, [NOW]
        mov [ebp+C_AGE], al
        ; The client's ack counts if it is in [C_ACK, C_SND]. edx = 1: it lacks something we
        ; sent, 2: and says so with the same ack as before, 0: neither
        xor edx, edx
        mov eax, [ebx+P_ACK]
        sub eax, [ebp+C_ACK]    ; how much further than before
        mov edi, [ebp+C_SND]
        sub edi, [ebp+C_ACK]    ; how much there is to acknowledge
        cmp eax, edi
        ja .odd
        jb .ak0
        test byte [ebp+C_FLG], F_CLOSED
        jnz .free               ; it has all we sent, our FIN included: done
        btr dword [ebp+C_FLG], F_DEFER_BIT ; If that was an answer of several segments, its
        jnc .ak1                ; data is acknowledged only now
        inc byte [ebx+P_MORE]
        jmp .ak1
.odd:   call ckx                ; not an ack for this connection: for a new one from the same
        jz .make                ; address and port (whose predecessor we never saw end)?
        jmp .ak
.ak0:   inc edx
        test eax, eax
        jnz .ak1
        inc edx
.ak1:   add [ebp+C_ACK], eax
.ak:    test byte [ebp+C_FLG], F_CLOSED
        jz .open
        test edx, edx           ; closed, but the client lacks something (our FIN at least):
        jz .ret                 ; if it asks, by sending anything but a plain new ack, it gets
        cmp dl, 2               ; that again
        je .resend
        test byte [ebx+P_FL], 1
        jnz .resend
        test ecx, ecx
        jnz .resend
        fret
.open:  mov eax, [ebp+C_NXT]
        sub eax, [ebx+P_SEQ]    ; how many of this segment's bytes we already have
        js .early
        jz .inord
        cmp eax, ecx
        ja .old
        jb .trim
        test byte [ebx+P_FL], 1 ; all of its data is old; a FIN after it would be new
        jz .old
.trim:  add esi, eax            ; drop what we have, the rest is new
        sub ecx, eax
        add [ebx+P_SEQ], eax
        jmp .new
.early: count 3                 ; From further on: what comes before it is late (neighbours do
        neg eax                 ; get swapped on the way) or lost. Keep it for when that
        cmp eax, 0xFFFF         ; arrives, if it is inside our window and not empty, and say
        ja .ack                 ; what we expect.
        mov al, [ebx+P_FL]
        and eax, 1
        or eax, ecx
        jz .ack
        call oohold
        jmp .ack
.old:   jecxz .ack              ; (a keep-alive probe: one byte back, no data)
        test edx, edx           ; old data again. If the client lacks something of ours, that
        jnz .resend             ; is why; if not, an ack will do
.ack:   mov esi, OB
        xor ecx, ecx
        mov al, 0x10
        jmp .send
.inord: test ecx, ecx
        jnz .new
        test byte [ebx+P_FL], 1
        jnz .new
        cmp dl, 2               ; no data: an ack. The same ack twice with something
        je .resend              ; outstanding: a segment of ours is missing
        cmp [ebx+P_MORE], bl
        jne .ack
        fret

.new:   mov edi, OB             ; edi = end of our answer
.more:  add [ebp+C_NXT], ecx    ; ecx new bytes at esi, in order
        cmp [ebx+P_PORTS+2], bl
        je .plain
        cmp [ebp+C_ST], ebx
        jne .walk
        mov eax, [ebp+C_LEN]    ; waiting for the ClientHello: collect it in a handshake buffer
        lea edx, [eax+ecx]      ; bytes so far, these included
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
.buf:   mov [ebp+C_LEN], edx
        push edi
        lea edi, [ebx+HS_CH+eax]
        rep movsb
        pop edi
        cmp edx, 5
        jb .reply
        movzx eax, word [ebx+HS_CH+3]
        xchg al, ah
        add eax, 5              ; record length
        cmp edx, eax
        jb .reply               ; not all there yet
        push edx
        push eax
        push ebx
        inc dword [ebp+C_ST]
        lea esi, [ebx+HS_CH+5]
        lea ecx, [eax-5]
        icall handshake         ; edi = end of our flight
        pop ebx
        mov ecx, edi            ; keep the flight: a client that sends its ClientHello again
        sub ecx, OB             ; has to get this one again (it may have got it already)
        mov [ebx+HS_FLEN], ecx
        push edi
        mov esi, OB
        lea edi, [ebx+HS_FL]
        rep movsb
        pop edi
        pop eax
        pop ecx
        sub ecx, eax            ; (anything behind the ClientHello is the first record)
        lea esi, [ebx+HS_CH+eax]
        xor ebx, ebx
        mov [ebp+C_LEN], ebx
        jmp .walk
.junk:  mov dword [ebp+C_LEN], CHMAX + 1 ; no ClientHello will come of this
        jmp .reply

        ; Records. C_LEN bytes of a record that is not looked at are still to come; or, if
        ; C_HDRN is not 0, so many bytes of a record header are in C_LEN. Only an application
        ; record that is all in this segment, has more than a tag and carries the tag of the
        ; client's next record counts, and then it gets one response (so the client's
        ; Finished, which has other keys, and anything forged are skipped like the junk they are).
.walk:  test ecx, ecx
        jz .reply
        movzx eax, byte [ebp+C_HDRN]
        test eax, eax
        jnz .hdr
        mov eax, [ebp+C_LEN]
        test eax, eax
        jz .rec
        cmp eax, ecx
        jbe .skip
        mov eax, ecx
.skip:  add esi, eax
        sub ecx, eax
        sub [ebp+C_LEN], eax
        jmp .walk
.hdr:   mov dl, [esi]           ; the rest of a header that began in an earlier segment
        inc esi
        dec ecx
        cmp al, 4
        je .hend
        mov [ebp+C_LEN+eax], dl
        inc byte [ebp+C_HDRN]
        jmp .walk
.hend:  mov dh, [ebp+C_LEN+3]   ; its last byte: the record's length, which is skipped
        movzx eax, dx
        mov [ebp+C_LEN], eax
        mov [ebp+C_HDRN], bl
        jmp .walk
.rec:   cmp ecx, 5
        jae .whole
.some:  mov dl, [esi]           ; a header that goes on in the next segment
        mov [ebp+C_LEN+eax], dl
        inc esi
        inc eax
        loop .some
        mov [ebp+C_HDRN], al
        jmp .reply
.whole: movzx eax, word [esi+3]
        xchg al, ah
        add eax, 5              ; record length
        cmp eax, ecx
        jbe .here
        sub eax, ecx            ; it goes on in later segments: skipped
        mov [ebp+C_LEN], eax
        jmp .reply
.here:  cmp byte [esi], 23      ; application_data
        jne .next
        cmp eax, 22
        jb .next
        cmp edi, OB + OBMAX - RL
        ja .next                ; (no room for another response: pipelined beyond reason)
        mov edx, [ebp+C_ST]     ; sequence number + 1, the same in both directions
        dec edx
        pushad
        lea ecx, [eax-21]
        add esi, 5
        lea ebx, [ebp+C_KIV+48]
        mov edi, VB
        stc
        icall seal              ; the record as it should be, tag included
        sub edi, 16
        add esi, ecx
        push 16
        pop ecx
        repe cmpsb
        popad
        jne .next
        inc dword [ebp+C_ST]
        call respond
.next:  add esi, eax
        sub ecx, eax
        jmp .walk

        ; Port 80. A request ends with an empty line (the top bit of C_FLG: the last line
        ; has just ended; CRs don't count either way) and gets the response.
.plain: test ecx, ecx
        jz .reply
        movzx edx, byte [ebp+C_FLG]
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
        and byte [ebp+C_FLG], 0x7F
        shl edx, 7
        or [ebp+C_FLG], dl

.reply: call ooent              ; Is a segment that came early next now? Then go on with it.
        jne .out
        mov eax, [ebp+C_NXT]
        sub eax, [ebx+OO_SEQ]   ; how many of its bytes we have by now
        js .out                 ; (it is still ahead)
        and dword [ebx+OO_TAG], 0
        mov ecx, [ebx+OO_LEN]
        cmp eax, ecx
        ja .out
        jb .use
        cmp dword [ebx+OO_FIN], 0 ; (all of its data came another way; a FIN after it is new)
        je .out
.use:   test byte [P_FL], 1
        jnz .out                ; (nothing follows a FIN)
        lea esi, [ebx+OO_DATA+eax]
        sub ecx, eax
        mov al, [ebx+OO_FIN]
        or [P_FL], al
        xor ebx, ebx
        jmp .more
.out:   xor ebx, ebx
        mov esi, OB             ; our answer is at OB, up to edi; it follows what we sent before
        mov ecx, edi
        sub ecx, esi
        mov al, 0x10            ; ACK
        jz .fin
        mov al, 0x18            ; ACK|PSH
.fin:   test byte [ebx+P_FL], 1
        jz .send
        inc dword [ebp+C_NXT]   ; the client's FIN takes a sequence number and gets ours with
        or al, 1                ; the answer
.send:  mov edx, [ebp+C_SND]
        add [ebp+C_SND], ecx
        test al, 1
        jz .sq
        inc dword [ebp+C_SND]   ; (ours takes one too)
        or byte [ebp+C_FLG], F_CLOSED
        mov edi, [ebx+P_ACK]    ; If the client had all we sent and there was nothing more to
        sub edi, edx            ; say, that was the connection (should our FIN get lost, the
        or edi, ecx             ; client's next one is told that there is none). If not, the
        jnz .sq                 ; slot stays until the client has the rest.
        call tcp_send
        jmp .free
.sq:    call tcp_send
        fret

        ; The client lacks the end of what we sent, from its ack on: build that again and
        ; send it: the last of our records (as many as OB has room for: whether more is
        ; missing its next ack will say), and before them the end of the flight if it lacks
        ; that too.
.resend:
        count 4
        mov edi, OB
        mov eax, [ebp+C_SND]
        sub eax, [ebx+P_ACK]    ; so many bytes (our FIN, if it lacks that, is not one)
        test byte [ebp+C_FLG], F_CLOSED
        jz .rsz
        dec eax
.rsz:   mov ecx, RESP_LEN - 1   ; in records of this length: on port 80 the bare response
        cmp [ebx+P_PORTS+2], bl
        je .recs
        mov ecx, RL
        mov edx, [ebp+C_ST]
        dec edx
        imul edx, ecx           ; all our records together
        cmp eax, edx
        jbe .recs
        sub eax, edx            ; more than those: the end of the flight, which is in the
        call hsbuf              ; handshake buffer, unless that has gone to another
        jc .reset               ; connection since
        mov esi, [ebx+HS_FLEN]
        sub esi, eax
        jb .ret0                ; (more than we ever sent)
        lea esi, [ebx+esi+HS_FL]
        push ecx
        xchg eax, ecx
        rep movsb
        pop ecx
        xor ebx, ebx
        xchg eax, edx           ; and then all the records
.recs:  mov esi, eax            ; eax = bytes of records, ecx = the length of one
        add eax, ecx
        dec eax
        xor edx, edx
        div ecx                 ; so many records, the last of them possibly not from its start
        push eax
        imul eax, ecx
        sub eax, esi
        xchg eax, esi           ; esi = how much of the first one the client has
        pop ecx
        mov edx, [ebp+C_ST]     ; (port 80 has no such thing, and doesn't care)
        dec edx
        sub edx, ecx            ; the first one's number
        jecxz .none
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
        test byte [ebp+C_FLG], F_CLOSED
        jnz .rs
        mov al, 0x18
        jecxz .ret0
.rs:    mov edx, [ebx+P_ACK]
        call tcp_send
.ret0:  fret
.reset: mov al, 4               ; we can't go on with this connection: say so and forget it
        mov edx, [ebp+C_SND]
        xor ecx, ecx
        xor edi, edi
        call tcp_seg
        jmp .free

; find: ebp = the slot of the connection the packet in FR belongs to. If it has none: CF, and
; ebp = the slot a new one would get, or 0 if there is no room for it.
; A connection is in one of two buckets of BUCKET slots, picked by two words of the keyed
; hash of its address and ports (`prf`; clients can't aim at each other's buckets). A new one
; goes into the bucket with more free slots. If both are full, it takes the place of the
; connection in them that has been quiet for the longest, if that is longer than IDLE: such
; a client has probably gone without saying so. If none has, the new one is refused.
find:   pushad
        call prf
        mov esi, PT             ; the table for port 80,
        push PSLOT
        pop ecx
        cmp byte [P_PORTS+2], 0
        je .tab
        mov esi, TT             ; or the one for TLS
        mov cl, TSLOT
.tab:   mov eax, [HKO+4]
        call .where
        push ebp                ; the second bucket
        mov eax, [HKO]
        call .where
        push ebp                ; the first
        mov eax, [P_IP]
        mov di, [P_PORTS]
        xor esi, esi            ; esi = the slot that has been quiet for longer than bh
        mov bh, IDLE
        call .scan
        mov bl, dl              ; free slots in the first bucket
        mov ebp, [esp+4]
        call .scan
        pop eax
        pop ebp
        cmp dl, bl
        ja .pick                ; the second has more
        xchg eax, ebp
        mov dl, bl
.pick:  test dl, dl
        jnz .free
        mov ebp, esi            ; no free slot in either
        jmp .miss
.free:  cmp dword [ebp+C_IP], 0
        je .miss
        add ebp, ecx
        jmp .free
.miss:  stc
.ret:   mov [esp+8], ebp
        popad
        ret
.where: mul dword [esi+4]       ; ebp = the bucket for hash eax: number (hash * buckets) >> 32
        imul edx, ecx
        shl edx, 4              ; (* BUCKET)
        add edx, [esi]
        mov ebp, edx
        ret
.scan:  mov edx, BUCKET << 8    ; dh = slots to look at, dl = free ones seen
.s:     cmp [ebp+C_IP], eax
        jne .other
        cmp [ebp+C_PORT], di
        jne .other
        add esp, 12             ; found (CF = 0): drop the return address and the buckets
        jmp .ret
.other: cmp dword [ebp+C_IP], 0
        jne .used
        inc edx
        jmp .nx
.used:  push eax
        mov al, [NOW]
        sub al, [ebp+C_AGE]     ; how long it has been quiet
        cmp al, bh
        jbe .young
        mov bh, al
        mov esi, ebp
.young: pop eax
.nx:    add ebp, ecx
        dec dh
        jnz .s
        ret

; prf: HKO = a keyed hash of the client's address and ports: a ChaCha20 block under a key
; made at boot (HKS), with those as its counter. Its words pick the two buckets (0, 1), make
; the cookie (2: W) and place a segment kept for later (3).
prf:    pushad
        mov edi, HKS + 48
        mov eax, [P_IP]
        stosd
        mov eax, [P_PORTS]
        stosd
        scasd
        scasd                   ; edi = HKO
        mov esi, HKS
        icall chacha
        popad
        ret

; ckx: eax = 0 (and ZF) if the packet is the first after a SYN-ACK of ours: its ack is the
; cookie for its sequence number (see `.syn`). Bits HINT of eax are 0 if it acknowledges a
; SYN-ACK of ours at all.
ckx:    push edx
        mov eax, [P_SEQ]
        dec eax
        shl eax, 10
        mov edx, [P_ACK]
        dec edx
        xor eax, edx
        xor eax, [HKO+8]
        and eax, -4
        pop edx
        ret

; respond: our response to request number edx of the connection ebp at edi (which moves on):
; as a record under the connection's key, or on port 80 as it is. (ebx = 0)
respond:
        push esi
        push ecx
        mov esi, RESP
        mov ecx, RESP_LEN
        cmp [ebx+P_PORTS+2], bl
        jne .tls
        dec ecx                 ; port 80: without the byte that says what a record holds
        rep movsb
%ifdef DEBUG
        pushad
        dec edi                 ; (the page ends with a line end)
        mov esi, DBG + 24
        std
.dc:    sub esi, 4
        mov edx, [esi]
        mov cl, 4
.dd:    mov al, dl
        and al, 15
        cmp al, 10
        sbb al, 0x69
        das                     ; hex digit
        dec edi
        mov [edi], al
        shr edx, 4
        loop .dd
        cmp esi, DBG
        ja .dc
        cld
        popad
%endif
        jmp .done
.tls:   push ebx
        lea ebx, [ebp+C_KIV]
        clc
        icall seal
        pop ebx
.done:  pop ecx
        pop esi
        ret

; oohold: keep the segment in hand (ecx bytes at esi, sequence number P_SEQ, FIN or not)
; until what comes before it is here (`.reply` in `tcp`). There are OON places for such
; segments; a client's place is picked by its hash, and whatever was there is gone, unless
; it is an earlier segment of the same client.
oohold: pushad
        call ooent
        jne .fill
        mov eax, [P_SEQ]
        sub eax, [ebx+OO_SEQ]
        jns .ret                ; the one kept comes first
.fill:  mov eax, [HKO+12]
        mov [ebx+OO_TAG], eax
        mov eax, [P_SEQ]
        mov [ebx+OO_SEQ], eax
        mov [ebx+OO_LEN], ecx
        mov al, [P_FL]
        and eax, 1
        mov [ebx+OO_FIN], eax
        lea edi, [ebx+OO_DATA]
        rep movsb
.ret:   popad
        ret

; ooent: ebx = the client's place for a segment kept for later; ZF if what is there is its own
ooent:  push eax
        mov eax, [HKO+12]
        mov ebx, eax
        and ebx, OON - 1
        shl ebx, 11
        add ebx, OOP
        cmp [ebx+OO_TAG], eax
        pop eax
        ret

; hsbuf: ebx = the handshake buffer of connection ebp; CF if it has none (any more)
hsbuf:  movzx ebx, word [ebp+C_HS]
        dec ebx
        js .none
        shl ebx, HS_SHIFT
        add ebx, HSP
        cmp [ebx+HS_OWNER], ebp
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
        mov [ebp+C_HS], bx
        dec ebx
        shl ebx, HS_SHIFT
        add ebx, HSP
        mov [ebx+HS_OWNER], ebp
        and dword [ebx+HS_FLEN], 0
        ret

; tcp_send: ecx bytes at esi to the client of connection ebp, in segments, from our sequence
; number edx; flags al on the last. If it takes several segments, none of them acknowledges
; what this packet brought (but what came before it): the client then keeps sending its data
; until it has all of the answer, whichever part gets lost, and it is acknowledged when its
; ack says so (F_DEFER, in `tcp`). Not when we close: then there is no later.
tcp_send:
        pushad
        movzx ebx, byte [ebp+C_FLG]
        shr ebx, 2
        and ebx, 3
        movzx ebx, word [MSSTAB+ebx*2]
        mov edi, [ebp+C_NXT]
        and byte [ebp+C_FLG], ~F_DEFER
        cmp ecx, ebx
        jbe .last
        test al, 1
        jnz .seg
        mov edi, [P_SEQ]
        or byte [ebp+C_FLG], F_DEFER
.seg:   push eax
        push ecx
        mov ecx, ebx
        mov al, 0x10
        call tcp_seg
        pop ecx
        pop eax
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
        mov [ebx+38], edx
        bswap edi
        mov [ebx+42], edi
        mov byte [ebx+46], 0x50
        test al, 2
        jz .nopt
        mov byte [ebx+46], 0x60 ; a SYN's "payload" is 4 bytes of options
.nopt:  mov [ebx+47], al
        xor eax, eax
        mov [ebx+50], eax       ; checksum (for now), nothing urgent
        dec eax
        mov [ebx+48], ax        ; window: we take whatever comes, at once
        lea edi, [ebx+54]
        rep movsb
        mov [edi], cl           ; zero pad byte for an odd length checksum
        mov edi, ebx
        call ethhdr
        mov eax, 0x00450008     ; IPv4, a header of 20 bytes, nothing special
        stosd
        scasw                   ; (the length: below)
        mov eax, 0x00400000     ; no id: never to be fragmented
        stosd
        lea eax, [ebp+20]       ; where TTL, protocol and checksum go, first the rest of the
        xchg al, ah             ; pseudo header: 0, protocol, TCP length; the addresses follow
        shl eax, 16
        mov ah, 6
        stosd
        mov eax, OURIP
        stosd
        mov eax, [P_IP]
        stosd
        mov eax, [P_PORTS]
        rol eax, 16
        stosd
        lea esi, [ebx+22]
        lea ecx, [ebp+32]
        icall csum
        mov [ebx+50], ax
        lea ecx, [ebp+40]
        xchg cl, ch
        mov [ebx+16], cx        ; IP total length
        mov dword [ebx+22], 0x0640 ; TTL 64, TCP, checksum 0
        lea esi, [ebx+14]
        push 20
        pop ecx
        icall csum
        mov [ebx+24], ax
        lea ecx, [ebp+54]
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
        fret

; ----------------------------------------------------------------------------
; handshake: ClientHello message at esi (ecx bytes), connection at ebp.
; Writes ServerHello + encrypted flight to OB, returns edi = end. Clobbers all but ebp.
handshake:
        push ebp
        mov edi, TR             ; transcript: ClientHello
        push esi
        rep movsb
        pop esi
        mov ebx, edi            ; the ServerHello goes here
        mov eax, TR             ; find the client's x25519 key share (group, length). If it
        mov edx, 0x20001d00     ; sent none, this stops the search: we then answer
        mov [edi], edx          ; with a "share" of junk, and the client gives up
.ks:    inc eax
        cmp [eax], edx
        jne .ks
        push eax
        mov edi, E              ; fresh secrets: X25519 scalar and ECDSA nonce
        mov cl, 16              ; (ecx = 0 after the copy above)
.rnd:   rdrand eax
        jnc .rnd
        stosd
        loop .rnd
        mov edi, ebx
        movzx edx, byte [esi+38] ; session id length
        lea ecx, [edx+39]
        rep movsb               ; ServerHello: ClientHello's random + session id ...
        mov esi, SHTAIL
        mov cl, 19
        rep movsb               ; ... + suite, extensions, key share header ...
        mov esi, R_NINE
        icall x25519
        mov esi, R_X2
        mov cl, 8
        rep movsd               ; ... + our key share
        pop esi
        lodsd
        icall x25519             ; X2 = the shared secret
        lea eax, [edx+86]
        shl eax, 24
        mov al, 2
        mov [ebx], eax          ; type 2, length

        mov ebp, SLOTS + 128    ; key schedule up to the handshake secret
        push ebx
        mov esi, CVB            ; (ecx = 0 after the copy above)
        lea edi, [ebp+S_EH]
        icall sha256             ; SHA256("")
        lea ebx, [ebp+S_Z]
        mov esi, ebx
        mov cl, 32
        lea edi, [ebp+S_ES]
        icall hmac               ; early secret
        mov ebx, edi
        mov esi, R_X2
        lea edi, [ebp+S_HS]
        icall stage              ; handshake secret
        icall sigr               ; r and 1/k for the CertificateVerify (in X2 and T1)
        pop ebx

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
.retry: inc byte [ebx+6]
        lea eax, [ebx+edx+90]   ; P1 = end of ServerHello
        icall thash
        push ebx
        push edx
        lea ebx, [ebp+S_HS]
        mov esi, L_SHTS
        lea edx, [ebp+S_TH]
        lea edi, [ebp+S_TS]
        icall expand             ; server handshake traffic secret
        pop edx
        pop ebx
        xchg eax, edi           ; EncryptedExtensions + Certificate (after thash: it pads in place)
        mov esi, EECERT
        mov ecx, EECERT_LEN
        rep movsb
        xchg eax, edi           ; eax = P2
        icall thash
        lea esi, [ebp+S_TH]
        mov edi, CVB+98
        mov cl, 32
        rep movsb
        mov esi, CVB
        mov cl, 130
        lea edi, [eax+46]
        icall sha256             ; the hash to sign (parked where s will go)
        pushad
        mov esi, edi
        mov edi, R_U
        icall rev32              ; as a number
        mov ebp, MN
        mov esi, SIGN
        call vm                 ; Z2 = s = (hash + r d) / k
        cmp byte [edi+R_Z2+31-R_U-32], 0 ; (edi = U + 32 after rev32)
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
        mov dword [edi], 0x00030316
        lea ecx, [edx+90]
        mov [edi+4], cl
        add edi, 5
        mov esi, ebx
        rep movsb
        push esi                ; P1 = end of ServerHello = start of the encrypted part
        push edi                ; output position
        lea ebx, [ebp+S_TS]
        mov edi, KH
        icall keys               ; handshake key and iv

        mov esi, L_FIN
        xor edx, edx
        lea edi, [ebp+S_D]
        icall expand
        mov ebx, edi            ; finished key
        icall thash
        xchg eax, edi
        mov eax, 0x20000014
        stosd
        lea esi, [ebp+S_TH]
        mov cl, 32              ; (ecx = 0 after the copy above)
        icall hmac
        add edi, ecx
        mov byte [edi], 0x16    ; inner content type: handshake
        xchg eax, edi

        pop edi                 ; output position
        pop esi                 ; P1
        lea ecx, [eax+1]
        sub ecx, esi
        mov ebx, KH
        xor edx, edx
        icall seal               ; edi = end of output

        icall thash              ; application traffic secret
        lea ebx, [ebp+S_HS]
        lea esi, [ebp+S_Z]
        push edi
        lea edi, [ebp+S_ES]
        icall stage              ; master secret
        mov ebx, edi
        mov esi, L_CATS
        lea edx, [ebp+S_TH]
        lea edi, [ebp+S_D]
        icall expand             ; client application traffic secret
        mov ecx, edi
        mov esi, L_SATS
        lea edi, [ebp+S_TS]
        icall expand             ; server application traffic secret
        mov ebx, edi
        pop eax                 ; end of output
        pop ebp
        mov edi, KA
        icall keys
        mov ebx, ecx
        add edi, 48
        icall keys
        mov esi, KA             ; (`keys` writes 20 bytes too many: not into the connection)
        lea edi, [ebp+C_KIV]
        push 24
        pop ecx
        rep movsd
        xchg eax, edi
        fret

; thash: TH slot = SHA256(transcript up to eax)
thash:
        pushad
        mov esi, TR
        mov ecx, eax
        sub ecx, esi
        lea edi, [ebp+S_TH]
        icall sha256
        popad
        fret

; stage: edi = HKDF-Extract(Derive-Secret(ebx, "derived", ""), 32 bytes at esi)
stage:
        pushad
        push esi
        push edi
        mov esi, L_DER
        lea edx, [ebp+S_EH]
        lea edi, [ebp+S_D]
        icall expand
        mov ebx, edi
        pop edi
        pop esi
        push 32
        pop ecx
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
        mov [edi-4], edx        ; block counter 0 (slots near 16 MiB hold SeaBIOS tables)
        add esi, L_IV - L_KEY
        icall expand
        popad
        fret

; ----------------------------------------------------------------------------
; sha256: edi = SHA-256 of ecx bytes at esi. Pads in place: esi[ecx .. ecx+72) is clobbered.
sha256:
        pushad
        push edi
        lea edi, [esi+ecx]
        lea eax, [ecx+72]
        and al, 0xC0
        sub eax, ecx            ; padding bytes
        shl ecx, 3
        bswap ecx
        xchg eax, ecx           ; eax = bit length, big-endian
        push eax
        mov al, 0x80
        stosb
        dec ecx
        xor eax, eax
        rep stosb
        pop dword [edi-4]
        push edi                ; end of padded message
        push esi
        mov esi, HT
        mov edi, SH
        mov cl, 8
        rep movsd
        pop esi
.blk:   push esi
        lea esi, [edi-32]       ; SH: edi = SH + 32 here, from the copy above or the sum below
        sub edi, SH+32-(AW+256)
        mov cl, 8
        rep movsd
        pop esi
        sub edi, 32             ; a..h at [edi]; W[i-k] sits at [edi+32+4k] (window slides down)
        push -64
        pop ebp                 ; round - 64
.rnd:   call wnext
        mov [edi+32], eax       ; W[i], over the h that the previous round dropped
        add eax, [KT+256+ebp*4]
        add eax, [edi+28]
        xchg eax, ebx           ; h + k + w
        mov eax, [edi+16]
        mov ecx, 0x190B06       ; S1: ror 6, 11, 25
        call sigma
        add ebx, edx
        mov edx, [edi+20]
        xor edx, [edi+24]
        and edx, eax
        xor edx, [edi+24]       ; ch(e, f, g)
        add ebx, edx            ; t1
        add [edi+12], ebx       ; new e = d + t1
        mov eax, [edi]
        mov ecx, 0x160D02       ; S0: ror 2, 13, 22
        call sigma
        add ebx, edx
        mov edx, [edi+4]
        xor eax, edx
        xor edx, [edi+8]
        and eax, edx
        xor eax, [edi+4]        ; maj(a, b, c) = ((a ^ b) & (b ^ c)) ^ b
        add ebx, eax            ; (ecx is still 0 from sigma: no other temporary)
        sub edi, 4
        mov [edi], ebx          ; new a = t1 + t2
        inc ebp
        jnz .rnd
        push esi                ; chaining value += a..h
        mov esi, edi
        mov edi, SH
        mov cl, 8
.add:   lodsd
        add [edi], eax
        scasd
        loop .add
        pop esi
        cmp esi, [esp]
        jb .blk
        pop eax
        lea esi, [edi-32]       ; SH
        pop edi
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
.s:     push eax
        test cl, 0x20
        jnz .sh
        ror eax, cl
        jmp .x
.sh:    shr eax, cl
.x:     xor edx, eax
        pop eax
        shr ecx, 8
        jnz .s
        ret

; wnext: eax = message schedule word W[ebp + 64] (window at edi, message at esi)
wnext:  cmp ebp, 16-64
        jge .sch
        lodsd
        bswap eax
        ret
.sch:   mov eax, [edi+92]       ; W[i-15]
        mov ecx, 0x231207       ; s0: ror 7, ror 18, shr 3
        call sigma
        push edx
        mov eax, [edi+40]       ; W[i-2]
        mov ecx, 0x2A1311       ; s1: ror 17, ror 19, shr 10
        call sigma
        pop eax
        add eax, edx
        add eax, [edi+96]       ; W[i-16]
        add eax, [edi+60]       ; W[i-7]
        ret

; hmac: edi = HMAC-SHA256(key = 32 bytes at ebx, ecx <= 64 bytes at esi)
hmac:
        pushad
        push edi
        push ecx
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
        pop ecx
        add ecx, 64
        mov esi, HB
        lea edi, [esi+64]
        icall sha256             ; inner hash
        mov cl, 64
.o:     xor byte [HB+ecx-1], 0x36 ^ 0x5c
        loop .o
        mov cl, 96
        pop edi
        icall sha256             ; outer hash
        popad
        fret

; expand: edi = HKDF-Expand-Label(secret ebx, label esi = {L, len, text}, context edx or 0), 32 bytes
expand:
        pushad
        push edi
        mov edi, INFO
        mov al, 0
        stosb
        movsb                   ; output length
        lodsb
        add al, 6
        stosb
        push esi
        mov esi, TLS13
        movsd
        movsw
        pop esi
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
        lea ecx, [edi-INFO]
        mov esi, INFO
        pop edi
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
%if ((R_GX + 36) | (R_GX + 72)) & 0x100 || (R_ONE & 0x100) = 0
%error "REGS: bit 8 must first be set at R_ONE (boot copies the constants up to there)"
%endif

; x25519: X2 = X25519(E, 32 bytes at esi). E is used as it is, unclamped: the other side
; only needs it to be the same number in our key share and in the secret.
x25519: pushad
        mov edi, R_U
        push 8
        pop ecx
        rep movsd
        mov ebp, M25519
        lea ebx, [edi+E-R_U-32]
        mov esi, INIT25519
        call smult
        popad
        fret

; sigr: the half of an ECDSA signature that needs no message. X2 = r = x(K G), where K is
; stepped until r is a plain 32-byte DER INTEGER (0 < r[0] < 0x80); T1 = R^2 / K mod n.
sigr:   pushad
        mov ebx, K
        mov ebp, MP256
.again: inc dword [ebx]
        mov esi, INIT256
        call smult
        cmp byte [ebx+R_X2+31-K], 0
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
.l:     bt [ebx], ecx
        sbb edx, edx
        call cswap              ; the step doubles (X2 : Z2) and adds it to (X3 : Z3)
        push esi
        call vm
        pop esi
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
        movzx edx, word [esi-2]
        push vmnext             ; where the operation returns to
        push 3
        pop ecx
.r:     mov eax, edx
        and eax, 15
        imul eax, eax, 36
        add eax, REGS
        push eax
        shr edx, 4
        loop .r
        pop edi                 ; dst
        pop esi                 ; a
        pop ebx                 ; b
        dec edx
        jz vadd                 ; (ecx = 0)
        dec edx
        jnz montmul
        inc ecx
        call vadd               ; sub: a - b + 256 m (the modulus, read one byte early)
        dec ecx
        mov esi, edi
        lea ebx, [ebp-1]
        jmp vadd
vmnext: popad
        jmp vm

; vadd: 9 limbs at edi = those at esi + those at ebx if ecx = 0; minus them if ecx = 1
; (a - b = a + ~b + 1; not, jecxz, dec and lea leave the carry alone)
vadd:   pushad
        push 9
        pop edx
        neg ecx                 ; CF = 1 to subtract
.l:     lodsd
        mov ebp, [ebx]
        jecxz .a
        not ebp
.a:     adc eax, ebp
        stosd
        lea ebx, [ebx+4]
        dec edx
        jnz .l
        popad
vmret:  ret

; montmul: 9 limbs at edi = (those at esi) * (those at ebx) / 2^288 mod m, not fully reduced
montmul:
        pushad
        mov edi, MT
        push 19
        pop ecx
        xor eax, eax
        rep stosd
        sub edi, 76
        mov cl, 9
.i:     lodsd                   ; MT += a[i] * b * 2^32i
        push esi
        mov esi, ebx
        call mulrow
        mov esi, ebp            ; then += m * whatever zeroes limb i
        mov eax, [edi]
        imul eax, [ebp+36]
        call mulrow
        scasd
        pop esi
        loop .i
        mov esi, edi            ; the upper half is the result
        mov edi, [esp]
        mov cl, 9
        rep movsd
        popad
        ret

; mulrow: the 11 limbs at edi += eax * the 9 limbs at esi
mulrow: pushad
        xchg eax, ebp
        xor ebx, ebx            ; carry
        push 9
        pop ecx
.l:     lodsd
        mul ebp
        add eax, ebx
        adc edx, 0
        add [edi], eax
        adc edx, 0
        mov ebx, edx
        scasd
        loop .l
        add [edi], ebx
        adc dword [edi+4], 0
        popad
        ret

; cswap: swap (X2, Z2) with (X3, Z3) if edx = -1, not if edx = 0
cswap:  pushad
        mov esi, R_X2
        lea edi, [esi+72]
        push 18
        pop ecx
.s:     mov eax, [esi]
        xor eax, [edi]
        and eax, edx
        xor [esi], eax
        xor [edi], eax
        cmpsd
        loop .s
        popad
        ret

; inv: T1 = (9 limbs at esi) ^ (m - 2), which is R^2 / it for a stored value. Clobbers T0, T2.
inv:    pushad
        mov edi, R_T0
        push 9
        pop ecx
        rep movsd               ; T0 = x
        lea esi, [edi-36]
        mov cl, 9
        rep movsd               ; T1 = x (bit 0 of m - 2 is set)
        mov esi, ebp            ; T2 = the exponent
        mov cl, 8
        rep movsd
        lea edx, [edi-32]
        sub byte [edx], 2       ; (no borrow: our moduli end in a byte >= 2)
        lea edi, [edx-72]       ; T0
        mov esi, edi
        mov ebx, edi
        inc ecx                 ; bit 1
.l:     call montmul            ; T0 = T0^2
        bt [edx], ecx
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
        pop ecx
.l:     mov al, [esi+ecx-1]
        stosb
        loop .l
        fret

; ----------------------------------------------------------------------------
; chacha: edi = ChaCha20 block of the 16-dword state at esi
chacha:
        pushad
        push esi
        push edi
        push 16
        pop ecx
        rep movsd
        pop ebp                 ; working state
        xor ecx, ecx            ; quarter round 0..79
.qr:    push ecx
        mov eax, ecx
        shl al, 2               ; column * 4 (masked below; al only, so no bit 8 sneaks in)
        and ecx, 4              ; diagonal rounds: shift the column by 4 bytes per row
        mov ebx, ebp
        mov dl, 4
.m:     and al, 12
        lea esi, [ebx+eax]
        push esi
        add eax, ecx
        add ebx, 16
        dec dl
        jnz .m
        pop edi                 ; d
        pop edx                 ; c
        pop ebx                 ; b
        pop esi                 ; a
        mov ecx, 0x07080C10
.st:    mov eax, [ebx]          ; P += Q; R ^= P; R <<<= n; then (P,Q,R) = (other,R,Q)
        add [esi], eax
        mov eax, [esi]
        xor [edi], eax
        rol dword [edi], cl
        xchg esi, edx
        xchg ebx, edi
        shr ecx, 8
        jnz .st
        pop ecx
        inc ecx
        cmp cl, 80
        jne .qr
        pop esi
        mov edi, ebp
        mov cl, 16
.ad:    lodsd
        add [edi], eax
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
        push edi                ; o
        push ecx                ; n
        push esi                ; m
        mov edi, ST             ; ChaCha state: constants | key | 0 counter | iv ^ seq
        mov esi, SIGMA
        movsd
        movsd
        movsd
        movsd
        mov esi, ebx
        push 12
        pop ecx
        rep movsd
        bswap edx
        xor [edi-4], edx
        lea esi, [edi-64]       ; ST
        add edi, 64             ; PK = ST + 128
        icall chacha             ; block 0: Poly1305 key
        mov edi, SB             ; SB = header, 0 pad | ciphertext, 0 pad | lengths
        mov al, 0x17
        stosb
        mov al, 3
        stosb
        stosb
        mov ecx, [esp+4]
        lea eax, [ecx+16]
        xchg al, ah
        stosw
        add ecx, 42             ; zero a bit more than needed: simpler than rounding
        xor eax, eax
        rep stosb
        pop esi                 ; m
        mov ecx, [esp]          ; n
        mov edi, SB+16
        test ebp, ebp
        jz .ks
        rep movsb
        jmp .d
.ks:    push esi
        push edi
        mov esi, ST
        inc dword [esi+48]      ; next counter
        lea edi, [esi+64]       ; KS = ST + 64 (64-byte aligned)
        mov edx, edi
        icall chacha
        pop edi
        pop esi
.x:     lodsb
        xor al, [edx]
        inc edx
        stosb
        dec ecx
        jz .d
        test dl, 63
        jnz .x
        jmp .ks
.d:     pop ecx                 ; n
        lea edi, [ecx+SB+16+15]
        and edi, -16            ; SB+16 is 16-aligned
        mov byte [edi], 5       ; aad length
        mov [edi+8], ecx        ; ciphertext length
        lea edx, [edi+16-SB]
        shr edx, 4              ; Poly1305 blocks
        pop edi                 ; o
        mov esi, SB
        movsd                   ; record header
        movsb
        add esi, 11
        rep movsb               ; ciphertext
        mov ebx, PK
        ; Poly1305 tag of the edx 16-byte blocks at SB, key at PK (r is clamped in place).
        ; h has 17 limbs of 8 bits (the top one 2, plus a little), in dwords. With R[16 + j] = r[j] and
        ; R[j - 1] = 320 r[j] (2^136 = 320 mod 2^130 - 5), limb k of h * r = sum_i h[i] * R[16 + k - i].
        push edi                ; where the tag goes
        mov eax, 0x0FFFFFFF
        and [ebx], eax
        mov al, 0xFC
        and [ebx+4], eax
        and [ebx+8], eax
        and [ebx+12], eax
        mov edi, PH
        push 17
        pop ecx
        xor eax, eax
        rep stosd               ; h = 0
        mov esi, ebx
        add edi, 68             ; &R[16]
        mov cl, 16
.r:     lodsb                   ; (R[15] = 320 r[16] and R[32] = r[16] are 0: never written)
        stosd
        imul ebp, eax, 320
        mov [edi-72], ebp
        loop .r
        mov ecx, edx            ; blocks
        mov esi, SB
.blk:   push ecx
        mov edi, PH             ; h += block + 2^128 (eax < 256 here)
        mov cl, 16
.m:     lodsb
        add [edi], eax
        scasd
        loop .m
        inc dword [edi]
        push esi
        mov edi, XT             ; XT = h * r: under 2^30 per limb
        mov ebx, RR + 64
        mov cl, 17
.k:     push ecx
        mov esi, PH
        mov edx, ebx
        xor ebp, ebp
        mov cl, 17
.i:     lodsd
        imul eax, [edx]
        add ebp, eax
        sub edx, 4
        loop .i
        xchg eax, ebp
        stosd
        add ebx, 4
        pop ecx
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
        lea ebx, [ebx+ebx*4]
        lea esi, [edi-68]
        dec dl
        jnz .pass
        pop esi
        pop ecx
        loop .blk
        pop edi
        mov ebx, PK+16
        mov esi, PH
        mov cl, 16
        xor edx, edx
.t:     lodsd                   ; tag = h + s mod 2^128
        add edx, eax
        movzx eax, byte [ebx]
        inc ebx
        add edx, eax
        mov [edi], dl
        inc edi
        shr edx, 8
        loop .t
        mov [esp], edi
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
GATES:  gatetable GATELIST ; (must follow regs.inc, and IDTR must follow this)
IDTR:   dw 8 * (1 + NGATES) - 1
        dd IDT
GDT:    dq 0
        dq 0x00CF9A000000FFFF   ; 8: code, flat
        dq 0x00CF92000000FFFF   ; 16: data, flat
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
