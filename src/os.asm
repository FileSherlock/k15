; os.asm - bare-metal HTTPS server, flat multiboot image (nasm -f bin)
;
; Boot: multiboot v1 "a.out kludge", loaded at 1 MiB by `qemu -kernel`.
; NIC:  ISA NE2000 at port 0x300, polled.  Network: slirp (10.0.2.15).
; TLS:  1.3, TLS_CHACHA20_POLY1305_SHA256, X25519, ecdsa_secp256r1_sha256.
; Unlike k1 this one is meant to be secure: a fresh X25519 key and a fresh ECDSA nonce per
; handshake (rdrand), a real certificate chain, and client records are authenticated before
; they get an answer. See CLAUDE.md for the shortcuts that remain.
;
; Convention: every routine preserves all registers (pushad/popad) unless it
; says otherwise. All buffers live at fixed addresses in zeroed RAM at 2 MiB.

BITS 32
%include "conf.inc"             ; CHAIN_LEN

BSS     equ 0x200000
FR      equ 0               ; Ethernet frame: received, then rewritten in place as reply.
                            ; At address 0 (old real-mode IVT, unused) so `xor reg, reg` loads it.
TR      equ BSS + 0x20000   ; handshake transcript
OB      equ BSS + 0x30000   ; TLS output for one TCP reply
VB      equ BSS + 0x38000   ; what a client record should look like (for its tag)
SB      equ BSS + 0x40000   ; seal scratch: Poly1305 input
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
CHB     equ 0x400000        ; ClientHello reassembly: 1024 x 4 KiB, by slirp's initial seq
CONNS   equ 0x800000        ; 16 tables of 65536 connections x 128 bytes: one slot per client
                            ; port, one table (8 MiB) per low nibble of the client's IP: up to 136 MiB

S_Z     equ -128            ; slot offsets from ebp = SLOTS + 128
S_EH    equ -96
S_ES    equ -64
S_D     equ -32
S_HS    equ 0
S_TS    equ 32
S_TH    equ 64

C_ST    equ 0               ; connection: 0 = waiting for the ClientHello, else 1 + the number
                            ; of requests answered (the sequence number, both directions)
C_NXT   equ 4               ; next sequence number we expect from the client
C_LEN   equ 8               ; ClientHello bytes so far; then bytes left of the current record
C_KIV   equ 12              ; application key | 0 counter | iv (+20 bytes of junk: `keys`)

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
%define GATELIST sha256, hmac, expand, thash, seal, keys, rev32, stage, x25519, inv, chacha, csum, handshake, sigr, tcp, nic_send, tcp_out
%else
%define GATELIST sha256, hmac, expand, thash, seal, keys, rev32, stage, x25519, inv, chacha, csum, handshake, sigr, tcp, nic_send
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
start:                          ; QEMU's multiboot loader leaves esp = 0x6f10: good enough
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
%ifdef HOST
        mov esi, REGC
        xor ecx, ecx
%else
        mov esi, nicinit        ; NE2000 setup: (register, value) pairs
        mov dh, 3
        push 7
        pop ecx
.ni:    lodsw
        mov dl, al
        mov al, ah
        out dx, al
        loop .ni
%endif
        mov edi, R_GX           ; the constant registers follow nicinit: x(G) R, 4b R, d R, 1
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

        xor ebx, ebx            ; FR: unsolicited ARP reply "10.0.2.15 is at <whatever MAC>"
        mov word [ebx+12], 0x0608 ; (the MAC is IVT junk: fine, the NIC is promiscuous)
        mov word [ebx+20], 0x0200
        mov dword [ebx+28], 0x0f02000a
        push 42
        pop ecx
        icall nic_send

        mov bl, 0x46            ; next page to read (PSTART); dh = 3 from here on
.poll:  mov dl, 0
        mov al, 0x40
        out dx, al              ; register page 1
        mov dl, 7
        in al, dx               ; CURR: page the NIC will write next
        cmp al, bl
        je .poll
        mov dl, 0
        xor eax, eax
        out dx, al              ; register page 0
        mov dl, 8
        out dx, al              ; remote DMA address = next page << 8
        inc edx
        mov al, bl
        out dx, al
        mov dl, 0x10
        in eax, dx              ; packet header: status, next page, length (QEMU allows 32-bit)
        mov bl, ah
        shr eax, 16
        xchg eax, ecx           ; (reads 4 bytes past the frame: harmless)
        xor edi, edi            ; FR
        rep insb
        mov al, bl
        mov dl, 3
        out dx, al              ; BNRY: free what we read
        pushad
        icall tcp
        popad
        jmp .poll

; nic_send: transmit ecx bytes from FR
nic_send:
        pushad
        mov dx, 0x308
        xor eax, eax
        out dx, al              ; remote DMA address 0x4000 (TX page)
        inc edx
        mov al, 0x40
        out dx, al
        mov dl, 0x0b
        out dx, al              ; remote byte count high = 0x40: enough for a full frame
        mov dl, 0x10
        xor esi, esi            ; FR
        rep outsb
        xchg eax, esi           ; = length, since FR = 0
        mov dl, 5
        out dx, al              ; transmit byte count
        inc edx
        mov al, ah
        out dx, al
        mov dl, 0
        mov al, 4
        out dx, al              ; transmit
        popad
nsret:  fret

; ----------------------------------------------------------------------------
; tcp: handle the TCP segment in FR. Our seq = their ack (nothing we send gets lost), but
; we track the next byte we expect, so segments slirp resends (or sends after one that our
; NIC dropped while we were busy) are only re-acked.
tcp:
        xor ebx, ebx            ; FR
        cmp byte [ebx+13], 0    ; IPv4 only (slirp also sends ARP and IPv6)
        jne nsret
        movzx eax, byte [ebx+46]
        shr eax, 2              ; TCP header length
        movzx ecx, word [ebx+16]
        xchg cl, ch
        sub ecx, 20
        sub ecx, eax            ; payload length
        lea esi, [ebx+eax+34]
        mov ebp, [ebx+33]       ; 15 (our IP's last byte) | client port | 1 (443 >> 8)
        mov al, [ebx+29]        ; the low nibble of the client's IP picks one of 16 tables
        and al, 15              ; (bounded: a client can't aim this anywhere else)
        shl eax, 24
        add ebp, eax
        shr ebp, 1              ; connection slot: CONNS + 7 + (nibble * 65536 + port (bytes swapped)) * 128
        mov dl, [ebx+47]        ; flags
        mov eax, [ebx+42]
        xchg eax, [ebx+38]      ; our seq = their ack; eax = their seq
        bswap eax
        test dl, 2
        jz .ns
        inc eax                 ; SYN: a new connection; the SYN takes a sequence number
        mov [ebp+C_NXT], eax    ; (so the check below passes, with nothing to add)
        mov [ebp+C_ST], ecx     ; (a SYN carries no payload: ecx = 0)
        mov [ebp+C_LEN], eax    ; until the ClientHello is in: slirp's ISN + 1
.ns:    push edx                ; flags
        push ecx                ; payload length: anything with data gets an answer
        sub eax, [ebp+C_NXT]
        jz .in
        mul ebx                 ; not the next byte we expect: ignore it, just re-ack
        xchg eax, ecx           ; (eax = edx = ecx = 0)
.in:    shr dl, 1               ; CF = FIN, which takes a sequence number
        adc [ebp+C_NXT], ecx
        mov eax, [ebp+C_NXT]
        bswap eax
        mov [ebx+42], eax       ; our ack
        mov eax, [ebx+26]
        xchg eax, [ebx+30]
        mov [ebx+26], eax       ; swap IP addresses
        rol dword [ebx+34], 16  ; swap ports
        mov edi, OB             ; edi = end of our output
        push edi
        cmp [ebp+C_ST], ebx
        jne .walk               ; (the record walk sits after the ret below: all jumps short)
.ch:    mov edx, [ebp+C_LEN]    ; still waiting for the ClientHello: collect it in a bucket
        mov eax, [ebp+C_NXT]
        sub eax, edx            ; bytes so far, this segment included
        cmp eax, 0xF00          ; a ClientHello must fit its bucket (and the transcript)
        ja .send
        shl edx, 13             ; slirp's ISN + 1 = 2 + 64000 n, n += 1 per connection:
        shr edx, 10             ; 16 + 4 KiB * (125 n mod 1024), so 1024 in a row differ
        bts edx, 22             ; + CHB
        push edi
        lea edi, [edx+eax]
        sub edi, ecx
        rep movsb
        pop edi
        movzx ecx, word [edx+3]
        xchg cl, ch             ; record body length
        sub eax, 5
        cmp eax, ecx
        jl .send                ; not all there yet (signed: a slot that never saw a SYN)
        inc dword [ebp+C_ST]
        lea esi, [edx+5]
        icall handshake
        xor ecx, ecx            ; C_LEN = 0: the next record starts with the client's next byte
.wend:  neg ecx
        mov [ebp+C_LEN], ecx
.send:  pop esi                 ; OB
        pop ecx                 ; payload length
        pop eax                 ; flags
        and eax, 3
        or ecx, eax
        jnz .tx
        fret                    ; pure ACK: stay quiet
.walk:  mov eax, [ebp+C_LEN]    ; bytes of the current record still to come
.w:     sub ecx, eax            ; skip whole records; we only read their headers
        jbe .wend
        add esi, eax
        movzx eax, word [esi+3]
        xchg al, ah
        add eax, 5              ; record length
        cmp byte [esi], 23      ; application_data
        jne .w
        cmp eax, ecx            ; only records that are all in this segment, and that have
        ja .w                   ; more than a tag, are looked at
        cmp eax, 22
        jb .w
        mov edx, [ebp+C_ST]     ; sequence number + 1, the same in both directions: a record
        dec edx                 ; counts only if it carries the tag of the client's next
        pushad                  ; application record, and then it gets one response
        lea ecx, [eax-21]       ; (so the client's Finished, which has other keys, and
        add esi, 5              ; anything forged are skipped like the junk they are)
        lea ebx, [ebp+C_KIV+48]
        mov edi, VB
        stc
        icall seal               ; the record as it should be, tag included
        sub edi, 16
        add esi, ecx
        push 16
        pop ecx
        repe cmpsb
        popad
        jne .w
        inc dword [ebp+C_ST]
        push esi
        push ecx
        mov esi, RESP
        push RESP_LEN           ; (imm8 form while the response is < 128 bytes)
        pop ecx
        lea ebx, [ebp+C_KIV]
        icall seal               ; (keeps eax; CF = 0 since the tags compared equal)
        pop ecx
        pop esi
        jmp .w
.tx:    or al, 0x18             ; ACK|PSH (+SYN or FIN)
%if CHAIN_LEN > 1100            ; a real certificate chain: our flight needs several segments
        mov edx, edi            ; (this code is only there if the baked-in chain needs it)
.seg:   push eax
        push edx
        mov ecx, edx
        sub ecx, esi
        cmp ecx, 1400
        jbe .one
        mov ecx, 1400
.one:   push ecx
        push esi
        icall tcp_out
        pop esi
        pop ecx
        add esi, ecx
        mov eax, [FR+38]        ; our sequence number += what went out
        bswap eax
        add eax, ecx
        bswap eax
        mov [FR+38], eax
        pop edx
        pop eax
        cmp esi, edx
        jb .seg
        fret
%else
        mov ecx, edi
        sub ecx, esi            ; all in one segment: the largest reply, our flight, is ~500 bytes
%endif

; tcp_out (falls through from tcp): send ecx bytes at esi with flags al, reusing the swapped
; headers in FR
tcp_out:
        xor ebx, ebx            ; FR
        mov ebp, ecx            ; payload length
        mov [ebx+47], al
        lea edi, [ebx+54]
        rep movsb
        mov [edi], cl           ; zero pad byte for an odd length checksum
        lea ecx, [ebp+20]       ; TCP length
        mov eax, ecx
        xchg al, ah
        mov [ebx+24], ax        ; pseudo header in place: 0, 6 (still there: protocol TCP),
        mov [ebx+22], bl        ; length, then the IPs
        mov byte [ebx+46], 0x50 ; no options (the window stays whatever slirp offered us)
        and dword [ebx+50], 0
        lea esi, [ebx+22]
        add ecx, 12
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
        jmp nic_send

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
        lea edi, [ebp+C_KIV]
        icall keys
        mov ebx, ecx
        add edi, 48
        icall keys
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
nicinit: db 1, 0x46, 2, 0xC0, 4, 0x40, 12, 0x10, 0, 0x40, 7, 0x46, 0, 0
%include "regs.inc"       ; (must follow nicinit: boot copies them with the same esi)
GATES:  gatetable GATELIST ; (must follow regs.inc, and IDTR must follow this)
IDTR:   dw 8 * (1 + NGATES) - 1
        dd IDT
%include "gen.inc"
SHTAIL: db 0x13, 0x03, 0x00, 0x00, 0x2e, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04
        db 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20
%else
%include "regs.inc"
%endif
%include "ec.inc"         ; curve programs
