; boot.asm - boot sector: what a BIOS needs to start os.bin from a disk (a cloud server's, or
; `qemu -drive`). The disk image is this sector followed by os.bin.
;
; Loads the 64 sectors after itself, asks the BIOS how much memory there is, enters 32-bit
; protected mode with flat segments, copies the image to 1 MiB and enters it where its
; multiboot header says, with the memory size in a multiboot information structure. (os.asm then sets up its
; own segments and stack and zeroes its memory, as it does after any other loader.)

LOAD    equ 0x8000              ; where the BIOS reads the image to
SECTORS equ 64                  ; 32 KiB (the Makefile checks that os.bin fits)

BITS 16
        org 0x7C00
        cli
        cld
        xor ax, ax
        mov ds, ax
        mov es, ax
        mov ss, ax
        mov sp, 0x7C00
        sti
        mov si, dap
        mov ah, 0x42            ; extended read; dl = the drive we were booted from
        int 0x13
        jc $                    ; (nothing to fall back on)
        mov ax, 0xE801          ; memory above 1 MiB: ax = KiB up to 16 MiB, bx = 64 KiB blocks
        int 0x15                ; above that (or the same in cx and dx)
        jc .nomem
        test ax, ax
        jnz .mem
        xchg ax, cx
        mov bx, dx
.mem:   movzx eax, ax
        movzx ebx, bx
        shl ebx, 6
        add eax, ebx
        mov [mbi+8], eax
        inc byte [mbi]          ; multiboot information: mem_lower and mem_upper are valid
.nomem: cli
        in al, 0x92
        or al, 2
        out 0x92, al            ; A20, in case it is off
        lgdt [gdtr]
        mov eax, cr0
        or al, 1
        mov cr0, eax
        jmp 8:pm
BITS 32
pm:     mov ax, 16
        mov ds, ax
        mov es, ax
        mov ss, ax
        mov fs, ax
        mov gs, ax
        mov esp, 0x7C00
        mov esi, LOAD
        mov edi, 0x100000
        mov ecx, SECTORS * 512 / 4
        rep movsd
        mov eax, 0x2BADB002     ; enter it the way a multiboot loader does
        mov ebx, mbi
        jmp [0x10001C]          ; the multiboot header's entry address

dap:    db 16, 0                ; disk address packet: 64 sectors to 0000:8000 from LBA 1
        dw SECTORS
        dw LOAD, 0
        dq 1
mbi:    dd 0, 640, 0            ; multiboot information: flags, mem_lower, mem_upper (KiB)
gdt:    dq 0
        dq 0x00CF9A000000FFFF   ; 8: code, 4 GiB
        dq 0x00CF92000000FFFF   ; 16: data, 4 GiB
gdtr:   dw 23
        dd gdt
        times 510 - ($ - $$) db 0
        dw 0xAA55
