; boot.asm - boot sector: what a BIOS needs to start os.bin from a disk (a cloud server's, or
; `qemu -drive`). The disk image is this sector followed by os.bin.
;
; Loads the 64 sectors after itself, asks the BIOS for its memory map, enters 32-bit
; protected mode with flat segments, copies the image to 1 MiB and enters it where its
; multiboot header says, with the memory map in a multiboot information structure, as GRUB
; would pass it. (os.asm then sets up long mode, its own segments and stack, and zeroes its
; memory, as it does after any other loader.)

LOAD    equ 0x8000              ; where the BIOS reads the image to
SECTORS equ 64                  ; 32 KiB (the Makefile checks that os.bin fits)
MMAP    equ 0x6000              ; the memory map: entries of size (20) | base | length | type
MMAX    equ 128                 ;   (as many as fit below the stack)

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
        mov di, MMAP + 4        ; int 15h, E820: one range per call, ebx says where we are
        xor ebx, ebx
.e820:  mov eax, 0xE820
        mov edx, 0x534D4150     ; "SMAP"
        mov ecx, 20
        mov [di-4], ecx
        int 0x15
        jc .done                ; (the end, said the other way)
        add di, 24
        cmp di, MMAP + 4 + 24 * MMAX
        jae .done
        test ebx, ebx
        jnz .e820
.done:  sub di, MMAP + 4
        mov [mbi+44], di
        cli
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
mbi:    dd 0x40                 ; multiboot information: flags (there is a memory map),
        times 10 dd 0
        dd 0, MMAP              ;   its length and address
gdt:    dq 0
        dq 0x00CF9A000000FFFF   ; 8: code, 4 GiB
        dq 0x00CF92000000FFFF   ; 16: data, 4 GiB
gdtr:   dw 23
        dd gdt
        times 510 - ($ - $$) db 0
        dw 0xAA55
