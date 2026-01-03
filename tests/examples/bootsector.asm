;; qemu-system-i386 -drive format=raw,file=bootsector.bin
bits 16
org 0x7C00

mov al,65
call print_char
jmp $


print_char:
    ; BIOS teletype output
    mov ah, 0x0E
    mov bh, 0
    mov bl, 7
    int 0x10
    ret

times 510-($-$$) db 0
dw 0xAA55
