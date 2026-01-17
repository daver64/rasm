; Test proc/endproc in 16-bit mode
bits 16
org 0x7C00

proc boot_func
    mov ax, 0x0E41  ; BIOS teletype 'A'
    int 0x10
endproc

_start:
    call boot_func
    hlt
    jmp $

times 510-($-$$) db 0
dw 0xAA55
