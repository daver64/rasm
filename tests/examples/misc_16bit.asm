; Test 16-bit misc instructions  
bits 16
org 0x7C00

_start:
    ; LOOP instructions in 16-bit
    mov cx, 5
.loop16:
    nop
    loop .loop16
    
    ; XLAT in 16-bit (uses BX as base)
    mov bx, xlat_table
    mov al, 1
    xlat
    
    ; Halt
    hlt
    jmp $

xlat_table:
    db 0xAA, 0xBB, 0xCC, 0xDD

times 510-($-$$) db 0
dw 0xAA55
