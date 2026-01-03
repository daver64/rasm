; Test times directive with $ expressions
bits 16
org 0x7C00

_start:
    mov ax, 65
    times 20-($-$$) nop
    ; After this, we should be at offset 20
    
    mov bx, 0x1234
    times 40-($-$$) nop
    ; Now at offset 40
    
    hlt
