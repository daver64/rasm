; Test immediate validation - this should fail
section .text
global main

main:
    ; This immediate is too large for a 16-bit operand
    mov ax, 0x10000
    ret
