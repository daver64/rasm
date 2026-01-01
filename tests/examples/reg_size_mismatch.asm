; Test register size mismatch validation
section .text
global main

main:
    ; This should fail: 8-bit vs 64-bit
    mov al, rax
    ret
