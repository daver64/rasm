; Test error messages with line numbers
section .text
global main

main:
    mov rax, rbx        ; Line 5: valid
    add eax, unknown    ; Line 6: unknown symbol (will be caught later)
    mov al, rax         ; Line 7: register size mismatch
    ret
