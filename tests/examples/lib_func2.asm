; Library function 2
global multiply_numbers

section .text
multiply_numbers:
    mov rax, rdi
    mov rcx, rsi
    imul rcx
    ret
