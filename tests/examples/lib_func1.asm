; Library function 1
global add_numbers

section .text
add_numbers:
    mov rax, rdi
    add rax, rsi
    ret
