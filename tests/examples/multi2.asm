; File 2 - defines more data and code
section .data
msg2: db "Second file", 0

section .text
global _start
_start:
    call func1
    mov rax, 60
    xor rdi, rdi
    syscall
