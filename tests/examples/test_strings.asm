; Test string initialization
section .data
    msg1: db "Hello, World!", 0
    msg2: db 'Single quotes', 0
    mixed: db "Test", 10, 13, 0
    bytes: db 0x48, 0x65, 0x6C, 0x6C, 0x6F

section .text
global _start
_start:
    mov rax, 60
    xor rdi, rdi
    syscall
