; Test MOVSQ without prefix

section .text
global _start

_start:
    movsq               ; 48 A5
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
