; Test REP MOVSQ

section .text
global _start

_start:
    rep movsq           ; F3 48 A7
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
