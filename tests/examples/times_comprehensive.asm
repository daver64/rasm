; Comprehensive test of times directive with instructions and data
bits 64

section .text
global _start

_start:
    ; Fixed count times with different instructions
    times 10 nop                    ; 10 NOPs
    times 3 inc rax                 ; 3 inc rax instructions
    times 2 push rbx                ; 2 push rbx instructions
    times 5 pop rcx                 ; 5 pop rcx instructions
    
    ; Mixed with regular instructions
    mov rax, 60
    times 3 xor rdi, rdi
    syscall

section .data
    ; Times with data still works
    times 16 db 0x90
    msg: db "Hello", 10
    times 10 db 0
