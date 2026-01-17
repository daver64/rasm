; Test proc/endproc procedure macros
BITS 64

; Simple procedure with automatic stack frame
proc my_function
    mov rax, 42
    add rax, 10
endproc

; Another procedure
proc helper_func
    xor rax, rax
endproc

; Call the procedures
section .text
global _start

_start:
    call my_function
    call helper_func
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
