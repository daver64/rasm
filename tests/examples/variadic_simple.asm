section .text

; Simple variadic macro
%macro PUSH_SOME 1-*
    push %1
%endmacro

global _start
_start:
    ; Test with 1 parameter
    PUSH_SOME rax
    
    ; Test with 2 parameters
    PUSH_SOME rbx, rcx
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
