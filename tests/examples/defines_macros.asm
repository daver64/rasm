; Test %define with macros

%define REG1 rax
%define REG2 rbx
%define NUM_ITERATIONS 5

%macro SWAP_REGS 2
    mov rcx, %1
    mov %1, %2
    mov %2, rcx
%endmacro

section .text
global _start
_start:
    ; Use defines as macro parameters
    mov REG1, 10
    mov REG2, 20
    SWAP_REGS REG1, REG2
    
    ; Define used in macro expansion
    mov rcx, NUM_ITERATIONS
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
