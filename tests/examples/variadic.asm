section .text

; Variadic macro with minimum 1 parameter
%macro PUSH_ONE 1-*
    push %1
%endmacro

; Variadic macro with minimum 2 parameters  
%macro PUSH_TWO 2-*
    push %1
    push %2
%endmacro

; Variadic macro with minimum 3 parameters
%macro PUSH_THREE 3-*
    push %1
    push %2
    push %3
%endmacro

; Variadic macro with fixed range 2-4
%macro ADD_UP_TO_FOUR 2-4
    add %1, %2
%endmacro

global _start
_start:
    ; Test PUSH_ONE with 1 parameter
    PUSH_ONE rax
    
    ; Test PUSH_ONE with 3 parameters (only uses first)
    PUSH_ONE rbx, rcx, rdx
    
    ; Test PUSH_TWO with exactly 2 parameters
    PUSH_TWO r8, r9
    
    ; Test PUSH_TWO with 5 parameters (only uses first 2)
    PUSH_TWO r10, r11, r12, r13, r14
    
    ; Test PUSH_THREE with exactly 3 parameters
    PUSH_THREE rsi, rdi, rbp
    
    ; Test PUSH_THREE with 6 parameters (only uses first 3)
    PUSH_THREE r15, rax, rbx, rcx, rdx, rsi
    
    ; Test ADD_UP_TO_FOUR with 2 parameters (minimum)
    mov rax, 1
    mov rbx, 2
    ADD_UP_TO_FOUR rax, rbx
    
    ; Test ADD_UP_TO_FOUR with 3 parameters
    mov rcx, 3
    mov rdx, 4
    mov rsi, 5
    ADD_UP_TO_FOUR rcx, rdx, rsi
    
    ; Test ADD_UP_TO_FOUR with 4 parameters (maximum)
    mov rdi, 6
    mov r8, 7
    mov r9, 8
    mov r10, 9
    ADD_UP_TO_FOUR rdi, r8, r9, r10
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
