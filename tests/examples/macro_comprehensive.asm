; Test comprehensive macro features

section .text

; Simple 0-parameter macro
%macro HELLO 0
    mov rax, 1
    mov rdi, 1
%endmacro

; Macro with multiple parameters
%macro MOVQ 2
    mov %1, %2
%endmacro

; Nested macro-local labels
%macro COND_MOVE 3
    cmp %1, %2
    je %%skip
    mov %1, %3
%%skip:
%endmacro

; Macro that uses another instruction multiple times
%macro CLEAR_REGS 3
    xor %1, %1
    xor %2, %2
    xor %3, %3
%endmacro

global _start
_start:
    ; Test 0-parameter macro
    HELLO
    
    ; Test 2-parameter macro
    MOVQ rax, 42
    MOVQ rbx, 100
    
    ; Test macro-local labels (first invocation)
    COND_MOVE rax, rbx, 99
    
    ; Test macro-local labels (second invocation - different labels)
    mov rcx, 50
    mov rdx, 50
    COND_MOVE rcx, rdx, 77
    
    ; Test clearing registers
    CLEAR_REGS rax, rbx, rcx
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
