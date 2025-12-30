; Comprehensive test for new parsing features:
; 1. String initialization (double and single quotes)
; 2. Times directive
; 3. Variadic macros

section .data
    ; String initialization with double quotes
    msg1: db "Hello, World!", 0
    
    ; String initialization with single quotes
    msg2: db 'Single quotes work too!', 0
    
    ; Times directive with db
    zeros: times 10 db 0
    pattern: times 5 db 0xAA, 0x55
    
    ; Times directive with larger data widths
    words: times 4 dw 0x1234
    dwords: times 3 dd 0xDEADBEEF
    qwords: times 2 dq 0x0123456789ABCDEF

section .bss
    ; Times directive with reserve directives
    buffer: times 256 resb 1
    array: times 64 resq 1

section .text

; Variadic macro with unlimited parameters (1-*)
%macro PUSH_MANY 1-*
    push %1
%endmacro

; Variadic macro with parameter range (2-4)
%macro ADD_RANGE 2-4
    add %1, %2
%endmacro

; Variadic macro for saving registers (0-*)
%macro SAVE_REGS 0-*
    ; Empty body is valid
%endmacro

global _start
_start:
    ; Test variadic macros
    PUSH_MANY rax
    PUSH_MANY rbx, rcx
    PUSH_MANY rdx, rsi, rdi, r8
    
    ; Test parameter range macro
    mov rax, 1
    mov rbx, 2
    ADD_RANGE rax, rbx
    
    mov rcx, 3
    mov rdx, 4
    mov rsi, 5
    ADD_RANGE rcx, rdx, rsi
    
    ; Test zero-parameter variadic
    SAVE_REGS
    SAVE_REGS rax
    SAVE_REGS rax, rbx, rcx
    
    ; Load string addresses
    lea rax, [rip+msg1]
    lea rbx, [rip+msg2]
    
    ; Load data from times-generated arrays
    mov rcx, [rip+words]
    mov rdx, [rip+dwords]
    mov rsi, [rip+qwords]
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
