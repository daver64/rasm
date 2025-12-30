section .text

; Define a macro to push registers
%macro PUSH_REGS 2
    push %1
    push %2
%endmacro

; Define a macro to pop registers
%macro POP_REGS 2
    pop %2
    pop %1
%endmacro

; Define a macro with local labels
%macro LOOP_N 2
%%loop:
    %1
    dec %2
    jnz %%loop
%endmacro

global _start
_start:
    ; Test basic parameter substitution
    PUSH_REGS rax, rbx
    
    ; Test with different parameters
    PUSH_REGS rcx, rdx
    
    ; Test local labels - first invocation
    mov rcx, 5
    LOOP_N nop, rcx
    
    ; Test local labels - second invocation (should get different label)
    mov rdx, 3
    LOOP_N nop, rdx
    
    ; Pop registers
    POP_REGS rcx, rdx
    POP_REGS rax, rbx
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
