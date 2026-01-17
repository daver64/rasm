; Test proc with automatic stack allocation and alignment
BITS 64

; Procedure with 32 bytes of local stack space (16-byte aligned)
proc func_with_locals, 32
    ; Local variables can use [rbp-8], [rbp-16], etc.
    mov qword [rbp-8], 0x1234
    mov qword [rbp-16], 0x5678
    mov rax, [rbp-8]
    add rax, [rbp-16]
endproc

; Procedure with odd size - should be rounded up to 16
proc func_odd_size, 10
    ; 10 bytes requested, but should allocate 16 (aligned)
    mov byte [rbp-1], 0xAA
    movzx rax, byte [rbp-1]
endproc

; Procedure with no locals (leaf function)
proc simple_func
    mov rax, 42
endproc

; Procedure with larger locals
proc func_large, 128
    ; 128 bytes (already aligned)
    lea rax, [rbp-128]
endproc

section .text
global _start

_start:
    call func_with_locals
    call func_odd_size
    call simple_func
    call func_large
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
