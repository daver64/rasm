; Practical example: Using times to create aligned code blocks
bits 64

section .text
global _start

_start:
    ; Function 1: starts at offset 0
    mov rax, 1
    syscall
    ; Pad to offset 32 using times and $
    times 32-($-$$) nop
    
    ; Function 2: starts at offset 32
    mov rax, 60
    xor rdi, rdi
    syscall
    ; Pad to offset 64
    times 64-($-$$) nop
    
    ; Function 3: starts at offset 64
    push rbp
    mov rbp, rsp
    pop rbp
    ret
