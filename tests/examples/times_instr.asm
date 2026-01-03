; Test times directive with instructions
bits 64

_start:
    ; Simple times with fixed count
    times 5 nop
    
    ; Times with multiple NOPs should produce 5 bytes
    mov rax, 60
    times 3 inc rax
    
    ; Times with position-dependent expression
    times 10-($-$$) nop
    
    ; After the above, we should be at offset 10
    mov rdi, 0
    syscall
