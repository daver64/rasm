; Test times directive with instructions - simpler version
bits 64

_start:
    ; Simple times with fixed count
    times 5 nop
    
    ; Times with register instruction
    times 3 inc rax
    
    ; Test with position marker
    mov rdi, 0
