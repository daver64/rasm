; Simple prefix test

section .text
global _start

_start:
    ; REP prefix with simple string operations
    rep movsb           ; F3 A4
    rep stosb           ; F3 AA
    rep lodsb           ; F3 AC
    
    ; REPE prefix
    repe cmpsb          ; F3 A6
    repe scasb          ; F3 AE
    
    ; REPNE prefix
    repne cmpsb         ; F2 A6
    repne scasb         ; F2 AE
    
    ; LOCK prefix
    lock add [rax], ebx ; F0 01 18
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
