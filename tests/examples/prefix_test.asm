; Test instruction prefixes (REP, REPE, REPNE, LOCK)

section .text
global _start

_start:
    ; REP prefix with string operations
    rep movsb           ; F3 A4
    rep movsw           ; F3 66 A5
    ; rep movsd         ; Ambiguous with SSE - skipping
    rep movsq           ; F3 48 A5
    
    rep stosb           ; F3 AA
    rep stosw           ; F3 66 AB
    rep stosd           ; F3 AB
    rep stosq           ; F3 48 AB
    
    rep lodsb           ; F3 AC
    rep lodsw           ; F3 66 AD
    rep lodsd           ; F3 AD
    rep lodsq           ; F3 48 AD
    
    ; REPE (same as REP for non-compare operations)
    repe cmpsb          ; F3 A6
    repe cmpsw          ; F3 66 A7
    ; repe cmpsd        ; Ambiguous - use cmpsq for 64-bit
    repe cmpsq          ; F3 48 A7
    
    repe scasb          ; F3 AE
    repe scasw          ; F3 66 AF
    repe scasd          ; F3 AF
    repe scasq          ; F3 48 AF
    
    ; REPNE prefix
    repne cmpsb         ; F2 A6
    repne cmpsw         ; F2 66 A7
    ; repne cmpsd       ; Ambiguous - use cmpsq for 64-bit
    repne cmpsq         ; F2 48 A7
    
    repne scasb         ; F2 AE
    repne scasw         ; F2 66 AF
    repne scasd         ; F2 AF
    repne scasq         ; F2 48 AF
    
    ; LOCK prefix with atomic operations
    lock add [rax], ebx      ; F0 01 18
    lock add [rax], rbx      ; F0 48 01 18
    lock or [rax], ebx       ; F0 09 18
    lock and [rax], ebx      ; F0 21 18
    lock xor [rax], ebx      ; F0 31 18
    lock sub [rax], ebx      ; F0 29 18
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
