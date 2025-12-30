; String Operations Test
.text
.global _start
_start:
    ; Move string
    movsb
    movsw
    movsq
    
    ; Store string
    stosb
    stosw
    stosd
    stosq
    
    ; Load string
    lodsb
    lodsw
    lodsd
    lodsq
    
    ; Scan string
    scasb
    scasw
    scasd
    scasq
    
    ; Compare string
    cmpsb
    cmpsw
    cmpsq
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
