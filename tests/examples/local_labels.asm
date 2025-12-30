; Test local labels
.text
.global _start

_start:
    mov rax, 5
    cmp rax, 3
    jg .skip        ; Local label reference
    mov rax, 10
.skip:              ; Local label definition
    mov rbx, rax
    
    call helper
    jmp .end        ; Another local label

.end:
    mov rax, 60
    xor rdi, rdi
    syscall

helper:
    mov rcx, 100
.loop:              ; Local label in helper scope
    dec rcx
    jnz .loop       ; Reference to helper's .loop
    ret
