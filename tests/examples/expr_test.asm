; Test expression evaluation
.text
.global _start

_start:
    ; Constant expressions
    mov rax, 16 + 4            ; 20
    mov rbx, 100 - 25          ; 75
    mov rcx, 8 * 5             ; 40
    mov rdx, 100 / 4           ; 25
    mov rsi, 1024 >> 2         ; 256
    mov rdi, 1 << 10           ; 1024
    mov r8, 0xFF & 0x0F        ; 15
    mov r9, 0x10 | 0x01        ; 17
    mov r10, 0xFF ^ 0xF0       ; 15
    mov r11, (5 + 3) * 2       ; 16
    mov r12, 100 - (20 + 5)    ; 75
    
    ; Unary minus
    mov r13, -(10 + 5)         ; -15
    
    ; Complex expression
    mov r14, ((1 << 12) + 256) / 16  ; 272
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
