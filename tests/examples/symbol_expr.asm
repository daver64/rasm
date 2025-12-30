; Test symbolic expressions
.text
.global _start

.data
buffer: dq 0x1234567890ABCDEF
msg: db 'H', 'e', 'l', 'l', 'o', '\n'
msg_end:

.text
_start:
    ; Symbol + offset expressions
    lea rax, [buffer + 8]
    lea rbx, [msg + 2]
    
    ; Symbol arithmetic in immediates (when symbols are defined)
    mov rcx, msg_end - msg    ; String length = 6
    
    ; Complex expression with shift
    mov rdx, (msg_end - msg) * 8  ; 48
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
