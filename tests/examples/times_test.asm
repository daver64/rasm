section .data
    ; test times with db
    times 10 db 0
    times 5 db 0xFF
    times 3 db 'A'
    
    ; test times with strings
    times 2 db "Hello", 0
    times 3 db 'X'
    
    ; test times with dw/dd/dq
    times 4 dw 0x1234
    times 3 dd 0xDEADBEEF
    times 2 dq 0x0123456789ABCDEF
    
section .bss
    ; test times with reserve directives
    times 100 resb 1
    times 20 resw 1
    times 10 resd 1
    times 5 resq 1

section .text
global _start
_start:
    mov rax, 60
    xor rdi, rdi
    syscall
