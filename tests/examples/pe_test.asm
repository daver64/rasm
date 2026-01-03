; Test file for PE object generation
section .text
global main
extern printf

main:
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    mov rcx, message
    call printf
    
    xor eax, eax
    add rsp, 32
    pop rbp
    ret

section .data
message: db "Hello from PE object!", 10, 0
