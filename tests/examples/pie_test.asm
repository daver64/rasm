; Test PIE (Position Independent Executable) support
; This should compile and link with -pie flag

global main
extern printf
extern exit

section .data
format: db "PIE test: %d", 10, 0
num: dq 42

section .text
main:
    push rbp
    mov rbp, rsp
    
    ; Call external function with PLT32 relocation
    lea rdi, [rip+format]
    mov rsi, [rip+num]
    xor rax, rax
    call printf
    
    xor rdi, rdi
    call exit
    
    pop rbp
    ret
