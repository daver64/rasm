; hello.asm smoke example
global main
extern puts
extern exit

section .data
msg: db "Hello, world!", 0

section .text
main:
    sub rsp, 8         ; align stack to 16 bytes before calls
    lea rdi, [rip+msg] ; arg0 = pointer to string
    call puts
    add rsp, 8         ; restore stack
    mov rax, 0         ; return code 0
    ret
