global start
section .text
start:
    mov rbx, 8
    mov rax, [rip+counter]
    inc rax
    dec rax
    not rbx
    mov rcx, [rip+counter]
    neg rcx
    shl rax, 1
    shr rbx, 1
    sar rcx, 3
    mov rdi, 0
    mov rax, 60
    syscall
section .data
counter: dq 1
