global start
section .text
start:
    lea rbx, [rip+val]
    mov rcx, [rbx]
    add rcx, 0x7f         ; imm8 should encode via 0x83
    add rcx, 0x11223344   ; imm32 form
    sub [rbx], rcx
    cmp rcx, [rbx]
    xor rax, rcx
    and rcx, rax
    or rax, [rbx]
    add [rbx], rcx
    add [rbx+8], 5
    mov rdi, 0
    mov rax, 60
    syscall
section .data
val: dq 1, 2
