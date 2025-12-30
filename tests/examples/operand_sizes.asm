; Test file for 8/16/32/64-bit operand sizes

section .text
global _start

_start:
    ; 64-bit operations (existing)
    mov rax, 0x1234567890ABCDEF
    mov rbx, rcx
    add rax, rbx
    sub rdx, 100
    
    ; 32-bit operations (new)
    mov eax, 0x12345678
    mov ebx, ecx
    add eax, ebx
    sub edx, 50
    xor eax, eax
    cmp ebx, 42
    
    ; 16-bit operations (new)
    mov ax, 0x1234
    mov bx, cx
    add ax, bx
    sub dx, 10
    and ax, 0xFF
    or bx, 1
    
    ; 8-bit operations (new)
    mov al, 0x12
    mov bl, cl
    add al, bl
    sub dl, 5
    xor al, al
    cmp bl, 10
    
    ; Exit syscall
    mov rax, 60
    xor edi, edi
    syscall
