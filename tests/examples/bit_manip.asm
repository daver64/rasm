; Bit Manipulation Instructions Test
.text
.global _start
_start:
    ; Bit scan
    bsf rax, rbx
    bsr rcx, rdx
    
    ; Bit test with register
    bt rsi, rdi
    btc r8, r9
    btr r10, r11
    bts r12, r13
    
    ; Bit test with immediate
    bt rax, 5
    btc rbx, 10
    btr rcx, 15
    bts rdx, 20
    
    ; Byte swap
    bswap rax
    bswap rcx
    bswap r15
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
