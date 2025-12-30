; Test 8/16/32/64-bit operand support for ALU instructions
section .text

global _start
_start:
    ; ADD with different sizes
    add rax, rbx            ; 64-bit
    add eax, ebx            ; 32-bit
    add ax, bx              ; 16-bit
    add al, bl              ; 8-bit
    add eax, [rsp]          ; 32-bit from memory
    add eax, 42             ; 32-bit with immediate
    add ax, 100             ; 16-bit with immediate
    add al, 5               ; 8-bit with immediate
    
    ; SUB with different sizes
    sub rax, rbx            ; 64-bit
    sub eax, ebx            ; 32-bit
    sub ax, bx              ; 16-bit
    sub al, bl              ; 8-bit
    sub ecx, 10             ; 32-bit with immediate
    
    ; XOR with different sizes
    xor rax, rax            ; 64-bit (common zeroing idiom)
    xor eax, eax            ; 32-bit (also zeros upper 32 bits)
    xor ax, ax              ; 16-bit
    xor al, al              ; 8-bit
    xor ecx, edx            ; 32-bit reg-reg
    
    ; AND with different sizes
    and rax, 0xFF           ; 64-bit with immediate
    and eax, 0xFF           ; 32-bit with immediate
    and ax, 0xFF            ; 16-bit with immediate
    and al, 0x0F            ; 8-bit with immediate
    and eax, ebx            ; 32-bit reg-reg
    
    ; OR with different sizes
    or rax, rbx             ; 64-bit
    or eax, ebx             ; 32-bit
    or ax, bx               ; 16-bit
    or al, bl               ; 8-bit
    or eax, 0x80000000      ; 32-bit with immediate
    
    ; CMP with different sizes
    cmp rax, rbx            ; 64-bit
    cmp eax, ebx            ; 32-bit
    cmp ax, bx              ; 16-bit
    cmp al, bl              ; 8-bit
    cmp eax, 0              ; 32-bit with immediate
    cmp ax, 100             ; 16-bit with immediate
    cmp al, 5               ; 8-bit with immediate
    
    ; TEST with different sizes
    test rax, rax           ; 64-bit
    test eax, eax           ; 32-bit
    test ax, ax             ; 16-bit
    test al, al             ; 8-bit
    test eax, 0xFF          ; 32-bit with immediate
    test ax, 0xFF           ; 16-bit with immediate
    test al, 0x0F           ; 8-bit with immediate
    test eax, ebx           ; 32-bit reg-reg
    test ax, bx             ; 16-bit reg-reg
    test al, bl             ; 8-bit reg-reg
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall

section .data
test_val: dd 0x12345678
