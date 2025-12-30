; Test 32-bit operand support for various instructions
section .text

global _start
_start:
    ; MOV with 32-bit registers (already implemented)
    mov eax, ebx
    mov ecx, [rsp]
    mov [rsp+8], edx
    
    ; BSF/BSR - bit scan with 32-bit
    bsf eax, ebx
    bsr ecx, edx
    bsf eax, [rsp]
    
    ; BT/BTC/BTR/BTS - bit test with 32-bit
    bt eax, ebx
    btc ecx, edx
    btr esi, edi
    bts eax, 5
    bt ecx, 31
    
    ; BSWAP - byte swap with 32-bit
    bswap eax
    bswap ebx
    bswap r8d
    
    ; LZCNT/TZCNT/POPCNT with 32-bit
    lzcnt eax, ebx
    tzcnt ecx, edx
    popcnt esi, edi
    popcnt eax, [rsp]
    
    ; BMI2 VEX-encoded instructions with 32-bit
    andn eax, ebx, ecx
    pdep esi, edi, r8d
    pext eax, ebx, [rsp]
    
    ; BMI instructions with 32-bit
    blsi eax, ebx
    blsmsk ecx, edx
    blsr esi, edi
    
    ; BMI2 shift instructions with 32-bit
    bextr eax, ebx, ecx
    bzhi esi, edi, r8d
    sarx eax, ebx, ecx
    shlx esi, edi, r8d
    shrx eax, [rsp], ebx
    rorx eax, ebx, 7
    
    ; 16-bit variants
    mov ax, bx
    bsf ax, cx
    bsr dx, si
    bt ax, 5
    lzcnt ax, bx
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall

section .data
test_val: dd 0x12345678
