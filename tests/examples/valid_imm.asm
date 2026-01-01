; Test valid immediate
section .text
global main

main:
    ; Valid immediates for each size
    mov al, 0xFF        ; 8-bit: max unsigned
    mov ax, 0xFFFF      ; 16-bit: max unsigned
    mov eax, 0xFFFFFFFF ; 32-bit: max unsigned
    mov rax, 0x1234567890ABCDEF ; 64-bit: any value
    
    ; Valid signed immediates
    mov al, -128        ; 8-bit: min signed
    mov ax, -32768      ; 16-bit: min signed
    ret
