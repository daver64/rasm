; Test optimal immediate encoding
section .text
global main

main:
    ; These should use sign-extended 8-bit immediates (smaller encoding)
    add rax, 5          ; Should be: 48 83 C0 05 (REX.W 83 /0 ib)
    add rax, 127        ; Should be: 48 83 C0 7F
    sub rbx, -128       ; Should be: 48 83 EB 80
    
    ; These should use full 32-bit immediates
    add rax, 128        ; Should be: 48 81 C0 80 00 00 00 (REX.W 81 /0 id)
    add rax, 0x12345    ; Should be: 48 81 C0 45 23 01 00
    
    ret
