; Simple struct definition test

struc Point
    .x: resq 1
    .y: resq 1
endstruc

struc RGB
    .r: resb 1
    .g: resb 1
    .b: resb 1
endstruc

section .text
global _start
_start:
    mov rax, 60
    xor rdi, rdi
    syscall
