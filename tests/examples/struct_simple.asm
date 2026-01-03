; Test NASM-compatible struct support - simple version

; Define a Point structure
struc Point
    .x: resq 1      ; 8 bytes (offset 0)
    .y: resq 1      ; 8 bytes (offset 8)
endstruc

section .bss
    ; Reserve space manually with literal size
    point1: resb 16     ; Point_size is 16 bytes

section .text
global _start

_start:
    ; Access struct fields using offsets
    ; point1.x = 10
    mov qword [point1 + Point.x], 10
    
    ; point1.y = 20
    mov qword [point1 + Point.y], 20
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
