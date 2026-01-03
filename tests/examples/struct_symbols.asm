; Test struct symbol definitions

; Define a Point structure
struc Point
    .x: resq 1      ; 8 bytes (offset 0)
    .y: resq 1      ; 8 bytes (offset 8)
endstruc

section .text
global _start

_start:
    ; Test that struct field offsets are defined
    mov rax, Point.x      ; Should be 0
    mov rbx, Point.y      ; Should be 8
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
