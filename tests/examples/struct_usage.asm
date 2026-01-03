; Test struct usage with explicit offsets

; Define a Point structure
struc Point
    .x: resq 1      ; 8 bytes (offset 0)
    .y: resq 1      ; 8 bytes (offset 8)
endstruc

section .bss
    point1: resb 16     ; sizeof(Point) = 16

section .text
global _start

_start:
    ; Access struct fields using explicit numeric offsets
    ; These should work since we know Point.x = 0, Point.y = 8
    
    ; point1.x = 10
    mov qword [point1 + 0], 10
    
    ; point1.y = 20
    mov qword [point1 + 8], 20
    
    ; Load values back
    mov rax, [point1 + 0]   ; rax = point1.x
    mov rbx, [point1 + 8]   ; rbx = point1.y
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
