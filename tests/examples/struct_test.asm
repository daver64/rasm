; Test NASM-compatible struct support

; Define a Point structure
struc Point
    .x: resq 1      ; 8 bytes (offset 0)
    .y: resq 1      ; 8 bytes (offset 8)
endstruc

; Define a Rectangle structure  
struc Rectangle
    .x: resd 1      ; 4 bytes (offset 0)
    .y: resd 1      ; 4 bytes (offset 4)
    .width: resd 1  ; 4 bytes (offset 8)
    .height: resd 1 ; 4 bytes (offset 12)
endstruc

section .data
    ; Can use struct field offsets
    msg: db "Struct test", 10, 0
    
section .bss
    ; Reserve space for struct instances
    point1: resb Point_size
    rect1: resb Rectangle_size

section .text
global _start

_start:
    ; Access struct fields using offsets
    ; point1.x = 10
    mov qword [point1 + Point.x], 10
    
    ; point1.y = 20
    mov qword [point1 + Point.y], 20
    
    ; rect1.x = 5
    mov dword [rect1 + Rectangle.x], 5
    
    ; rect1.width = 100
    mov dword [rect1 + Rectangle.width], 100
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
