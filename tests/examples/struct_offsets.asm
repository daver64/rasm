; Test struct field offsets as immediate values

struc Point
    .x: resq 1      ; offset 0
    .y: resq 1      ; offset 8
endstruc

struc Vec3
    .x: resd 1      ; offset 0
    .y: resd 1      ; offset 4
    .z: resd 1      ; offset 8
endstruc

section .data
    msg: db "Testing struct offsets", 10, 0

section .text
global _start

_start:
    ; Load struct field offsets into registers
    mov rax, Point.x         ; rax = 0
    mov rbx, Point.y         ; rbx = 8
    mov rcx, Point_size      ; rcx = 16
    
    mov rdx, Vec3.x          ; rdx = 0
    mov rsi, Vec3.y          ; rsi = 4
    mov rdi, Vec3.z          ; rdi = 8
    mov r8, Vec3_size        ; r8 = 12
    
    ; Verify values (for debugging with gdb)
    ; Expected: rax=0, rbx=8, rcx=16, rdx=0, rsi=4, rdi=8, r8=12
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
