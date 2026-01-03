; Comprehensive working example of NASM-compatible structs

struc Point
    .x: resq 1      ; 8 bytes (offset 0)
    .y: resq 1      ; 8 bytes (offset 8)
endstruc
; Point_size = 16

struc Vec3f
    .x: resd 1      ; 4 bytes (offset 0)
    .y: resd 1      ; 4 bytes (offset 4)
    .z: resd 1      ; 4 bytes (offset 8)
endstruc
; Vec3f_size = 12

section .data
    ; Sample data
    origin_x: dq 100
    origin_y: dq 200
    
section .bss
    ; Reserve space for struct instances
    my_point: resb 16       ; sizeof(Point)
    my_vec: resb 12         ; sizeof(Vec3f)

section .text
global _start

_start:
    ; Load struct field offsets (these are compile-time constants)
    mov r10, Point.x        ; r10 = 0
    mov r11, Point.y        ; r11 = 8
    mov r12, Point_size     ; r12 = 16
    
    mov r13, Vec3f.x        ; r13 = 0
    mov r14, Vec3f.y        ; r14 = 4
    mov r15, Vec3f.z        ; r15 = 8
    
    ; Initialize point using field offsets
    lea rdi, [rip+my_point]
    mov rax, [rip+origin_x]
    mov [rdi + 0], rax      ; my_point.x = origin_x (offset Point.x)
    mov rax, [rip+origin_y]
    mov [rdi + 8], rax      ; my_point.y = origin_y (offset Point.y)
    
    ; Calculate address using struct offset as immediate
    lea rdi, [rip+my_point]
    add rdi, Point.y        ; rdi now points to my_point.y
    mov rax, [rdi]          ; Load my_point.y
    
    ; Initialize vector (without size prefixes)
    lea rdi, [rip+my_vec]
    mov eax, 1
    mov [rdi], eax          ; my_vec.x = 1 (offset 0)
    xor eax, eax
    mov [rdi+4], eax        ; my_vec.y = 0 (offset 4)
    mov [rdi+8], eax        ; my_vec.z = 0 (offset 8)
    
    ; Exit successfully
    mov rax, 60
    xor rdi, rdi
    syscall
