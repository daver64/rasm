; Working struct example with NASM-compatible syntax
;
; This demonstrates that struct definitions create offset symbols
; that can be used for manual struct field access

struc Vec3
    .x: resd 1      ; float x at offset 0
    .y: resd 1      ; float y at offset 4
    .z: resd 1      ; float z at offset 8
endstruc
; Vec3_size = 12 bytes

struc Matrix
    .m00: resd 1    ; offset 0
    .m01: resd 1    ; offset 4
    .m10: resd 1    ; offset 8
    .m11: resd 1    ; offset 12
endstruc
; Matrix_size = 16 bytes

section .data
    vec_data: dd 1.0, 2.0, 3.0          ; Sample vector data

section .bss
    my_vec: resb 12         ; Space for Vec3 (12 bytes)
    my_matrix: resb 16      ; Space for Matrix (16 bytes)

section .text
global _start

_start:
    ; Vec3 field offsets are: x=0, y=4, z=8
    ; Matrix field offsets are: m00=0, m01=4, m10=8, m11=12
    
    ; Copy vector data to my_vec
    lea rsi, [rip+vec_data]
    lea rdi, [rip+my_vec]
    mov eax, [rsi]          ; Load x
    mov [rdi], eax          ; Store to my_vec.x (offset 0)
    mov eax, [rsi+4]        ; Load y
    mov [rdi+4], eax        ; Store to my_vec.y (offset 4)
    mov eax, [rsi+8]        ; Load z
    mov [rdi+8], eax        ; Store to my_vec.z (offset 8)
    
    ; Initialize identity matrix manually
    lea rdi, [rip+my_matrix]
    mov dword [rdi], 1      ; m00 = 1.0 (offset 0)
    mov dword [rdi+4], 0    ; m01 = 0.0 (offset 4)
    mov dword [rdi+8], 0    ; m10 = 0.0 (offset 8)
    mov dword [rdi+12], 1   ; m11 = 1.0 (offset 12)
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
