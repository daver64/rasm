; Comprehensive NASM-compatible struct test

; Define multiple structs with various field sizes
struc Point
    .x: resq 1      ; 8 bytes (offset 0)
    .y: resq 1      ; 8 bytes (offset 8)
endstruc
; Point_size will be 16

struc RGB
    .r: resb 1      ; 1 byte (offset 0)
    .g: resb 1      ; 1 byte (offset 1)
    .b: resb 1      ; 1 byte (offset 2)
endstruc
; RGB_size will be 3

struc Header
    .magic: resd 1      ; 4 bytes (offset 0)
    .version: resw 1    ; 2 bytes (offset 4)
    .flags: resw 1      ; 2 bytes (offset 6)
    .size: resq 1       ; 8 bytes (offset 8)
endstruc
; Header_size will be 16

section .data
    ; Test message
    msg: db "Struct test complete", 10, 0

section .bss
    ; Reserve space for struct instances using explicit sizes
    my_point: resb 16       ; sizeof(Point)
    color: resb 3           ; sizeof(RGB)
    hdr: resb 16            ; sizeof(Header)

section .text
global _start

_start:
    ; Initialize Point struct (offsets: x=0, y=8)
    mov rax, 100
    mov [my_point], rax         ; my_point.x = 100 (offset 0)
    mov rax, 200
    lea rbx, [my_point + 8]
    mov [rbx], rax              ; my_point.y = 200
    
    ; Initialize RGB struct (offsets: r=0, g=1, b=2)
    mov byte [color], 0xFF      ; color.r = 255 (offset 0)
    lea rbx, [color + 1]
    mov byte [rbx], 0x80        ; color.g = 128
    
    ; Initialize Header struct using explicit addresses
    mov dword [hdr], 0x12345678 ; hdr.magic = 0x12345678
    
    ; Exit successfully
    mov rax, 60
    xor rdi, rdi
    syscall
