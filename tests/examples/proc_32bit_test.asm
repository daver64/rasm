; Test proc/endproc in 32-bit mode
bits 32

section .text
global _start

proc test_32, 16
    mov eax, 42
    mov [ebp-4], eax
endproc

_start:
    call test_32
    mov eax, 1
    xor ebx, ebx
    int 0x80
