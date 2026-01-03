; Test 32-bit misc instructions
bits 32

section .text
global _start

_start:
    ; LOOP instructions in 32-bit
    mov ecx, 10
.loop32:
    nop
    loop .loop32
    
    ; XLAT in 32-bit (uses EBX as base)
    mov ebx, xlat_table
    mov al, 2
    xlat
    
    ; MOVBE in 32-bit (commented - may not work in 32-bit mode)
    ; mov eax, data_val
    ; movbe ebx, [eax]
    ; movbe [eax], ecx
    
    ; Exit (32-bit syscall)
    mov eax, 1
    xor ebx, ebx
    int 0x80

section .data
xlat_table:
    db 10, 20, 30, 40
data_val:
    dd 0x12345678
