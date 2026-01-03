bits 16
org 0x7C00

start:
    cli
    mov eax, cr0
    or eax, 1
    mov cr0, eax
    jmp $
