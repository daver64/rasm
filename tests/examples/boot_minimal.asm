bits 16
org 0x7C00

%define CR0_PE  0x00000001

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00
    
    ; Load GDT
    lgdt [gdt_descriptor]
    
    ; Enable Protected Mode
    mov eax, cr0
    or eax, CR0_PE
    mov cr0, eax
    
    jmp $
    
; GDT
align 8
gdt_start:
    dq 0    ; Null descriptor
gdt_end:

gdt_descriptor:
    dw 7    ; Size: 1 entry * 8 bytes - 1
    dd gdt_start
