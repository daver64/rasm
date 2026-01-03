bits 16
org 0x7C00

; CR0 bits
%define CR0_PE  0x00000001  ; Protected Mode Enable

; Segment selectors
%define CODE32_SEL   0x08  ; Entry 1 in GDT
%define DATA32_SEL   0x10  ; Entry 2 in GDT

start:
    ; Disable interrupts during setup
    cli
    
    ; Clear segment registers
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00              ; Set up stack below bootloader
    
    ; Print loading message in real mode
    mov si, msg_loading
    
msg_loading: db "Loading...", 0
