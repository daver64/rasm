; Minimal Protected Mode Bootloader
; Demonstrates control register access and protected mode transition
;
; Build: ./rasm pmode_bootloader.asm -f bin -o boot.bin
; Test: qemu-system-x86_64 -drive format=raw,file=boot.bin

bits 16
org 0x7C00

start:
    cli                         ; Disable interrupts
    xor ax, ax
    mov ds, ax                  ; Zero data segment
    mov ss, ax                  ; Zero stack segment
    mov sp, 0x7C00              ; Stack grows down from bootloader
    
    ; Enable Protected Mode
    mov eax, cr0                ; Read CR0
    or eax, 1                   ; Set PE bit
    mov cr0, eax                ; Write back to CR0
    
    ; In a real bootloader, we'd do a far jump here to flush the pipeline
    ; and switch to 32-bit mode. For this minimal example, we just halt.
    sti                         ; Re-enable interrupts
    hlt                         ; Halt

; Boot signature
times 510-($-$$) db 0
dw 0xAA55
