; Simple Protected Mode Bootloader Example
; Demonstrates RASM's OSDev capabilities
;
; This bootloader:
; 1. Starts in 16-bit real mode
; 2. Sets up a minimal GDT
; 3. Enables protected mode
; 4. Switches to 32-bit protected mode
; 5. Displays a message using VGA text mode
;
; Build: ./rasm tests/examples/bootloader.asm -f bin -o bootloader.bin
; Test with QEMU: qemu-system-x86_64 -drive format=raw,file=bootloader.bin

bits 16
org 0x7C00

; CR0 bits
%define CR0_PE  0x00000001  ; Protected Mode Enable

; Segment selectors
%define CODE32_SEL   0x08  ; Entry 1 in GDT
%define DATA32_SEL   0x10  ; Entry 2 in GDT

; ============================================================================
; Boot sector entry point (Real Mode, 16-bit)
; ============================================================================
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
    call print_string_16
    
    ; Load GDT
    lgdt [gdt_descriptor]
    
    ; Enable Protected Mode
    mov eax, cr0
    or eax, CR0_PE
    mov cr0, eax
    
    ; Far jump to 32-bit code segment to flush pipeline
    jmp CODE32_SEL:protected_mode_entry

; ============================================================================
; Real Mode Helper Functions
; ============================================================================
print_string_16:
    ; Print null-terminated string pointed to by SI using BIOS
    mov ah, 0x0E                ; BIOS teletype output
.loop:
    lodsb                       ; Load byte from [SI] into AL
    test al, al                 ; Check for null terminator
    jz .done
    int 0x10                    ; BIOS video interrupt
    jmp .loop
.done:
    ret

; ============================================================================
; Global Descriptor Table (GDT)
; ============================================================================
align 8
gdt_start:
    ; Null descriptor (required)
    dq 0
    
    ; Code segment (0x08)
    dw 0xFFFF                   ; Limit low
    dw 0x0000                   ; Base low
    db 0x00                     ; Base middle
    db 0x9A                     ; Access: present, ring 0, code, executable, readable
    db 0xCF                     ; Flags: 4KB granularity, 32-bit | Limit high
    db 0x00                     ; Base high
    
    ; Data segment (0x10)
    dw 0xFFFF                   ; Limit low
    dw 0x0000                   ; Base low
    db 0x00                     ; Base middle
    db 0x92                     ; Access: present, ring 0, data, writable
    db 0xCF                     ; Flags: 4KB granularity, 32-bit | Limit high
    db 0x00                     ; Base high
gdt_end:

gdt_descriptor:
    dw gdt_end - gdt_start - 1  ; GDT limit (size - 1)
    dd gdt_start                ; GDT base address

; ============================================================================
; Protected Mode Code (32-bit)
; ============================================================================
bits 32
protected_mode_entry:
    ; Set up segment registers with data segment selector
    mov ax, DATA32_SEL
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    
    ; Print message to VGA text buffer at 0xB8000
    mov esi, msg_protected
    mov edi, 0xB8000            ; VGA text buffer address
    mov ah, 0x0F                ; White on black attribute
.print_loop:
    lodsb                       ; Load character from message
    test al, al                 ; Check for null terminator
    jz .done
    stosw                       ; Write character + attribute to VGA buffer
    jmp .print_loop

.done:
    ; Halt the system
    cli
.hang:
    hlt
    jmp .hang

; ============================================================================
; Data Section
; ============================================================================
msg_loading: db "Loading...", 13, 10, 0
msg_protected: db "Protected Mode Enabled! RASM OSDev Demo", 0

; ============================================================================
; Boot Signature
; ============================================================================
times 510-($-$$) db 0           ; Pad to 510 bytes
dw 0xAA55                       ; Boot signature
