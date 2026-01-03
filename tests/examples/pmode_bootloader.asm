; Simple Protected Mode Bootloader Example
; Demonstrates RASM's OSDev capabilities
;
; Build: ./rasm pmode_bootloader.asm -f bin -o boot.bin
; Test: qemu-system-x86_64 -drive format=raw,file=boot.bin

bits 16
org 0x7C00

start:
    ; Disable interrupts during setup
    cli
    
    ; Clear segment registers and setup stack
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00
    
    ; Load GDT
    lgdt [gdt_ptr]
    
    ; Enable Protected Mode - set CR0.PE bit
    mov eax, cr0
    or eax, 1                   ; Set PE (Protection Enable) bit
    mov cr0, eax
    
    ; Far jump to 32-bit code segment to flush pipeline
    ; This would be: jmp CODE32_SEL:protected_mode_start
    ; but for now we'll use a db/dd encoding
    db 0x66                     ; Operand size prefix for 32-bit
    db 0xEA                     ; Far JMP opcode
    dd protected_mode_start     ; Offset
    dw 0x08                     ; Segment selector (CODE32_SEL)

; ============================================================================
; Global Descriptor Table
; ============================================================================
align 8
gdt_start:
    ; Null descriptor (required)
    dq 0
    
    ; Code segment descriptor (selector 0x08)
    dw 0xFFFF                   ; Limit low (0-15)
    dw 0x0000                   ; Base low (0-15)
    db 0x00                     ; Base middle (16-23)
    db 0x9A                     ; Access: present, ring 0, code, executable, readable
    db 0xCF                     ; Flags (4KB gran, 32-bit) | Limit high (16-19)
    db 0x00                     ; Base high (24-31)
    
    ; Data segment descriptor (selector 0x10)
    dw 0xFFFF                   ; Limit low
    dw 0x0000                   ; Base low
    db 0x00                     ; Base middle
    db 0x92                     ; Access: present, ring 0, data, writable
    db 0xCF                     ; Flags (4KB gran, 32-bit) | Limit high
    db 0x00                     ; Base high
gdt_end:

gdt_ptr:
    dw gdt_end - gdt_start - 1  ; GDT limit (size - 1)
    dd gdt_start                ; GDT base address

; ============================================================================
; Protected Mode Code (32-bit)
; ============================================================================
bits 32
protected_mode_start:
    ; Setup data segments in protected mode
    mov ax, 0x10                ; Data segment selector
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov esp, 0x90000            ; New stack in extended memory
    
    ; Display message to VGA text mode (0xB8000)
    mov edi, 0xB8000
    mov esi, msg_protected
    mov ah, 0x0F                ; White on black attribute
.loop:
    lodsb
    test al, al
    jz .done
    mov [edi], ax
    add edi, 2
    jmp .loop
.done:
    ; Infinite loop
    jmp $

msg_protected: db "Protected Mode Active!", 0

; ============================================================================
; Boot signature
; ============================================================================
times 510-($-$$) db 0
dw 0xAA55
