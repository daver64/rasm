; Test for Protected Mode Instructions
; Tests all newly added OSDev-specific instructions

bits 64
section .text
global _start

_start:
    ; ===== Descriptor Table Instructions =====
    ; LGDT/LIDT - Load GDT/IDT
    lgdt [rip+gdt_descriptor]
    lidt [rip+idt_descriptor]
    
    ; SGDT/SIDT - Store GDT/IDT
    sgdt [rip+gdt_save]
    sidt [rip+idt_save]
    
    ; ===== Task Register Instructions =====
    ; LTR/STR - Load/Store Task Register
    mov ax, 0x28
    ltr ax
    str bx
    str [rip+tr_save]
    
    ; ===== LDT Instructions =====
    ; LLDT/SLDT - Load/Store Local Descriptor Table
    mov cx, 0x30
    lldt cx
    sldt dx
    sldt [rip+ldt_save]
    
    ; ===== Segment Descriptor Inspection =====
    ; LAR - Load Access Rights
    lar rax, rbx            ; 64-bit
    lar eax, ebx            ; 32-bit
    lar rax, [rip+selector]
    
    ; LSL - Load Segment Limit
    lsl rax, rcx            ; 64-bit
    lsl eax, ecx            ; 32-bit
    lsl rax, [rip+selector]
    
    ; ===== Segment Verification =====
    ; VERR/VERW - Verify Read/Write
    verr ax
    verw bx
    verr [rip+selector]
    verw [rip+selector]
    
    ; ===== Control Register Access =====
    ; MOV CR - Move to/from Control Registers
    mov rax, cr0            ; Read CR0
    mov cr0, rax            ; Write CR0
    
    mov rbx, cr2            ; Read CR2 (page fault address)
    mov cr2, rbx
    
    mov rcx, cr3            ; Read CR3 (page directory base)
    mov cr3, rcx            ; Write CR3
    
    mov rdx, cr4            ; Read CR4
    mov cr4, rdx            ; Write CR4
    
    mov r8, cr8             ; Read CR8 (Task Priority Register, 64-bit only)
    mov cr8, r8
    
    ; ===== Debug Register Access =====
    ; MOV DR - Move to/from Debug Registers
    mov rax, dr0            ; Read DR0 (breakpoint 0)
    mov dr0, rax            ; Write DR0
    
    mov rbx, dr1            ; Read DR1 (breakpoint 1)
    mov dr1, rbx
    
    mov rcx, dr2            ; Read DR2 (breakpoint 2)
    mov dr2, rcx
    
    mov rdx, dr3            ; Read DR3 (breakpoint 3)
    mov dr3, rdx
    
    mov rsi, dr6            ; Read DR6 (debug status)
    mov dr6, rsi
    
    mov rdi, dr7            ; Read DR7 (debug control)
    mov dr7, rdi
    
    ; ===== Task-Switched Flag =====
    ; CLTS - Clear Task-Switched Flag in CR0
    clts
    
    ; ===== Machine Status Word =====
    ; LMSW/SMSW - Load/Store Machine Status Word (legacy, lower 16 bits of CR0)
    mov r9w, 0x0001
    lmsw r9w
    smsw r10w
    smsw [rip+msw_save]
    
    ; ===== TLB Management =====
    ; INVLPG - Invalidate TLB Entry
    invlpg [rip+page_addr]
    invlpg [rbx]
    
    ; ===== Cache Management =====
    ; INVD - Invalidate Cache (no writeback)
    invd
    
    ; WBINVD - Write Back and Invalidate Cache
    wbinvd
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall

section .data
align 16
gdt_descriptor:
    dw 0x00FF
    dq 0x0000000000000000

idt_descriptor:
    dw 0x0FFF
    dq 0x0000000000000000

selector:
    dw 0x0008

page_addr:
    dq 0x0000000000400000

section .bss
gdt_save: resb 10
idt_save: resb 10
tr_save: resw 1
ldt_save: resw 1
msw_save: resw 1
