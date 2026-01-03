; OS Development Helper Macros for RASM
; NASM-compatible macros for building OS kernels, bootloaders, and protected mode code
;
; This file provides convenient macros for:
; - GDT (Global Descriptor Table) entries
; - IDT (Interrupt Descriptor Table) entries
; - Page table entries
; - Segment selectors
; - Common OS constants

; ============================================================================
; GDT (Global Descriptor Table) Macros
; ============================================================================

; GDT Entry - Create a full GDT descriptor
; Parameters: base (32-bit), limit (20-bit), access (8-bit), flags (4-bit)
;
; Access byte format (from low to high bit):
;   Bit 0-1: Accessed (set by CPU)
;   Bit 1:   Readable (code) / Writable (data)
;   Bit 2:   Direction/Conforming
;   Bit 3:   Executable (1=code, 0=data)
;   Bit 4:   Descriptor type (1=code/data, 0=system)
;   Bit 5-6: DPL (privilege level, 0=kernel, 3=user)
;   Bit 7:   Present (must be 1)
;
; Flags nibble (4 bits):
;   Bit 0:   Reserved (should be 0)
;   Bit 1:   Long mode (1=64-bit code segment)
;   Bit 2:   Size (1=32-bit, 0=16-bit)
;   Bit 3:   Granularity (1=4KB, 0=1B)
;
%macro GDT_ENTRY 4
    dw (%2 & 0xFFFF)                    ; Limit low (bits 0-15)
    dw (%1 & 0xFFFF)                    ; Base low (bits 0-15)
    db ((%1 >> 16) & 0xFF)              ; Base middle (bits 16-23)
    db %3                               ; Access byte
    db (((%2 >> 16) & 0x0F) | ((%4 & 0x0F) << 4))  ; Limit high + Flags
    db ((%1 >> 24) & 0xFF)              ; Base high (bits 24-31)
%endmacro

; Simplified GDT entry macros with common access/flag combinations
%macro GDT_NULL 0
    dq 0  ; Null descriptor (required as first entry)
%endmacro

%macro GDT_CODE_32 0
    GDT_ENTRY 0, 0xFFFFF, 0x9A, 0xC  ; 32-bit code: base=0, limit=4GB, ring 0
%endmacro

%macro GDT_DATA_32 0
    GDT_ENTRY 0, 0xFFFFF, 0x92, 0xC  ; 32-bit data: base=0, limit=4GB, ring 0
%endmacro

%macro GDT_CODE_64 0
    GDT_ENTRY 0, 0, 0x9A, 0xA        ; 64-bit code: base=0, limit ignored, ring 0
%endmacro

%macro GDT_DATA_64 0
    GDT_ENTRY 0, 0, 0x92, 0xC        ; 64-bit data: base=0, limit ignored, ring 0
%endmacro

%macro GDT_CODE_USER_32 0
    GDT_ENTRY 0, 0xFFFFF, 0xFA, 0xC  ; 32-bit user code: ring 3
%endmacro

%macro GDT_DATA_USER_32 0
    GDT_ENTRY 0, 0xFFFFF, 0xF2, 0xC  ; 32-bit user data: ring 3
%endmacro

%macro GDT_CODE_USER_64 0
    GDT_ENTRY 0, 0, 0xFA, 0xA        ; 64-bit user code: ring 3
%endmacro

%macro GDT_DATA_USER_64 0
    GDT_ENTRY 0, 0, 0xF2, 0xC        ; 64-bit user data: ring 3
%endmacro

; TSS descriptor (takes base address and limit)
%macro GDT_TSS 2
    GDT_ENTRY %1, %2, 0x89, 0x0      ; TSS: present, ring 0, 32-bit available TSS
%endmacro

; ============================================================================
; IDT (Interrupt Descriptor Table) Macros
; ============================================================================

; IDT Entry - Create interrupt gate descriptor
; Parameters: offset (32/64-bit address), selector (16-bit), type_attr (8-bit)
;
; Type/Attr byte:
;   Bits 0-3: Gate type (0xE=interrupt gate, 0xF=trap gate)
;   Bit 4:    Zero
;   Bits 5-6: DPL (privilege level)
;   Bit 7:    Present flag

; 32-bit IDT entry
%macro IDT_ENTRY_32 3
    dw (%1 & 0xFFFF)                    ; Offset low (bits 0-15)
    dw %2                               ; Selector
    db 0                                ; Reserved (always 0)
    db %3                               ; Type and attributes
    dw ((%1 >> 16) & 0xFFFF)            ; Offset high (bits 16-31)
%endmacro

; 64-bit IDT entry
%macro IDT_ENTRY_64 3
    dw (%1 & 0xFFFF)                    ; Offset low (bits 0-15)
    dw %2                               ; Selector
    db 0                                ; IST (Interrupt Stack Table)
    db %3                               ; Type and attributes
    dw ((%1 >> 16) & 0xFFFF)            ; Offset middle (bits 16-31)
    dd ((%1 >> 32) & 0xFFFFFFFF)        ; Offset high (bits 32-63)
    dd 0                                ; Reserved
%endmacro

; Simplified IDT entry macros
%macro IDT_INTERRUPT_GATE_32 2
    IDT_ENTRY_32 %1, %2, 0x8E           ; 32-bit interrupt gate, ring 0
%endmacro

%macro IDT_TRAP_GATE_32 2
    IDT_ENTRY_32 %1, %2, 0x8F           ; 32-bit trap gate, ring 0
%endmacro

%macro IDT_INTERRUPT_GATE_64 2
    IDT_ENTRY_64 %1, %2, 0x8E           ; 64-bit interrupt gate, ring 0
%endmacro

%macro IDT_TRAP_GATE_64 2
    IDT_ENTRY_64 %1, %2, 0x8F           ; 64-bit trap gate, ring 0
%endmacro

; ============================================================================
; Segment Selector Calculation
; ============================================================================

; Calculate segment selector from GDT index
; Selector = (index * 8) | RPL | TI
; RPL = Requested Privilege Level (0-3)
; TI = Table Indicator (0=GDT, 1=LDT)
%define SEL_RPL0 0
%define SEL_RPL1 1
%define SEL_RPL2 2
%define SEL_RPL3 3
%define SEL_TI_GDT 0
%define SEL_TI_LDT 4

; Common selector values (assuming standard GDT layout):
%define NULL_SEL     0x00
%define CODE32_SEL   0x08  ; Entry 1 in GDT
%define DATA32_SEL   0x10  ; Entry 2 in GDT
%define CODE64_SEL   0x18  ; Entry 3 in GDT (if present)
%define DATA64_SEL   0x20  ; Entry 4 in GDT (if present)

; ============================================================================
; Page Table Entry Macros (32-bit and PAE)
; ============================================================================

; Page Directory Entry flags (32-bit paging)
%define PDE_PRESENT     0x001  ; Page is present in memory
%define PDE_WRITABLE    0x002  ; Read/write (if 0, read-only)
%define PDE_USER        0x004  ; User mode accessible
%define PDE_WRITE_THRU  0x008  ; Write-through caching
%define PDE_NO_CACHE    0x010  ; Disable caching
%define PDE_ACCESSED    0x020  ; Set by CPU on access
%define PDE_SIZE_4MB    0x080  ; 4MB page size (if PSE enabled)

; Page Table Entry flags (32-bit paging)
%define PTE_PRESENT     0x001  ; Page is present
%define PTE_WRITABLE    0x002  ; Read/write
%define PTE_USER        0x004  ; User mode
%define PTE_WRITE_THRU  0x008  ; Write-through
%define PTE_NO_CACHE    0x010  ; Disable cache
%define PTE_ACCESSED    0x020  ; Accessed
%define PTE_DIRTY       0x040  ; Dirty (written to)
%define PTE_PAT         0x080  ; Page Attribute Table
%define PTE_GLOBAL      0x100  ; Global (not flushed from TLB)

; ============================================================================
; Control Register Bits
; ============================================================================

; CR0 bits
%define CR0_PE  0x00000001  ; Protected Mode Enable
%define CR0_MP  0x00000002  ; Monitor Coprocessor
%define CR0_EM  0x00000004  ; Emulation
%define CR0_TS  0x00000008  ; Task Switched
%define CR0_ET  0x00000010  ; Extension Type
%define CR0_NE  0x00000020  ; Numeric Error
%define CR0_WP  0x00010000  ; Write Protect
%define CR0_AM  0x00040000  ; Alignment Mask
%define CR0_NW  0x20000000  ; Not Write-through
%define CR0_CD  0x40000000  ; Cache Disable
%define CR0_PG  0x80000000  ; Paging Enable

; CR3 bits
%define CR3_PWT 0x008       ; Page-level Write-Through
%define CR3_PCD 0x010       ; Page-level Cache Disable

; CR4 bits
%define CR4_VME  0x0001     ; Virtual-8086 Mode Extensions
%define CR4_PVI  0x0002     ; Protected Mode Virtual Interrupts
%define CR4_TSD  0x0004     ; Time Stamp Disable
%define CR4_DE   0x0008     ; Debugging Extensions
%define CR4_PSE  0x0010     ; Page Size Extensions (4MB pages)
%define CR4_PAE  0x0020     ; Physical Address Extension
%define CR4_MCE  0x0040     ; Machine Check Enable
%define CR4_PGE  0x0080     ; Page Global Enable
%define CR4_PCE  0x0100     ; Performance Monitoring Counter Enable
%define CR4_OSFXSR 0x0200   ; OS Support for FXSAVE/FXRSTOR
%define CR4_OSXMMEXCPT 0x0400  ; OS Support for Unmasked SIMD FP Exceptions

; ============================================================================
; EFLAGS bits
; ============================================================================
%define EFLAGS_CF   0x0001  ; Carry Flag
%define EFLAGS_PF   0x0004  ; Parity Flag
%define EFLAGS_AF   0x0010  ; Auxiliary Carry Flag
%define EFLAGS_ZF   0x0040  ; Zero Flag
%define EFLAGS_SF   0x0080  ; Sign Flag
%define EFLAGS_TF   0x0100  ; Trap Flag
%define EFLAGS_IF   0x0200  ; Interrupt Enable Flag
%define EFLAGS_DF   0x0400  ; Direction Flag
%define EFLAGS_OF   0x0800  ; Overflow Flag
%define EFLAGS_IOPL 0x3000  ; I/O Privilege Level
%define EFLAGS_NT   0x4000  ; Nested Task
%define EFLAGS_RF   0x10000 ; Resume Flag
%define EFLAGS_VM   0x20000 ; Virtual-8086 Mode
%define EFLAGS_AC   0x40000 ; Alignment Check
%define EFLAGS_VIF  0x80000 ; Virtual Interrupt Flag
%define EFLAGS_VIP  0x100000 ; Virtual Interrupt Pending
%define EFLAGS_ID   0x200000 ; ID Flag

; ============================================================================
; Utility Macros
; ============================================================================

; Load GDT from a descriptor
%macro LOAD_GDT 1
    lgdt [%1]
%endmacro

; Load IDT from a descriptor
%macro LOAD_IDT 1
    lidt [%1]
%endmacro

; Enable Protected Mode (sets CR0.PE)
%macro ENABLE_PMODE 0
    mov eax, cr0
    or eax, CR0_PE
    mov cr0, eax
%endmacro

; Enable Paging (sets CR0.PG)
%macro ENABLE_PAGING 0
    mov eax, cr0
    or eax, CR0_PG
    mov cr0, eax
%endmacro

; Far jump to flush pipeline and load new code segment
; Usage: FAR_JMP selector, offset_label
%macro FAR_JMP 2
    jmp %1:%2
%endmacro

; Set up segment registers (for protected mode initialization)
%macro SETUP_SEGMENTS 1
    mov ax, %1      ; Load data segment selector
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
%endmacro

; Disable interrupts
%macro CLI_SAFE 0
    cli
%endmacro

; Enable interrupts
%macro STI_SAFE 0
    sti
%endmacro

; Halt and catch fire (HCF) - infinite halt loop
%macro HCF 0
    cli
%%hang:
    hlt
    jmp %%hang
%endmacro
