; Test miscellaneous new instructions: LOOP, XLAT, IN/OUT, MOVBE
bits 64

section .text
global _start

_start:
    ; === LOOP instructions ===
    ; Set up loop counter in RCX
    mov rcx, 10
.loop_test:
    nop
    loop .loop_test         ; Decrement RCX and jump if not zero
    
    ; LOOPE/LOOPZ - Loop while equal/zero
    mov rcx, 5
.loope_test:
    cmp rax, rbx
    loope .loope_test       ; Loop while ZF=1 and RCX!=0
    
    ; LOOPNE/LOOPNZ - Loop while not equal/not zero
    mov rcx, 5
.loopne_test:
    cmp rax, rbx
    loopne .loopne_test     ; Loop while ZF=0 and RCX!=0
    
    ; === XLAT - Table lookup ===
    ; Set up translation table
    lea rbx, [rip+xlat_table]
    mov al, 3               ; Index to look up
    xlat                    ; AL = [RBX + AL]
    
    ; === Port I/O (requires privileges, will fault in usermode) ===
    ; These are here for encoding tests only
    
    ; IN with immediate port
    ; in al, 0x60           ; Read from port 0x60 (commented - would fault)
    ; in ax, 0x64
    ; in eax, 0x80
    
    ; IN with DX port
    mov dx, 0x3F8
    ; in al, dx             ; Read from port in DX (commented)
    ; in ax, dx
    ; in eax, dx
    
    ; OUT with immediate port
    ; out 0x60, al          ; Write to port 0x60 (commented)
    ; out 0x64, ax
    ; out 0x80, eax
    
    ; OUT with DX port
    mov dx, 0x3F8
    ; out dx, al            ; Write to port in DX (commented)
    ; out dx, ax
    ; out dx, eax
    
    ; === String I/O (commented - would fault) ===
    ; insb                  ; Input string byte from DX
    ; insw                  ; Input string word from DX
    ; insd                  ; Input string dword from DX
    ; outsb                 ; Output string byte to DX
    ; outsw                 ; Output string word to DX
    ; outsd                 ; Output string dword to DX
    
    ; === MOVBE - Move with byte swap ===
    ; Useful for endianness conversion
    lea rax, [rip+data_value]
    movbe rbx, [rax]        ; Load with byte swap
    movbe [rax], rcx        ; Store with byte swap
    
    ; 32-bit MOVBE
    movbe edx, [rax]
    movbe [rax], esi
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall

section .data
xlat_table:
    db 10, 20, 30, 40, 50, 60, 70, 80    ; Translation table
data_value:
    dq 0x0123456789ABCDEF                ; 64-bit value for MOVBE tests
