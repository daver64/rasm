; TIMES directive examples - supporting both data and instructions
;
; The TIMES directive repeats data or instructions a specified number of times.
; The count can be:
;   - A constant: times 10 nop
;   - An expression: times 2+3 inc rax
;   - Position-dependent: times 512-($-$$) db 0
;
; Position-dependent expressions use:
;   $  = current position (origin + offset)
;   $$ = section start (origin)

bits 64
section .text

; Example 1: Fixed count with instructions
test1:
    times 5 nop                 ; Repeat NOP 5 times
    times 3 inc rax             ; Repeat inc rax 3 times
    ret

; Example 2: Alignment using position-dependent times
test2:
    mov rax, 1
    syscall
    ; Pad to next 16-byte boundary using times
    times 16-($-$$) nop         ; Fill until offset 16
    mov rax, 60                 ; This starts at offset 16
    ret

; Example 3: Fixed-size code blocks
test3:
    push rbp
    mov rbp, rsp
    ; Function body
    pop rbp
    ret
    ; Pad function to 32 bytes total
    times 32-($-test3) nop

; Example 4: Data with times (traditional usage)
section .data
    buffer: times 64 db 0       ; 64-byte zero-filled buffer
    pattern: times 16 db 0xAA   ; 16 bytes of 0xAA
    
; Example 5: Mixed data and instructions
section .text
test5:
    times 10 nop                ; 10 NOPs
    db 0x90                     ; Single NOP as data
    times 5 db 0x90             ; 5 NOPs as data
    nop                         ; Single NOP as instruction

; Example 6: Practical bootsector padding
bits 16
org 0x7C00
boot:
    mov ax, 0x0E41              ; BIOS teletype 'A'
    int 0x10                    ; Print character
    jmp $                       ; Infinite loop
    ; Pad to 510 bytes and add signature
    times 510-($-$$) db 0       ; Fill to byte 510
    dw 0xAA55                   ; Boot signature at bytes 510-511
