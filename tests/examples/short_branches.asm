; Test short branch optimization
section .text
global start

start:
    ; These should use short (2-byte) encoding
    jmp .local1
    nop
.local1:
    je .local2
    nop
.local2:
    jne .local3
    nop
.local3:
    ; Far jump (should use near encoding)
    jmp far_target
    
    ; Fill some space to ensure distance > 128 bytes
    times 120 nop
    
far_target:
    ret
