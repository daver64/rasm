; Test %rep/%endrep loops
BITS 64

; Simple repetition
%rep 3
    nop
%endrep

; Repeat with instructions
%rep 4
    inc rax
%endrep

; Nested %rep
%rep 2
    %rep 3
        xor rbx, rbx
    %endrep
%endrep

; Can use %assign with %rep
%assign repeat_count 5
%rep repeat_count
    dec rcx
%endrep

; Test with data
section .data
%rep 8
    db 0xFF
%endrep

section .text
ret
