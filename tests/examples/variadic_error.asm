section .text

; Macro requiring 2-4 parameters
%macro TEST 2-4
    mov %1, %2
%endmacro

global _start
_start:
    ; This should fail - only 1 parameter, minimum is 2
    TEST rax
    
    mov rax, 60
    xor rdi, rdi
    syscall
