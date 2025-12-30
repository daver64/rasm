section .text

; Macro accepting 1-3 parameters
%macro TEST 1-3
    mov rax, %1
%endmacro

global _start
_start:
    ; This should fail - 5 parameters, maximum is 3
    TEST 1, 2, 3, 4, 5
    
    mov rax, 60
    xor rdi, rdi
    syscall
