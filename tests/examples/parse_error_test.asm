; Test parse error with line number
section .text
global main

main:
    mov rax, rbx
    unknowninstruction rax, rbx    ; This should give parse error
    ret
