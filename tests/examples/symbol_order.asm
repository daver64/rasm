; Test symbol table ordering
section .text
global main
extern printf

local_func:
    ret

main:
    call printf
    call local_func
    ret
