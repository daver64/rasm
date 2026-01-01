; Test that extern symbols are allowed
section .text
global main
extern printf

main:
    ; This should work - printf is declared extern
    call printf
    ret
