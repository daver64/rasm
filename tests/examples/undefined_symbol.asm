; Test undefined symbol detection
section .text
global main

main:
    ; undefined_function is not defined or declared extern
    call undefined_function
    ret
