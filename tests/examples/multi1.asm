; File 1 - defines data section
section .data
msg1: db "First file", 0

section .text
func1:
    mov rax, [rip+msg1]
    ret
