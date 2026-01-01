global main
extern add_numbers
extern multiply_numbers

section .text
main:
    ; Test add_numbers(10, 20)
    mov rdi, 10
    mov rsi, 20
    call add_numbers
    
    ; Test multiply_numbers(3, 7)
    mov rdi, 3
    mov rsi, 7
    call multiply_numbers
    
    ; Return 0
    xor rax, rax
    ret
