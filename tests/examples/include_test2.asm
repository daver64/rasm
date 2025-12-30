; Test %include with %define substitution
%include "tests/examples/syscalls.inc"

section .data
mydata: dq 0

section .text
global _start

_start:
    mov rax, SYS_EXIT        ; Should be 60
    mov rdi, [rip+mydata]
    syscall
