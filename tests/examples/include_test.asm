; Test %include directive

%include "tests/examples/syscalls.inc"

section .data
mydata: dq 0

section .text
global _start
_start:
    ; Use defines from included file
    mov rax, SYS_EXIT
    mov rdi, [rip+mydata]
    syscall
