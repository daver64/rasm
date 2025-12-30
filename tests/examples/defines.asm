; Test %define directives (Phase 2)

%define SYSCALL_EXIT 60
%define STDOUT 1
%define EXIT_SUCCESS 0

%define BUFFER_SIZE 1024
%define MAX_COUNT 100

section .text

global _start
_start:
    ; Use simple defines
    mov rax, SYSCALL_EXIT
    mov rdi, EXIT_SUCCESS
    
    ; Use in expressions
    mov rcx, BUFFER_SIZE
    add rcx, MAX_COUNT
    
    ; Use in memory operands
    mov rbx, BUFFER_SIZE
    mov rdx, [rsp + BUFFER_SIZE]
    
    ; Final exit
    mov rax, SYSCALL_EXIT
    mov rdi, EXIT_SUCCESS
    syscall
