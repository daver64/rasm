; Comprehensive conditional assembly test

%define DEBUG
%define VERSION 2

section .data
%ifdef DEBUG
    debug_msg: db "Debug mode", 10, 0
%endif

%ifndef RELEASE
    dev_flag: dq 1
%endif

section .text
global _start
_start:
    ; Multiple levels of nesting
    %ifdef DEBUG
        mov rax, 1           ; Level 1: included
        
        %ifdef VERSION
            mov rbx, 2       ; Level 2: included
            
            %ifndef RELEASE
                mov rcx, 3   ; Level 3: included
            %endif
        %endif
    %endif
    
    ; Test %else branches
    %ifdef UNDEFINED_SYMBOL
        ; Should skip
        mov rdx, 999
    %else
        ; Should include
        mov rdx, 42
    %endif
    
    ; Complex nesting with multiple branches
    %ifdef DEBUG
        %ifdef RELEASE
            ; Skip - RELEASE not defined
            mov rsi, 100
        %else
            ; Include - DEBUG defined and RELEASE not
            mov rsi, 200
        %endif
    %else
        %ifdef RELEASE
            ; Skip - DEBUG not in this branch
            mov rsi, 300
        %else
            ; Skip - DEBUG not in this branch
            mov rsi, 400
        %endif
    %endif
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
