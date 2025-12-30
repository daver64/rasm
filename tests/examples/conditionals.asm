; Test Phase 3 conditional assembly

%define LINUX
; %define WINDOWS

section .text
global _start
_start:
    ; Test %ifdef
    %ifdef LINUX
        mov rax, 60      ; Linux exit syscall
    %endif
    
    ; Test %ifndef
    %ifndef WINDOWS
        mov rdi, 0       ; Linux exit code
    %endif
    
    ; Test %ifdef with %else
    %ifdef WINDOWS
        ; This should be skipped
        int 0x21
    %else
        ; This should be included
        syscall
    %endif
    
    ; Nested conditionals
    %ifdef LINUX
        %ifdef WINDOWS
            ; Should be skipped (WINDOWS not defined)
            nop
        %else
            ; Should be included
            nop
        %endif
    %endif
