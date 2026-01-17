; Comprehensive test of all advanced NASM features
BITS 64

; Test %imacro (case-insensitive)
%imacro SafePush 1
    push %1
%endmacro

SafePush rax
safepush rbx
SAFEPUSH rcx

; Test %deftok and %defstr
%deftok myreg r8
%defstr mystring "test"

mov myreg, 100

; Test %push/%pop
%push scope1
    %define LOCAL_VAR 42
%pop

%push scope2
    %assign counter 5
%pop

; Test proc/endproc
proc calculate
    mov rax, 10
    add rax, 20
endproc

proc finish
    xor rax, rax
endproc

; Main code
section .text
global _start

_start:
    call calculate
    call finish
    
    ; Restore
    pop rcx
    pop rbx
    pop rax
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
