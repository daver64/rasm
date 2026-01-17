; Test %push/%pop context stack and %$ context-local labels
BITS 64

; Test basic context push/pop
%push mycontext
%define TEST_VAL 100
%pop

; Test nested contexts
%push outer
    %push inner
    %pop
%pop

; Note: %$ labels work in macro bodies, not at top level
%macro context_macro 0
    %push testctx
    mov rax, 1
    %pop
%endmacro

context_macro

ret
