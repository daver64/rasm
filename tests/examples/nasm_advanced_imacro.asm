; Test %imacro - case-insensitive macros
BITS 64

%imacro TestMacro 1
    mov rax, %1
%endmacro

; All these should work (case-insensitive)
TestMacro 10
testmacro 20
TESTMACRO 30
tEsTmAcRo 40

ret
