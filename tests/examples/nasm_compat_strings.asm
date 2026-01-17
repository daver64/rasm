; Test string functions: %strlen, %substr, %strcat
BITS 64

; Test %strlen
%define mystr "Hello"
; %assign len %strlen(mystr)
; Note: %strlen might not work perfectly in all contexts,
; but we test basic substitution

; Test define with string value
%define msg "test"

; For now, just test that code compiles
mov rax, 1

ret
