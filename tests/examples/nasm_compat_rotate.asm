; Test %rotate directive
BITS 64

%macro rotate_test 3
    ; Initially: %1=first, %2=second, %3=third
    mov rax, %1
    %rotate 1
    ; Now: %1=second, %2=third, %3=first
    mov rbx, %1
    %rotate 1
    ; Now: %1=third, %2=first, %3=second
    mov rcx, %1
%endmacro

; Test rotation
rotate_test 10, 20, 30
; Should generate:
;   mov rax, 10
;   mov rbx, 20
;   mov rcx, 30

ret
