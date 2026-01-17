; Test %if/%elif expression conditionals
BITS 64

%assign counter 0
%assign flag 1

; Test basic %if with numeric expression
%if counter == 0
    mov rax, 1      ; Should be included
%endif

; Test %if with arithmetic
%if 2 + 2
    mov rbx, 2      ; Should be included (non-zero)
%endif

; Test %if/%elif/%else chain
%if counter > 5
    mov rcx, 100
%elif counter == 0
    mov rcx, 200    ; Should be included
%else
    mov rcx, 300
%endif

; Test nested %if
%if flag
    %if counter == 0
        mov rdx, 999    ; Should be included
    %endif
%endif

; Test %if with expressions
%assign x 10
%assign y 5
%if x > y
    mov rsi, 42     ; Should be included
%endif

%if x & 2
    mov rdi, 1      ; Should be included (10 & 2 = 2, non-zero)
%endif

; Should produce valid 64-bit code
ret
