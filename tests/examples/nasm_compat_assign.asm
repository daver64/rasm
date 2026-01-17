; Test %assign directive
BITS 64

; Basic assignment
%assign count 0
%assign value 100

; Use in expressions
%if value > 50
    mov rax, value
%endif

; Arithmetic with %assign
%assign a 10
%assign b 20
%assign sum a + b
%assign product a * b

%if sum == 30
    mov rbx, sum
%endif

%if product == 200
    mov rcx, product
%endif

; Counter increment pattern
%assign i 0
%if i == 0
    nop
    %assign i i + 1
%endif

%if i == 1
    nop
    %assign i i + 1
%endif

ret
