; Comprehensive NASM compatibility test
; Tests multiple features together
BITS 64

; Setup
%assign counter 0
%assign max_count 3

; Macro with variadic parameters
%macro smart_push 1-*
    push %1
    %if %0 > 1
        push %2
    %endif
    %if %0 > 2
        push %3
    %endif
%endmacro

; Conditional code generation
%if counter < max_count
    %rep 3
        nop
    %endrep
%endif

; Test macro with rotation
%macro sum_three 3
    mov rax, %1
    %rotate 1
    add rax, %1
    %rotate 1
    add rax, %1
%endmacro

sum_three 10, 20, 30

; Test variadic macros
smart_push rax
smart_push rbx, rcx
smart_push rdx, rsi, rdi

; Increment counter
%assign counter counter + 1

%if counter == 1
    ; Code only if counter is 1
    mov r8, counter
%endif

; Nested conditionals with expressions
%assign debug 1
%if debug
    %if counter > 0
        ; Debug output simulation
        xor r9, r9
    %endif
%endif

; Final cleanup
%rep 2
    pop rax
    pop rbx
%endrep

ret
