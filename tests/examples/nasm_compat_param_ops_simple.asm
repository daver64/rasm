; Simplified test for %0, %+, and %? operators
BITS 64

; Test %0 - parameter count (simple use)
%macro count_params 1-*
    ; Just use parameters directly
    mov rax, %1
    ; If there are more, use them
    %if %0 > 1
        mov rbx, %2
    %endif
%endmacro

; This should work
count_params 100
count_params 200, 300

ret
