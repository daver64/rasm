; Test %deftok and %defstr
BITS 64

; %deftok - define as token (no quotes)
%deftok register rax
%deftok value 42

mov register, value    ; Expands to: mov rax, 42

; %defstr - define as quoted string
%defstr message Hello World
; This would be used in string contexts, but for testing we just verify it compiles

ret
