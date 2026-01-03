bits 64

; x87 FPU Test Instructions

; Data Transfer
fld st0           ; Load ST(0)
fld st1           ; Load ST(1)
fst st2           ; Store to ST(2)
fstp st3          ; Store and pop to ST(3)
fxch              ; Exchange ST(0) with ST(1)
fxch st2          ; Exchange ST(0) with ST(2)

; Arithmetic
fadd              ; Add ST(0) += ST(1)
fadd st1          ; Add ST(0) += ST(1)
fadd st3, st0     ; Add ST(3) += ST(0)
faddp st1, st0    ; Add and pop
fsub st2          ; Subtract
fsubp st1, st0    ; Subtract and pop
fmul st1          ; Multiply
fmulp st1, st0    ; Multiply and pop
fdiv st2          ; Divide
fdivp st1, st0    ; Divide and pop

; Comparison
fcom              ; Compare
fcom st1          ; Compare ST(0) with ST(1)
fcomp             ; Compare and pop
fcomp st2         ; Compare and pop
fcompp            ; Compare and pop twice
fucom             ; Unordered compare
fucom st1         ; Unordered compare
fucomp            ; Unordered compare and pop
fucomp st3        ; Unordered compare and pop
fucompp           ; Unordered compare and pop twice
fcomi st1         ; Compare and set EFLAGS
fcomip st2        ; Compare, set EFLAGS and pop
fucomi st3        ; Unordered compare and set EFLAGS
fucomip st1       ; Unordered compare, set EFLAGS and pop
ftst              ; Test ST(0) against 0.0
fxam              ; Examine ST(0)

; Transcendental
fsin              ; Sine of ST(0)
fcos              ; Cosine of ST(0)
fsincos           ; Sine and cosine
fptan             ; Partial tangent
fpatan            ; Partial arctangent
f2xm1             ; 2^x - 1
fyl2x             ; y*log2(x)
fyl2xp1           ; y*log2(x+1)

; Mathematical operations
fsqrt             ; Square root
fscale            ; Scale
fprem             ; Partial remainder
fprem1            ; Partial remainder (IEEE)
frndint           ; Round to integer
fxtract           ; Extract exponent and mantissa
fabs              ; Absolute value
fchs              ; Change sign

; Load constants
fld1              ; Load +1.0
fldl2t            ; Load log2(10)
fldl2e            ; Load log2(e)
fldpi             ; Load pi
fldlg2            ; Load log10(2)
fldln2            ; Load ln(2)
fldz              ; Load +0.0

; Control
finit             ; Initialize FPU (with WAIT)
fninit            ; Initialize FPU (no WAIT)
fclex             ; Clear exceptions (with WAIT)
fnclex            ; Clear exceptions (no WAIT)
fincstp           ; Increment stack pointer
fdecstp           ; Decrement stack pointer
ffree st0         ; Free register
ffreep st1        ; Free register and pop
fnop              ; No operation
fwait             ; Wait

; Stack management
fxch st4          ; Exchange with ST(4)
