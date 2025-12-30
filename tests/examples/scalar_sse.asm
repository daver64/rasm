global _start

section .data
fval1: dd 3.14159          ; single-precision float
fval2: dd 2.71828
dval1: dq 1.41421          ; double-precision float
dval2: dq 2.23607
ival: dq 42

section .text
_start:
	; Test scalar single-precision operations
	movss xmm0, [rip+fval1]
	movss xmm1, [rip+fval2]
	addss xmm0, xmm1
	subss xmm0, xmm1
	mulss xmm0, xmm1
	divss xmm0, xmm1
	sqrtss xmm2, xmm0

	; Test scalar double-precision operations
	movsd xmm3, [rip+dval1]
	movsd xmm4, [rip+dval2]
	addsd xmm3, xmm4
	subsd xmm3, xmm4
	mulsd xmm3, xmm4
	divsd xmm3, xmm4
	sqrtsd xmm5, xmm3

	; Test comparisons
	comiss xmm0, xmm1
	comisd xmm3, xmm4
	ucomiss xmm0, xmm1
	ucomisd xmm3, xmm4

	; Test conversions
	cvtss2sd xmm6, xmm0       ; float to double
	cvtsd2ss xmm7, xmm3       ; double to float
	mov rax, [rip+ival]
	cvtsi2ss xmm8, rax        ; int to float
	cvtsi2sd xmm9, rax        ; int to double
	cvtss2si rbx, xmm0        ; float to int (round)
	cvtsd2si rcx, xmm3        ; double to int (round)
	cvttss2si rdx, xmm0       ; float to int (truncate)
	cvttsd2si rsi, xmm3       ; double to int (truncate)

	; Exit
	mov rax, 60
	xor rdi, rdi
	syscall
