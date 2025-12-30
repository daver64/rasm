; Comprehensive test of comparison predicates
; Predicates: 0=EQ, 1=LT, 2=LE, 3=UNORD, 4=NEQ, 5=NLT, 6=NLE, 7=ORD

section .text
global _start

_start:
    ; Test all comparison predicates for SSE
    cmpps xmm0, xmm1, 0    ; EQ - equal
    cmpps xmm0, xmm1, 1    ; LT - less than
    cmpps xmm0, xmm1, 2    ; LE - less or equal
    cmpps xmm0, xmm1, 3    ; UNORD - unordered
    cmpps xmm0, xmm1, 4    ; NEQ - not equal
    cmpps xmm0, xmm1, 5    ; NLT - not less than
    cmpps xmm0, xmm1, 6    ; NLE - not less or equal
    cmpps xmm0, xmm1, 7    ; ORD - ordered
    
    ; Test division and sqrt combinations
    divps xmm2, xmm3
    sqrtps xmm2, xmm2
    divpd xmm4, xmm5
    sqrtpd xmm4, xmm4
    
    ; AVX versions
    vcmpps ymm0, ymm1, ymm2, 0
    vdivps ymm3, ymm4, ymm5
    vsqrtps ymm3, ymm3
    
    ; Exit
    mov rax, 60
    xor edi, edi
    syscall
