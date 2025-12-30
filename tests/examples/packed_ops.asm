; Test packed division, sqrt, and comparison instructions

section .text
global _start

_start:
    ; SSE Packed Division
    divps xmm0, xmm1
    divps xmm2, [rsp]
    divpd xmm3, xmm4
    divpd xmm5, [rsp+16]
    
    ; SSE Packed Square Root
    sqrtps xmm0, xmm1
    sqrtps xmm2, [rsp]
    sqrtpd xmm3, xmm4
    sqrtpd xmm5, [rsp+16]
    
    ; SSE Packed Comparisons (imm8 specifies comparison predicate)
    cmpps xmm0, xmm1, 0    ; EQ
    cmpps xmm2, [rsp], 1   ; LT
    cmppd xmm3, xmm4, 2    ; LE
    cmppd xmm5, [rsp+16], 3 ; UNORD
    
    ; AVX Packed Division
    vdivps xmm0, xmm1, xmm2
    vdivps xmm3, xmm4, [rsp]
    vdivps ymm5, ymm6, ymm7
    vdivpd xmm8, xmm9, xmm10
    vdivpd ymm11, ymm12, [rsp]
    
    ; AVX Packed Square Root (2-operand form)
    vsqrtps xmm0, xmm1
    vsqrtps xmm2, [rsp]
    vsqrtps ymm3, ymm4
    vsqrtpd xmm5, xmm6
    vsqrtpd ymm7, [rsp+32]
    
    ; AVX Packed Comparisons (4-operand form with immediate)
    vcmpps xmm0, xmm1, xmm2, 0
    vcmpps xmm3, xmm4, [rsp], 1
    vcmpps ymm5, ymm6, ymm7, 2
    vcmppd xmm8, xmm9, xmm10, 3
    vcmppd ymm11, ymm12, [rsp+32], 4
    
    ; Exit
    mov rax, 60
    xor edi, edi
    syscall
