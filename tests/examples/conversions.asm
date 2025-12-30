; Test AVX conversion and horizontal operations

.text
.global _start
_start:
    ; AVX Conversions - single precision to double precision
    vcvtps2pd xmm0, xmm1         ; convert 2 singles to 2 doubles
    vcvtps2pd ymm2, xmm3         ; convert 4 singles to 4 doubles
    
    ; AVX Conversions - double precision to single precision  
    vcvtpd2ps xmm4, xmm5         ; convert 2 doubles to 2 singles
    vcvtpd2ps xmm6, ymm7         ; convert 4 doubles to 4 singles
    
    ; AVX Conversions - float to/from integer
    vcvtps2dq xmm0, xmm1         ; convert packed single to packed int32
    vcvtps2dq ymm2, ymm3         ; convert 8 singles to 8 int32
    vcvtdq2ps xmm4, xmm5         ; convert packed int32 to packed single
    vcvtdq2ps ymm6, ymm7         ; convert 8 int32 to 8 singles
    
    ; Double precision to/from integer
    vcvtpd2dq xmm0, xmm1         ; convert 2 doubles to 2 int32
    vcvtpd2dq xmm2, ymm3         ; convert 4 doubles to 4 int32
    vcvtdq2pd xmm4, xmm5         ; convert 2 int32 to 2 doubles
    vcvtdq2pd ymm6, xmm7         ; convert 4 int32 to 4 doubles
    
    ; SSE3 Horizontal operations
    haddps xmm0, xmm1            ; horizontal add packed single
    haddpd xmm2, xmm3            ; horizontal add packed double
    hsubps xmm4, xmm5            ; horizontal sub packed single
    hsubpd xmm6, xmm7            ; horizontal sub packed double
    
    ; AVX Horizontal operations (3-operand)
    vhaddps xmm0, xmm1, xmm2     ; horizontal add packed single
    vhaddps ymm3, ymm4, ymm5     ; horizontal add packed single (256-bit)
    vhaddpd xmm6, xmm7, xmm8     ; horizontal add packed double
    vhsubps xmm9, xmm10, xmm11   ; horizontal sub packed single
    vhsubpd ymm12, ymm13, ymm14  ; horizontal sub packed double (256-bit)
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
