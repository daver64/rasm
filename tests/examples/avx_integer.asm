; AVX Integer Operations Test
.text
.global _start
_start:
    ; AVX integer arithmetic (3-operand form)
    vpaddd xmm0, xmm1, xmm2
    vpaddq xmm3, xmm4, xmm5
    vpsubd xmm6, xmm7, xmm8
    vpsubq xmm9, xmm10, xmm11
    
    ; AVX integer multiply
    vpmuludq xmm0, xmm1, xmm2
    vpmulld xmm3, xmm4, xmm5
    
    ; AVX logical operations
    vpand xmm0, xmm1, xmm2
    vpor xmm3, xmm4, xmm5
    vpxor xmm6, xmm7, xmm8
    
    ; 256-bit versions
    vpaddd ymm0, ymm1, ymm2
    vpand ymm3, ymm4, ymm5
    vpxor ymm6, ymm7, ymm8
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
