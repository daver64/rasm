; SSE2 Integer Operations Test
.text
.global _start
_start:
    ; Integer arithmetic
    paddd xmm0, xmm1
    paddq xmm2, xmm3
    psubd xmm4, xmm5
    psubq xmm6, xmm7
    
    ; Integer multiply
    pmuludq xmm0, xmm1
    pmulld xmm2, xmm3
    
    ; Logical operations
    pand xmm0, xmm1
    por xmm2, xmm3
    pxor xmm4, xmm5
    
    ; Shifts with immediate
    psllq xmm0, 4
    psrlq xmm1, 8
    psraq xmm2, 16
    
    ; Comparisons
    pcmpeqd xmm0, xmm1
    pcmpgtd xmm2, xmm3
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
