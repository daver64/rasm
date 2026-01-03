; Test file for additional SSE/SSE2 instructions
BITS 64

section .text

    ; Logical operations
    andps xmm0, xmm1
    andpd xmm2, xmm3
    andps xmm0, [rax]
    andpd xmm2, [rbx]
    andnps xmm4, xmm5
    andnpd xmm6, xmm7
    orps xmm0, xmm1
    orpd xmm2, xmm3

    ; Min/Max operations
    minps xmm0, xmm1
    minpd xmm2, xmm3
    minss xmm4, xmm5
    minsd xmm6, xmm7
    maxps xmm0, xmm1
    maxpd xmm2, xmm3
    maxss xmm4, xmm5
    maxsd xmm6, xmm7
    minps xmm0, [rax]
    maxpd xmm2, [rbx]

    ; Reciprocal operations
    rcpps xmm0, xmm1
    rcpss xmm2, xmm3
    rsqrtps xmm4, xmm5
    rsqrtss xmm6, xmm7
    rcpps xmm0, [rax]

    ; Unpack operations
    unpcklps xmm0, xmm1
    unpckhps xmm2, xmm3
    unpcklpd xmm4, xmm5
    unpckhpd xmm6, xmm7
    unpcklps xmm0, [rax]
    unpckhpd xmm6, [rbx]

    ; Shuffle operations
    shufps xmm0, xmm1, 0x1B
    shufpd xmm2, xmm3, 0x02
    shufps xmm0, [rax], 0xFF
    
    pshufd xmm0, xmm1, 0x1B
    pshufhw xmm2, xmm3, 0xE4
    pshuflw xmm4, xmm5, 0x27
    pshufd xmm0, [rax], 0x93
    
    pshufw mm0, mm1, 0x1B
    pshufw mm2, [rax], 0xE4

    ; Half/Low packed moves
    movhps xmm0, [rax]
    movhps [rax], xmm0
    movlps xmm1, [rbx]
    movlps [rbx], xmm1
    movhpd xmm2, [rcx]
    movhpd [rcx], xmm2
    movlpd xmm3, [rdx]
    movlpd [rdx], xmm3

    ; MMX conversions
    cvtpi2ps xmm0, mm1
    cvtpi2ps xmm2, [rax]
    cvtps2pi mm0, xmm1
    cvtps2pi mm2, [rbx]
    cvttps2pi mm3, xmm4
    cvttps2pi mm5, [rcx]
    
    cvtpi2pd xmm0, mm1
    cvtpi2pd xmm2, [rdx]
    cvtpd2pi mm0, xmm1
    cvtpd2pi mm2, [rsi]
    cvttpd2pi mm3, xmm4
    cvttpd2pi mm5, [rdi]

    ; Masked moves
    maskmovdqu xmm0, xmm1

    ; Non-temporal stores
    movntps [rax], xmm0
    movntpd [rbx], xmm1
    movntdq [rcx], xmm2
