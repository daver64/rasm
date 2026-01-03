; Test file for SSE3, SSSE3, SSE4.1, SSE4.2, and AES-NI instructions
BITS 64

section .text

    ; SSE3 Instructions
    movddup xmm0, xmm1
    movddup xmm2, [rax]
    movshdup xmm3, xmm4
    movshdup xmm5, [rbx]
    movsldup xmm6, xmm7
    movsldup xmm0, [rcx]
    addsubps xmm1, xmm2
    addsubps xmm3, [rdx]
    addsubpd xmm4, xmm5
    addsubpd xmm6, [rsi]

    ; SSSE3 Instructions
    pabsb xmm0, xmm1
    pabsb xmm2, [rax]
    pabsw xmm3, xmm4
    pabsd xmm5, xmm6
    psignb xmm0, xmm1
    psignw xmm2, xmm3
    psignd xmm4, xmm5
    pshufb xmm0, xmm1
    pshufb xmm2, [rbx]
    pmulhrsw xmm3, xmm4
    pmulhrsw xmm5, [rcx]
    palignr xmm0, xmm1, 0x08
    palignr xmm2, [rdx], 0x0F

    ; SSE4.1 Min/Max (new ones - not in MMX)
    pminsb xmm0, xmm1
    pminsb xmm2, [rax]
    pminuw xmm3, xmm4
    pminud xmm5, xmm6
    pminsd xmm7, xmm0
    pmaxsb xmm1, xmm2
    pmaxuw xmm3, xmm4
    pmaxud xmm5, xmm6
    pmaxsd xmm7, xmm0

    ; SSE4.1 Other
    pmuldq xmm0, xmm1
    pmuldq xmm2, [rbx]
    movntdqa xmm0, [rax]

    ; SSE4.1 Insert/Extract
    pinsrb xmm0, eax, 0x05
    pinsrb xmm1, [rbx], 0x0F
    pinsrd xmm2, ecx, 0x02
    pinsrq xmm3, rdx, 0x01
    pextrb eax, xmm0, 0x07
    pextrb [rax], xmm1, 0x0A
    pextrd ebx, xmm2, 0x03
    pextrq rcx, xmm3, 0x01

    ; SSE4.2 String Compare
    pcmpestri xmm0, xmm1, 0x08
    pcmpestri xmm2, [rax], 0x0C
    pcmpestrm xmm3, xmm4, 0x44
    pcmpistri xmm5, xmm6, 0x0A
    pcmpistrm xmm7, xmm0, 0x19

    ; SSE4.2 CRC32
    crc32 eax, bl
    crc32 eax, ecx
    crc32 rax, rbx
    crc32 edx, [rsi]

    ; AES-NI Instructions
    aesenc xmm0, xmm1
    aesenc xmm2, [rax]
    aesenclast xmm3, xmm4
    aesenclast xmm5, [rbx]
    aesdec xmm6, xmm7
    aesdec xmm0, [rcx]
    aesdeclast xmm1, xmm2
    aesdeclast xmm3, [rdx]
    aesimc xmm4, xmm5
    aesimc xmm6, [rsi]
    aeskeygenassist xmm0, xmm1, 0x01
    aeskeygenassist xmm2, [rdi], 0x10
