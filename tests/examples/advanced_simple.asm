; Minimal test for advanced instructions
section .text

global _start
_start:
    ; SSE4.1 blend
    blendps xmm0, xmm1, 0x0F
    
    ; AVX blend
    vblendps xmm2, xmm3, xmm4, 0x55
    
    ; FMA3
    vfmadd132ps xmm0, xmm1, xmm2
    
    ; AVX2
    vperm2i128 ymm0, ymm1, ymm2, 0x01
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
