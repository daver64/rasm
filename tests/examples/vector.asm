global start
section .text
start:
    vmovups ymm0, [rip+vec]
    vmovaps ymm1, ymm0
    vaddps ymm2, ymm1, ymm0
    vxorps ymm3, ymm2, ymm0
    vptest ymm4, ymm3
    vroundps xmm5, [rip+vec], 1
    vpermilps ymm6, ymm0, 0xb1
    mov rdi, 0
    mov rax, 60
    syscall
section .data
vec: dd 1,1,1,1,1,1,1,1
