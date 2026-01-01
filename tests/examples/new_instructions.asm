; Test file for newly added SSE4.1, FMA, and AVX2 instructions
global _start

section .data
align 16
data1: dd 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0
data2: dd 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0
blend_mask: dw 0x00FF, 0xFF00, 0x00FF, 0xFF00, 0x00FF, 0xFF00, 0x00FF, 0xFF00

section .text
_start:
    ; SSE4.1 new instructions
    
    ; pblendw - blend packed words
    movdqa xmm0, [rip+data1]
    movdqa xmm1, [rip+data2]
    pblendw xmm0, xmm1, 0x55
    
    ; roundss/roundsd - round scalar single/double
    movss xmm2, [rip+data1]
    roundss xmm2, xmm2, 0x00        ; round to nearest
    
    movsd xmm3, [rip+data1]
    roundsd xmm3, xmm3, 0x01        ; round down
    
    ; dpps - dot product packed single precision
    movaps xmm4, [rip+data1]
    movaps xmm5, [rip+data2]
    dpps xmm4, xmm5, 0xFF
    
    ; dppd - dot product packed double precision
    movdqa xmm6, [rip+data1]
    movdqa xmm7, [rip+data2]
    dppd xmm6, xmm7, 0xFF
    
    ; FMA3 new variants - vfmsub (multiply-subtract)
    vmovaps ymm0, [rip+data1]
    vmovaps ymm1, [rip+data2]
    vmovaps ymm2, [rip+data1]
    
    vfmsub132ps ymm0, ymm1, ymm2    ; ymm0 = ymm0 * ymm2 - ymm1
    vfmsub213ps ymm0, ymm1, ymm2    ; ymm0 = ymm1 * ymm0 - ymm2
    vfmsub231ps ymm0, ymm1, ymm2    ; ymm0 = ymm1 * ymm2 - ymm0
    
    vfmsub132pd ymm0, ymm1, ymm2
    vfmsub213pd ymm0, ymm1, ymm2
    vfmsub231pd ymm0, ymm1, ymm2
    
    ; FMA3 new variants - vfnmadd (negated multiply-add)
    vfnmadd132ps ymm0, ymm1, ymm2   ; ymm0 = -(ymm0 * ymm2) + ymm1
    vfnmadd213ps ymm0, ymm1, ymm2   ; ymm0 = -(ymm1 * ymm0) + ymm2
    vfnmadd231ps ymm0, ymm1, ymm2   ; ymm0 = -(ymm1 * ymm2) + ymm0
    
    vfnmadd132pd ymm0, ymm1, ymm2
    vfnmadd213pd ymm0, ymm1, ymm2
    vfnmadd231pd ymm0, ymm1, ymm2
    
    ; FMA3 new variants - vfnmsub (negated multiply-subtract)
    vfnmsub132ps ymm0, ymm1, ymm2   ; ymm0 = -(ymm0 * ymm2) - ymm1
    vfnmsub213ps ymm0, ymm1, ymm2   ; ymm0 = -(ymm1 * ymm0) - ymm2
    vfnmsub231ps ymm0, ymm1, ymm2   ; ymm0 = -(ymm1 * ymm2) - ymm0
    
    vfnmsub132pd ymm0, ymm1, ymm2
    vfnmsub213pd ymm0, ymm1, ymm2
    vfnmsub231pd ymm0, ymm1, ymm2
    
    ; AVX2 new instructions
    
    ; vpermq - permute qwords in YMM with immediate control
    vmovdqa ymm8, [rip+data1]
    vpermq ymm9, ymm8, 0x1B         ; reverse the qwords
    
    ; vgatherdps - gather single precision floats with dword indices
    ; vgatherdps dst, vsib, mask
    ; (Simplified test - proper VSIB addressing would be needed in real use)
    vmovaps ymm10, [rip+data1]
    vmovaps ymm11, [rip+data2]
    vgatherdps ymm10, [rax+ymm11*4], ymm12
    
    ; vpmaskmovd - masked load/store dwords
    vmovdqa ymm13, [rip+data1]
    vmovdqa ymm14, [rip+data2]
    vpmaskmovd ymm13, ymm14, [rip+data1]    ; load
    vpmaskmovd [rip+data1], ymm14, ymm13    ; store
    
    ; vpmaskmovq - masked load/store qwords
    vpmaskmovq ymm15, ymm14, [rip+data1]    ; load
    vpmaskmovq [rip+data1], ymm14, ymm15    ; store
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
