; Comprehensive test of all FMA3 variants
global _start

section .data
align 32
vec1: dd 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0
vec2: dd 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0
vec3: dd 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5

section .text
_start:
    ; Load vectors
    vmovaps ymm0, [rip+vec1]
    vmovaps ymm1, [rip+vec2]
    vmovaps ymm2, [rip+vec3]
    
    ; ===== VFMADD - Fused Multiply-Add (a*b + c) =====
    ; vfmadd132: dst = dst * src2 + src1
    vfmadd132ps ymm0, ymm1, ymm2
    vfmadd132pd ymm0, ymm1, ymm2
    vfmadd132ps xmm0, xmm1, xmm2
    vfmadd132pd xmm0, xmm1, xmm2
    
    ; vfmadd213: dst = src1 * dst + src2
    vfmadd213ps ymm0, ymm1, ymm2
    vfmadd213pd ymm0, ymm1, ymm2
    vfmadd213ps xmm0, xmm1, xmm2
    vfmadd213pd xmm0, xmm1, xmm2
    
    ; vfmadd231: dst = src1 * src2 + dst
    vfmadd231ps ymm0, ymm1, ymm2
    vfmadd231pd ymm0, ymm1, ymm2
    vfmadd231ps xmm0, xmm1, xmm2
    vfmadd231pd xmm0, xmm1, xmm2
    
    ; ===== VFMSUB - Fused Multiply-Subtract (a*b - c) =====
    ; vfmsub132: dst = dst * src2 - src1
    vfmsub132ps ymm0, ymm1, ymm2
    vfmsub132pd ymm0, ymm1, ymm2
    vfmsub132ps xmm0, xmm1, xmm2
    vfmsub132pd xmm0, xmm1, xmm2
    
    ; vfmsub213: dst = src1 * dst - src2
    vfmsub213ps ymm0, ymm1, ymm2
    vfmsub213pd ymm0, ymm1, ymm2
    vfmsub213ps xmm0, xmm1, xmm2
    vfmsub213pd xmm0, xmm1, xmm2
    
    ; vfmsub231: dst = src1 * src2 - dst
    vfmsub231ps ymm0, ymm1, ymm2
    vfmsub231pd ymm0, ymm1, ymm2
    vfmsub231ps xmm0, xmm1, xmm2
    vfmsub231pd xmm0, xmm1, xmm2
    
    ; ===== VFNMADD - Negated Fused Multiply-Add (-(a*b) + c) =====
    ; vfnmadd132: dst = -(dst * src2) + src1
    vfnmadd132ps ymm0, ymm1, ymm2
    vfnmadd132pd ymm0, ymm1, ymm2
    vfnmadd132ps xmm0, xmm1, xmm2
    vfnmadd132pd xmm0, xmm1, xmm2
    
    ; vfnmadd213: dst = -(src1 * dst) + src2
    vfnmadd213ps ymm0, ymm1, ymm2
    vfnmadd213pd ymm0, ymm1, ymm2
    vfnmadd213ps xmm0, xmm1, xmm2
    vfnmadd213pd xmm0, xmm1, xmm2
    
    ; vfnmadd231: dst = -(src1 * src2) + dst
    vfnmadd231ps ymm0, ymm1, ymm2
    vfnmadd231pd ymm0, ymm1, ymm2
    vfnmadd231ps xmm0, xmm1, xmm2
    vfnmadd231pd xmm0, xmm1, xmm2
    
    ; ===== VFNMSUB - Negated Fused Multiply-Subtract (-(a*b) - c) =====
    ; vfnmsub132: dst = -(dst * src2) - src1
    vfnmsub132ps ymm0, ymm1, ymm2
    vfnmsub132pd ymm0, ymm1, ymm2
    vfnmsub132ps xmm0, xmm1, xmm2
    vfnmsub132pd xmm0, xmm1, xmm2
    
    ; vfnmsub213: dst = -(src1 * dst) - src2
    vfnmsub213ps ymm0, ymm1, ymm2
    vfnmsub213pd ymm0, ymm1, ymm2
    vfnmsub213ps xmm0, xmm1, xmm2
    vfnmsub213pd xmm0, xmm1, xmm2
    
    ; vfnmsub231: dst = -(src1 * src2) - dst
    vfnmsub231ps ymm0, ymm1, ymm2
    vfnmsub231pd ymm0, ymm1, ymm2
    vfnmsub231ps xmm0, xmm1, xmm2
    vfnmsub231pd xmm0, xmm1, xmm2
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
