; Test file for advanced SSE4.1, FMA3, and AVX2 instructions

section .text

global _start
_start:
    ; SSE4.1 blend operations
    blendps xmm0, xmm1, 0x0F      ; Blend with immediate mask
    blendps xmm2, [rax], 0x33     ; Blend from memory
    blendpd xmm3, xmm4, 0x03      ; Blend packed doubles
    blendpd xmm5, [rbx], 0x01     ; Blend doubles from memory

    ; AVX blend operations (4-operand)
    vblendps xmm0, xmm1, xmm2, 0x0F    ; AVX 128-bit blend
    vblendps ymm0, ymm1, ymm2, 0x33    ; AVX 256-bit blend
    vblendps xmm3, xmm4, [rax], 0x55   ; AVX blend from memory
    vblendpd xmm5, xmm6, xmm7, 0x03    ; AVX blend packed doubles
    vblendpd ymm3, ymm4, ymm5, 0x0F    ; AVX 256-bit blend doubles

    ; SSE4.1 insertps - insert single precision float
    insertps xmm0, xmm1, 0x10     ; Insert with immediate control
    insertps xmm2, [rax], 0x20    ; Insert from memory
    insertps xmm3, xmm4, 0x30     ; Insert with zeroing

    ; SSE4.1 extractps - extract single precision float
    extractps eax, xmm0, 0        ; Extract to register
    extractps ebx, xmm1, 1        ; Extract element 1
    extractps [rax], xmm2, 2      ; Extract to memory
    extractps edx, xmm3, 3        ; Extract element 3

    ; FMA3 instructions - Fused Multiply-Add
    ; vfmadd132ps: dest = dest * src2 + src1
    vfmadd132ps xmm0, xmm1, xmm2
    vfmadd132ps ymm0, ymm1, ymm2
    vfmadd132ps xmm3, xmm4, [rax]
    vfmadd132pd xmm5, xmm6, xmm7       ; Double precision
    vfmadd132pd ymm3, ymm4, ymm5

    ; vfmadd213ps: dest = src1 * dest + src2
    vfmadd213ps xmm0, xmm1, xmm2
    vfmadd213ps ymm0, ymm1, ymm2
    vfmadd213pd xmm3, xmm4, xmm5

    ; vfmadd231ps: dest = src1 * src2 + dest
    vfmadd231ps xmm0, xmm1, xmm2
    vfmadd231ps ymm0, ymm1, ymm2
    vfmadd231pd xmm3, xmm4, xmm5

    ; AVX2 vperm2i128 - permute 128-bit lanes
    vperm2i128 ymm0, ymm1, ymm2, 0x01  ; Swap low/high lanes
    vperm2i128 ymm3, ymm4, ymm5, 0x20  ; Zero high lane
    vperm2i128 ymm6, ymm7, [rax], 0x31 ; Permute with memory

    ; AVX2 vpermd - permute dwords
    vpermd ymm0, ymm1, ymm2            ; Permute using ymm1 as control
    vpermd ymm3, ymm4, [rax]           ; Permute from memory

    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall

section .data
    test_data:
        dd 1.0, 2.0, 3.0, 4.0
        dd 5.0, 6.0, 7.0, 8.0
