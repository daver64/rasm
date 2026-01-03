; AVX-512 Foundation Instructions Test
; Testing ZMM registers, opmask registers, and basic AVX-512 operations
BITS 64

section .text

; ===== Opmask Operations =====
; KMOV - Move opmask registers
kmovw k1, k2                ; k <- k
kmovb k3, k4                ; k <- k (byte)
kmovq k5, k6                ; k <- k (qword)
kmovd k7, k0                ; k <- k (dword)

kmovw k1, eax               ; k <- r32
kmovb k2, ecx               ; k <- r32
kmovq k3, rax               ; k <- r64
kmovd k4, edx               ; k <- r32

kmovw eax, k5               ; r32 <- k
kmovb ebx, k6               ; r32 <- k
kmovq rcx, k7               ; r64 <- k
kmovd edi, k1               ; r32 <- k

kmovw k1, [rax]             ; k <- m16
kmovb k2, [rbx]             ; k <- m8
kmovq k3, [rcx]             ; k <- m64
kmovd k4, [rdx]             ; k <- m32

kmovw [rsi], k5             ; m16 <- k
kmovb [rdi], k6             ; m8 <- k
kmovq [r8], k7              ; m64 <- k
kmovd [r9], k1              ; m32 <- k

; KAND - Bitwise AND
kandw k1, k2, k3            ; k1 = k2 & k3
kandb k4, k5, k6            ; byte version
kandq k1, k2, k3            ; qword version
kandd k7, k0, k1            ; dword version

; KOR - Bitwise OR
korw k2, k3, k4             ; k2 = k3 | k4
korb k5, k6, k7             ; byte version
korq k0, k1, k2             ; qword version
kord k3, k4, k5             ; dword version

; KXOR - Bitwise XOR
kxorw k1, k2, k3            ; k1 = k2 ^ k3
kxorb k4, k5, k6            ; byte version
kxorq k7, k0, k1            ; qword version
kxord k2, k3, k4            ; dword version

; KNOT - Bitwise NOT
knotw k1, k2                ; k1 = ~k2
knotb k3, k4                ; byte version
knotq k5, k6                ; qword version
knotd k7, k0                ; dword version

; Test with high opmask registers
kandw k7, k6, k5
korq k4, k3, k2
kxord k1, k0, k7

; ===== ZMM Arithmetic Operations (512-bit) =====
; VADDPS/VADDPD - Packed floating-point addition (use .512 suffix for ZMM)
vaddps.512 zmm0, zmm1, zmm2         ; zmm0 = zmm1 + zmm2 (packed single)
vaddpd.512 zmm3, zmm4, zmm5         ; zmm3 = zmm4 + zmm5 (packed double)
vaddps.512 zmm6, zmm7, [rax]        ; zmm6 = zmm7 + [rax] (memory operand)
vaddpd.512 zmm8, zmm9, [rbx]        ; zmm8 = zmm9 + [rbx]

; VSUBPS/VSUBPD - Packed floating-point subtraction
vsubps.512 zmm10, zmm11, zmm12      ; zmm10 = zmm11 - zmm12
vsubpd.512 zmm13, zmm14, zmm15      ; zmm13 = zmm14 - zmm15
vsubps.512 zmm16, zmm17, [rcx]      ; with memory operand
vsubpd.512 zmm18, zmm19, [rdx]

; VMULPS/VMULPD - Packed floating-point multiplication
vmulps.512 zmm20, zmm21, zmm22      ; zmm20 = zmm21 * zmm22
vmulpd.512 zmm23, zmm24, zmm25      ; zmm23 = zmm24 * zmm25
vmulps.512 zmm26, zmm27, [rsi]
vmulpd.512 zmm28, zmm29, [rdi]

; VDIVPS/VDIVPD - Packed floating-point division
vdivps.512 zmm30, zmm31, zmm0       ; zmm30 = zmm31 / zmm0
vdivpd.512 zmm1, zmm2, zmm3         ; zmm1 = zmm2 / zmm3
vdivps.512 zmm4, zmm5, [r8]
vdivpd.512 zmm6, zmm7, [r9]

; ===== ZMM Data Movement (512-bit) =====
; VMOVAPS/VMOVAPD - Aligned packed moves
vmovaps.512 zmm8, zmm9              ; zmm8 = zmm9 (aligned single)
vmovapd.512 zmm10, zmm11            ; zmm10 = zmm11 (aligned double)
vmovaps.512 zmm12, [r10]            ; load from aligned memory
vmovapd.512 zmm13, [r11]
vmovaps.512 [r12], zmm14            ; store to aligned memory
vmovapd.512 [r13], zmm15

; VMOVUPS/VMOVUPD - Unaligned packed moves
vmovups.512 zmm16, zmm17            ; zmm16 = zmm17 (unaligned single)
vmovupd.512 zmm18, zmm19            ; zmm18 = zmm19 (unaligned double)
vmovups.512 zmm20, [r14]            ; load from unaligned memory
vmovupd.512 zmm21, [r15]
vmovups.512 [rax], zmm22            ; store to unaligned memory
vmovupd.512 [rbx], zmm23

; ===== Integer Data Movement (512-bit) =====
; VMOVDQA32/VMOVDQA64 - Aligned integer moves
vmovdqa32 zmm24, zmm25          ; aligned 32-bit integer move
vmovdqa64 zmm26, zmm27          ; aligned 64-bit integer move
vmovdqa32 zmm28, [rcx]          ; load from memory
vmovdqa64 zmm29, [rdx]
vmovdqa32 [rsi], zmm30          ; store to memory
vmovdqa64 [rdi], zmm31

; VMOVDQU32/VMOVDQU64 - Unaligned integer moves
vmovdqu32 zmm0, zmm1            ; unaligned 32-bit integer move
vmovdqu64 zmm2, zmm3            ; unaligned 64-bit integer move
vmovdqu32 zmm4, [r8]            ; load from memory
vmovdqu64 zmm5, [r9]
vmovdqu32 [r10], zmm6           ; store to memory
vmovdqu64 [r11], zmm7

; ===== Broadcast Operations (512-bit) =====
; VBROADCASTSS/VBROADCASTSD - Broadcast scalar to all elements
vbroadcastss zmm8, xmm9         ; broadcast single from xmm
vbroadcastsd zmm10, xmm11       ; broadcast double from xmm
vbroadcastss zmm12, [r12]       ; broadcast from memory
vbroadcastsd zmm13, [r13]

; VBROADCASTI32X4/VBROADCASTI64X4 - Broadcast 128/256-bit integer
vbroadcasti32x4 zmm14, [r14]    ; broadcast 128-bit (4x int32)
vbroadcasti64x4 zmm15, [r15]    ; broadcast 256-bit (4x int64)

; VPBROADCASTD/VPBROADCASTQ - Broadcast integer scalar
vpbroadcastd zmm16, xmm17       ; broadcast dword
vpbroadcastq zmm18, xmm19       ; broadcast qword
vpbroadcastd zmm20, [rax]       ; broadcast from memory
vpbroadcastq zmm21, [rbx]

; ===== High Register Tests =====
; Test with high ZMM registers (16-31)
vaddps.512 zmm16, zmm17, zmm18
vsubpd.512 zmm24, zmm25, zmm26
vmulps.512 zmm28, zmm29, zmm30
vdivpd.512 zmm31, zmm0, zmm1
vmovaps.512 zmm20, zmm21
vmovdqu64 zmm27, [rcx]
vbroadcastss zmm22, xmm23
