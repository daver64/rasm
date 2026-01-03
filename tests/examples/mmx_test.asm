bits 64

; MMX Test Instructions

; Data transfer
movd mm0, eax
movd eax, mm0
movq mm1, mm2
movq mm3, [rax]
movq [rbx], mm4

; Packed arithmetic
paddb mm0, mm1
paddw mm2, mm3
paddd mm4, mm5
paddsb mm6, mm7
paddsw mm0, mm1
paddusb mm2, mm3
paddusw mm4, mm5

psubb mm0, mm1
psubw mm2, mm3
psubd mm4, mm5
psubsb mm6, mm7
psubsw mm0, mm1
psubusb mm2, mm3
psubusw mm4, mm5

pmullw mm0, mm1
pmulhw mm2, mm3
pmaddwd mm4, mm5

; Logical operations
pand mm0, mm1
pandn mm2, mm3
por mm4, mm5
pxor mm6, mm7

; Comparisons
pcmpeqb mm0, mm1
pcmpeqw mm2, mm3
pcmpeqd mm4, mm5
pcmpgtb mm6, mm7
pcmpgtw mm0, mm1
pcmpgtd mm2, mm3

; Packing
packsswb mm0, mm1
packssdw mm2, mm3
packuswb mm4, mm5

; Unpacking
punpcklbw mm0, mm1
punpcklwd mm2, mm3
punpckldq mm4, mm5
punpckhbw mm6, mm7
punpckhwd mm0, mm1
punpckhdq mm2, mm3

; Shifts
psllw mm0, mm1
psllw mm2, 4
pslld mm3, mm4
pslld mm5, 8
psllq mm6, mm7
psllq mm0, 16

psrlw mm1, mm2
psrlw mm3, 4
psrld mm4, mm5
psrld mm6, 8
psrlq mm7, mm0
psrlq mm1, 16

psraw mm2, mm3
psraw mm4, 4
psrad mm5, mm6
psrad mm7, 8

; SSE extended MMX
pmulhuw mm0, mm1
pavgb mm2, mm3
pavgw mm4, mm5
pmaxsw mm6, mm7
pmaxub mm0, mm1
pminsw mm2, mm3
pminub mm4, mm5
pmovmskb eax, mm6
psadbw mm7, mm0
pextrw eax, mm1, 2
pinsrw mm2, eax, 3
maskmovq mm3, mm4
movntq [rcx], mm5

; Clean up
emms
