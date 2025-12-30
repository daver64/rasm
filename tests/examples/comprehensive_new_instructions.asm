; Comprehensive test of SSE2 integer, BMI/BMI2, bit manipulation, and string operations
.text
.global _start

_start:
    ; ===== SSE2 Integer Operations =====
    ; Integer arithmetic
    paddd xmm0, xmm1         ; Add packed dwords
    paddq xmm2, xmm3         ; Add packed qwords
    psubd xmm4, xmm5         ; Subtract packed dwords
    psubq xmm6, xmm7         ; Subtract packed qwords
    pmuludq xmm8, xmm9       ; Multiply unsigned dwords
    pmulld xmm10, xmm11      ; Multiply packed dwords
    
    ; Logical operations
    pand xmm0, xmm1          ; Bitwise AND
    por xmm2, xmm3           ; Bitwise OR
    pxor xmm4, xmm5          ; Bitwise XOR
    
    ; Shift operations
    psllq xmm0, 8            ; Shift left logical
    psrlq xmm1, 16           ; Shift right logical
    psraq xmm2, 4            ; Shift right arithmetic
    
    ; Comparisons
    pcmpeqd xmm0, xmm1       ; Compare equal
    pcmpgtd xmm2, xmm3       ; Compare greater than
    
    ; ===== AVX Integer Operations =====
    vpaddd xmm0, xmm1, xmm2  ; 3-operand add
    vpand ymm3, ymm4, ymm5   ; 256-bit AND
    vpxor xmm6, xmm7, xmm8   ; 3-operand XOR
    
    ; ===== BMI/BMI2 Instructions =====
    ; Bit counting
    lzcnt rax, rbx           ; Leading zero count
    tzcnt rcx, rdx           ; Trailing zero count
    popcnt rsi, rdi          ; Population count
    
    ; Bit field operations
    andn r8, r9, r10         ; Logical AND NOT
    blsi r11, r12            ; Extract lowest set bit
    blsmsk r13, r14          ; Get mask up to lowest set
    blsr r15, rax            ; Reset lowest set bit
    
    ; Parallel bit operations
    pdep rbx, rcx, rdx       ; Parallel deposit
    pext rsi, rdi, r8        ; Parallel extract
    
    ; Variable shifts and rotates
    bextr r9, r10, r11       ; Bit field extract
    bzhi r12, r13, r14       ; Zero high bits
    sarx rax, rbx, rcx       ; Shift arithmetic right
    shlx rdx, rsi, rdi       ; Shift left
    shrx r8, r9, r10         ; Shift right
    rorx r11, r12, 15        ; Rotate right with immediate
    
    ; ===== Bit Manipulation =====
    ; Bit scan
    bsf rax, rbx             ; Scan forward
    bsr rcx, rdx             ; Scan reverse
    
    ; Bit test/modify with register
    bt rsi, rdi              ; Bit test
    btc r8, r9               ; Bit test and complement
    btr r10, r11             ; Bit test and reset
    bts r12, r13             ; Bit test and set
    
    ; Bit test/modify with immediate
    bt rax, 7                ; Test bit 7
    btc rbx, 15              ; Complement bit 15
    btr rcx, 31              ; Reset bit 31
    bts rdx, 63              ; Set bit 63
    
    ; Byte swap
    bswap rax                ; Swap bytes
    bswap r15                ; Works with extended regs
    
    ; ===== String Operations =====
    ; Move string
    movsb                    ; Move byte
    movsw                    ; Move word
    movsq                    ; Move qword
    
    ; Store string
    stosb                    ; Store byte
    stosw                    ; Store word
    stosd                    ; Store dword
    stosq                    ; Store qword
    
    ; Load string
    lodsb                    ; Load byte
    lodsw                    ; Load word
    lodsd                    ; Load dword
    lodsq                    ; Load qword
    
    ; Scan string
    scasb                    ; Scan byte
    scasw                    ; Scan word
    scasd                    ; Scan dword
    scasq                    ; Scan qword
    
    ; Compare string
    cmpsb                    ; Compare byte
    cmpsw                    ; Compare word
    cmpsq                    ; Compare qword
    
    ; Exit successfully
    mov rax, 60
    xor rdi, rdi
    syscall
