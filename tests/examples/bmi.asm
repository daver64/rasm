; BMI/BMI2 Instructions Test
.text
.global _start
_start:
    ; Count instructions
    lzcnt rax, rbx
    tzcnt rcx, rdx
    popcnt rsi, rdi
    
    ; 3-operand BMI/BMI2
    andn r8, r9, r10
    pdep r11, r12, r13
    pext r14, r15, rax
    
    ; Bit field extraction
    blsi rbx, rcx
    blsmsk rdx, rsi
    blsr rdi, r8
    
    ; BMI2 shift/rotate
    bextr r9, r10, r11
    bzhi r12, r13, r14
    sarx rax, rbx, rcx
    shlx rdx, rsi, rdi
    shrx r8, r9, r10
    rorx r11, r12, 7
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
