; Test file for all newly implemented x86-64 instructions
global _start

section .text
_start:
    ; Rotate instructions
    rol rax, 1
    mov rcx, 3
    rol rax, rcx
    rol rax, 5
    ror rbx, 1
    ror rbx, rcx
    ror rbx, 3
    rcl rdx, 1
    rcl rdx, rcx
    rcl rdx, 7
    rcr rsi, 1
    rcr rsi, rcx
    rcr rsi, 2
    
    ; Stack frame instructions
    enter 16, 0
    leave
    
    ; Exchange instructions
    xchg rax, rbx
    xchg rcx, rax
    xchg rax, rdx
    xchg rsi, rdi
    xchg [rsp], rax
    xchg rbx, [rsp+8]
    
    ; Atomic operations
    xadd [rsp], rax
    xadd rbx, rcx
    cmpxchg [rsp], rax
    cmpxchg rbx, rcx
    cmpxchg8b [rsp]
    cmpxchg16b [rsp]
    
    ; Carry arithmetic
    adc rax, rbx
    adc rax, 42
    adc rcx, [rsp]
    adc [rsp], rdx
    sbb rsi, rdi
    sbb rsi, 100
    sbb r8, [rsp+16]
    sbb [rsp+8], r9
    
    ; Flag manipulation instructions
    clc
    stc
    cmc
    cld
    std
    lahf
    sahf
    pushf
    popf
    pushfq
    popfq
    
    ; Conversion instructions
    cbw
    cwde
    cdqe
    cdq
    
    ; Miscellaneous instructions
    hlt
    pause
    cpuid
    rdtsc
    rdtscp
    int 0x80
    int 3
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
