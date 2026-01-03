; Test new instructions
bits 64

section .text
global _start

_start:
    ; Double-precision shifts
    shld rax, rbx, 5
    shld rcx, rdx, cl
    shrd rsi, rdi, 3
    shrd r8, r9, cl
    
    ; Memory fences
    mfence
    lfence
    sfence
    
    ; System instructions
    ud2                     ; Comment this out to avoid trap
    
    ; Random number generation
    rdrand rax
    rdseed rbx
    
    ; Prefetch
    prefetchnta [rax]
    prefetcht0 [rbx]
    prefetcht1 [rcx]
    prefetcht2 [rdx]
    
    ; Cache control
    clflush [rsi]
    clflushopt [rdi]
    
    ; Extended control
    xgetbv
    ; xsetbv              ; Privileged
    
    ; Monitoring
    monitor
    mwait
    
    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall
