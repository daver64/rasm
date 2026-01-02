; Comprehensive test for all newly added 64-bit instructions
; This file tests encoding correctness without floating-point literals
global _start

section .text
_start:
    ; === Rotate Instructions ===
    rol rax, 1          ; Rotate left by 1
    rol rbx, 5          ; Rotate left by immediate
    mov rcx, 3
    rol rdx, rcx        ; Rotate left by CL (via RCX)
    
    ror rsi, 1          ; Rotate right by 1
    ror rdi, 7          ; Rotate right by immediate
    ror r8, rcx         ; Rotate right by CL
    
    rcl r9, 1           ; Rotate through carry left
    rcl r10, 4
    rcl r11, rcx
    
    rcr r12, 1          ; Rotate through carry right
    rcr r13, 2
    rcr r14, rcx
    
    ; === Stack Frame ===
    enter 32, 0         ; Create stack frame (32 bytes, nesting 0)
    leave               ; Destroy stack frame
    
    ; === Exchange ===
    xchg rax, rbx       ; Exchange registers (short form)
    xchg rcx, rdx       ; Exchange registers (general form)
    xchg [rsp], rax     ; Exchange memory with register
    xchg rsi, [rsp+8]   ; Exchange register with memory
    
    ; === Atomic Operations ===
    xadd rax, rbx       ; Exchange and add
    xadd [rsp], rcx     ; Exchange and add (memory)
    
    cmpxchg rdx, rsi    ; Compare and exchange
    cmpxchg [rsp], rdi  ; Compare and exchange (memory)
    
    cmpxchg8b [rsp]     ; Compare and exchange 8 bytes
    cmpxchg16b [rsp]    ; Compare and exchange 16 bytes (REX.W)
    
    ; === Carry Arithmetic ===
    adc rax, rbx        ; Add with carry (reg, reg)
    adc rax, 100        ; Add with carry (reg, imm)
    adc rcx, [rsp]      ; Add with carry (reg, mem)
    adc [rsp], rdx      ; Add with carry (mem, reg)
    
    sbb rsi, rdi        ; Subtract with borrow (reg, reg)
    sbb rsi, 50         ; Subtract with borrow (reg, imm)
    sbb r8, [rsp+16]    ; Subtract with borrow (reg, mem)
    sbb [rsp+8], r9     ; Subtract with borrow (mem, reg)
    
    ; === Flag Manipulation ===
    clc                 ; Clear carry flag
    stc                 ; Set carry flag
    cmc                 ; Complement carry flag
    cld                 ; Clear direction flag
    std                 ; Set direction flag
    lahf                ; Load flags into AH
    sahf                ; Store AH into flags
    pushf               ; Push FLAGS
    popf                ; Pop FLAGS
    pushfq              ; Push RFLAGS (64-bit)
    popfq               ; Pop RFLAGS (64-bit)
    
    ; === Conversion Instructions ===
    cbw                 ; Convert byte to word (AL -> AX)
    cwde                ; Convert word to doubleword (AX -> EAX)
    cdqe                ; Convert doubleword to quadword (EAX -> RAX)
    cdq                 ; Convert doubleword to quadword (EDX:EAX)
    
    ; === System/Miscellaneous ===
    nop                 ; No operation
    pause               ; Spin loop hint
    cpuid               ; CPU identification
    rdtsc               ; Read time-stamp counter
    rdtscp              ; Read time-stamp counter and processor ID
    
    ; Software interrupts
    ; int 0x80          ; Linux 32-bit syscall (commented - would cause error)
    ; int 3             ; Breakpoint (commented - would trap)
    
    ; Halt (commented out to allow normal exit)
    ; hlt               ; Halt processor
    
    ; === Exit ===
    mov rax, 60         ; sys_exit
    xor rdi, rdi        ; status = 0
    syscall

section .data
    ; No data needed for this test
