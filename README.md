# RASM - x86/x64 Assembler

A from-scratch x86/x86-64 assembler written in C17 that produces relocatable object files. Supports 16-bit, 32-bit, and 64-bit x86 code with comprehensive SIMD instruction coverage from MMX through AVX-512.

## Quick Start

```bash
# Compile
make

# Assemble to object file (auto-detects format from extension)
./rasm input.asm -o output.o      # ELF64
./rasm input.asm -o output.obj    # PE64

# Specify architecture and format
./rasm input.asm -m32 -f elf32 -o output.o
./rasm input.asm -m16 -f bin -o boot.bin
```

## Features

### Multi-Architecture Support
- **x86-64 (64-bit)**: Full x86-64 with REX prefixes (`-m64`, default)
- **x86 (32-bit)**: i386-compatible 32-bit mode (`-m32`)
- **x86 (16-bit)**: 8086/286-compatible 16-bit mode (`-m16`)
- Automatic operand-size prefix handling per architecture
- Register validation (rejects invalid registers per mode)

### Output Formats
- **ELF64/ELF32**: Linux/Unix object files (`.o`)
- **PE64/PE32**: Windows object files (`.obj`)
- **BIN**: Flat binary (raw machine code)
- **COM**: DOS COM format (16-bit, ORG 0x100)
- Auto-detection from file extension or explicit with `-f`

### Assembly Features
- **Symbol Management**: `global`, `extern` declarations
- **Sections**: `.text`, `.data`, `.bss`
- **Data**: `db`/`dw`/`dd`/`dq`, `resb`/`resw`/`resd`/`resq`
- **Alignment**: `align N`
- **Repetition**: `times count <instruction>`
- **Local Labels**: `.label` (scoped to preceding global)
- **Expressions**: Full arithmetic/bitwise with `$` (current pos), `$$` (section start)
- **Macros**: NASM-compatible with parameters, local labels, defines, conditionals, includes
- **Position Symbols**: `$`, `$$` for calculating offsets and sizes

### Addressing Modes
- Register: `mov rax, rbx`
- Immediate: `mov rax, 42`
- RIP-relative: `mov rax, [rip+label]`
- SIB: `[base + index*scale + disp]`
- Absolute: `[0x1234]`

## Instruction Set Support

### General Purpose

#### Data Movement
`mov`, `movzx`, `movsx`, `movsxd`, `movbe`, `lea`, `push`, `pop`, `xchg`, `xlat`/`xlatb`

#### Arithmetic & Logic
- **Arithmetic**: `add`, `sub`, `cmp`, `inc`, `dec`, `neg`, `mul`, `imul`, `div`, `idiv`, `adc`, `sbb`, `cqo`
- **BCD**: `aaa`, `aad`, `aam`, `aas`, `daa`, `das` (16/32-bit only)
- **Logical**: `and`, `or`, `xor`, `not`, `test`

#### Bit Manipulation
- **Shifts**: `shl`/`sal`, `shr`, `sar`, `shld`, `shrd`
- **Rotates**: `rol`, `ror`, `rcl`, `rcr`

#### Control Flow
- **Unconditional**: `jmp`, `call`, `ret`, `retf`
- **Conditional Jumps**: `je`/`jz`, `jne`/`jnz`, `ja`, `jae`, `jb`, `jbe`, `jg`, `jge`, `jl`, `jle`, `jo`, `jno`, `js`, `jns`, `jp`/`jpe`, `jnp`/`jpo`
- **Count Jumps**: `jcxz`, `jecxz`, `jrcxz`
- **Loop**: `loop`, `loope`/`loopz`, `loopne`/`loopnz`
- **Conditional Moves**: `cmove`, `cmovne`, `cmova`, `cmovae`, `cmovb`, `cmovbe`, `cmovg`, `cmovge`, `cmovl`, `cmovle`, `cmovo`, `cmovno`, `cmovs`, `cmovns`, `cmovp`, `cmovnp`
- **Conditional Sets**: `sete`, `setne`, `seta`, `setae`, `setb`, `setbe`, `setg`, `setge`, `setl`, `setle`, `seto`, `setno`, `sets`, `setns`, `setp`, `setnp`

#### Stack & Flags
- **Stack Frame**: `enter`, `leave`
- **Flags**: `clc`, `stc`, `cmc`, `cld`, `std`, `lahf`, `sahf`, `pushf`, `popf`, `pushfq`, `popfq`
- **Conversions**: `cbw`, `cwde`, `cdqe`, `cdq`

#### I/O & System
- **I/O**: `in`, `out`, `insb`/`insw`/`insd`, `outsb`/`outsw`/`outsd`
- **System Calls**: `syscall`, `sysenter`, `sysexit`, `sysret`, `int`, `iret`/`iretd`/`iretq`, `into` (16/32-bit)
- **Control**: `hlt`, `nop`, `pause`, `ud2`

#### CPU Features
- **Identification**: `cpuid`, `rdtsc`, `rdtscp`
- **Random**: `rdrand`, `rdseed`
- **Memory Fences**: `mfence`, `lfence`, `sfence`
- **Cache Control**: `clflush`, `clflushopt`, `prefetchnta`, `prefetcht0`/`t1`/`t2`
- **Monitoring**: `monitor`, `mwait`
- **Extended State**: `xsave`, `xrstor`, `xsaveopt`, `xsavec`, `xsaves`, `xrstors` (and 64-bit variants)
- **XSAVE Control**: `xgetbv`, `xsetbv`

#### Atomic Operations
`xadd`, `cmpxchg`, `cmpxchg8b`, `cmpxchg16b`

#### Segment Registers
- **Registers**: `es`, `cs`, `ss`, `ds`, `fs`, `gs`
- **Segment Loads**: `lds`, `les`, `lfs`, `lgs`, `lss` (16/32-bit only)

#### Protected Mode (OS Development)
- **Descriptor Tables**: `lgdt`, `lidt`, `sgdt`, `sidt`
- **Task/LDT**: `ltr`, `str`, `lldt`, `sldt`
- **Segment Inspection**: `lar`, `lsl`, `verr`, `verw`
- **Control Registers**: `mov cr0-cr4/cr8, reg` (read/write)
- **Debug Registers**: `mov dr0-dr7, reg` (read/write)
- **Interrupts**: `cli`, `sti`
- **Task Management**: `clts`, `lmsw`, `smsw`
- **TLB/Cache**: `invlpg`, `invd`, `wbinvd`

#### Legacy Instructions
`bound`, `arpl`, `salc` (16/32-bit only)

### x87 Floating-Point Unit

#### Data Transfer
`fld`, `fst`, `fstp`, `fild`, `fist`, `fistp`, `fbld`, `fbstp`, `fxch`

#### Arithmetic
- **Operations**: `fadd`, `faddp`, `fiadd`, `fsub`, `fsubp`, `fisub`, `fsubr`, `fsubrp`, `fisubr`
- **Multiply/Divide**: `fmul`, `fmulp`, `fimul`, `fdiv`, `fdivp`, `fidiv`, `fdivr`, `fdivrp`, `fidivr`

#### Comparison
`fcom`, `fcomp`, `fcompp`, `fucom`, `fucomp`, `fucompp`, `ficom`, `ficomp`, `fcomi`, `fcomip`, `fucomi`, `fucomip`, `ftst`, `fxam`

#### Transcendental
`fsin`, `fcos`, `fsincos`, `fptan`, `fpatan`, `f2xm1`, `fyl2x`, `fyl2xp1`

#### Mathematical
`fsqrt`, `fscale`, `fprem`, `fprem1`, `frndint`, `fxtract`, `fabs`, `fchs`

#### Constants
`fld1`, `fldl2t`, `fldl2e`, `fldpi`, `fldlg2`, `fldln2`, `fldz`

#### Control
`finit`, `fninit`, `fclex`, `fnclex`, `fstcw`, `fnstcw`, `fldcw`, `fstenv`, `fnstenv`, `fldenv`, `fsave`, `fnsave`, `frstor`, `fstsw`, `fnstsw`, `fincstp`, `fdecstp`, `ffree`, `ffreep`, `fnop`, `fwait`

### MMX (64-bit SIMD)

**Registers**: `mm0`-`mm7`

#### Data Transfer
`movd`, `movq`, `movntq`

#### Packed Arithmetic
- **Addition**: `paddb`, `paddw`, `paddd`, `paddsb`, `paddsw`, `paddusb`, `paddusw`
- **Subtraction**: `psubb`, `psubw`, `psubd`, `psubsb`, `psubsw`, `psubusb`, `psubusw`
- **Multiplication**: `pmullw`, `pmulhw`, `pmulhuw`, `pmaddwd`

#### Logical
`pand`, `pandn`, `por`, `pxor`

#### Comparison
`pcmpeqb`, `pcmpeqw`, `pcmpeqd`, `pcmpgtb`, `pcmpgtw`, `pcmpgtd`

#### Packing/Unpacking
`packsswb`, `packssdw`, `packuswb`, `punpcklbw`, `punpcklwd`, `punpckldq`, `punpckhbw`, `punpckhwd`, `punpckhdq`

#### Shifts
`psllw`, `pslld`, `psllq`, `psrlw`, `psrld`, `psrlq`, `psraw`, `psrad`

#### SSE Extensions to MMX
`pavgb`, `pavgw`, `pmaxsw`, `pmaxub`, `pminsw`, `pminub`, `pmovmskb`, `psadbw`, `pextrw`, `pinsrw`, `maskmovq`

#### Control
`emms` (clear MMX state)

### SSE/SSE2 (128-bit)

**Registers**: `xmm0`-`xmm15` (64-bit mode), `xmm0`-`xmm7` (32-bit mode)

#### Packed Floating-Point Operations
- **Arithmetic**: `addps`, `addpd`, `subps`, `subpd`, `mulps`, `mulpd`, `divps`, `divpd`
- **Math**: `sqrtps`, `sqrtpd`, `rcpps`, `rcpss`, `rsqrtps`, `rsqrtss`
- **Logical**: `andps`, `andpd`, `andnps`, `andnpd`, `orps`, `orpd`, `xorps`, `xorpd`
- **Min/Max**: `minps`, `minpd`, `maxps`, `maxpd`
- **Comparison**: `cmpps`, `cmppd`

#### Scalar Floating-Point
- **Arithmetic**: `addss`, `addsd`, `subss`, `subsd`, `mulss`, `mulsd`, `divss`, `divsd`
- **Math**: `sqrtss`, `sqrtsd`, `minss`, `minsd`, `maxss`, `maxsd`
- **Data Movement**: `movss`, `movsd`
- **Comparison**: `comiss`, `comisd`, `ucomiss`, `ucomisd`

#### Conversions
- **Float ↔ Double**: `cvtss2sd`, `cvtsd2ss`
- **Integer ↔ Float**: `cvtsi2ss`, `cvtsi2sd`, `cvtss2si`, `cvtsd2si`, `cvttss2si`, `cvttsd2si`
- **MMX Conversions**: `cvtpi2ps`, `cvtps2pi`, `cvttps2pi`, `cvtpi2pd`, `cvtpd2pi`, `cvttpd2pi`

#### Data Movement
- **Aligned**: `movaps`, `movapd`, `movdqa`
- **Unaligned**: `movups`, `movupd`, `movdqu`
- **Half/Low**: `movhps`, `movlps`, `movhpd`, `movlpd`
- **Non-Temporal**: `movntps`, `movntpd`, `movntdq`
- **Masked**: `maskmovdqu`

#### Shuffle & Unpack
- **Shuffle**: `shufps`, `shufpd`, `pshufd`, `pshufhw`, `pshuflw`, `pshufw`
- **Unpack**: `unpcklps`, `unpckhps`, `unpcklpd`, `unpckhpd`

### SSE3/SSSE3

#### SSE3
`movddup`, `movshdup`, `movsldup`, `addsubps`, `addsubpd`, `haddps`, `haddpd`, `hsubps`, `hsubpd`

#### SSSE3
- **Absolute Value**: `pabsb`, `pabsw`, `pabsd`
- **Sign Operations**: `psignb`, `psignw`, `psignd`
- **Shuffle**: `pshufb`
- **Alignment**: `palignr`
- **Multiply**: `pmulhrsw`

### SSE4.1/SSE4.2

#### SSE4.1
- **Min/Max**: `pminsb`, `pminuw`, `pminud`, `pminsd`, `pmaxsb`, `pmaxuw`, `pmaxud`, `pmaxsd`
- **Blend**: `blendps`, `blendpd`, `pblendw`
- **Insert/Extract**: `pinsrb`, `pinsrd`, `pinsrq`, `pextrb`, `pextrd`, `pextrq`, `insertps`, `extractps`
- **Rounding**: `roundss`, `roundsd`
- **Dot Product**: `dpps`, `dppd`
- **Other**: `pmuldq`, `movntdqa`

#### SSE4.2
- **String Compare**: `pcmpestri`, `pcmpestrm`, `pcmpistri`, `pcmpistrm`
- **CRC32**: `crc32`

### AES-NI

**Instructions**: `aesenc`, `aesenclast`, `aesdec`, `aesdeclast`, `aesimc`, `aeskeygenassist`

### AVX (128/256-bit)

**Registers**: `xmm0`-`xmm15`, `ymm0`-`ymm15` (extended to `ymm0`-`ymm31` in AVX-512)

#### Packed Operations
- **Arithmetic**: `vaddps`, `vaddpd`, `vsubps`, `vsubpd`, `vmulps`, `vmulpd`, `vdivps`, `vdivpd`
- **Math**: `vsqrtps`, `vsqrtpd`
- **Logical**: `vxorps`, `vxorpd`
- **Comparison**: `vcmpps`, `vcmppd`
- **Data Movement**: `vmovaps`, `vmovups`, `vmovdqa`, `vmovdqu`

#### Conversions
`vcvtps2pd`, `vcvtpd2ps`, `vcvtps2dq`, `vcvtpd2dq`, `vcvtdq2ps`, `vcvtdq2pd`

#### Horizontal Operations
`vhaddps`, `vhaddpd`, `vhsubps`, `vhsubpd`

#### Blend Operations
`vblendps`, `vblendpd`

#### Rounding & Utilities
`vroundps`, `vroundpd`, `vptest`, `vpermilps`, `vpermilpd`

### FMA3 (Fused Multiply-Add)

- **FMA**: `vfmadd132ps`, `vfmadd132pd`, `vfmadd213ps`, `vfmadd213pd`, `vfmadd231ps`, `vfmadd231pd`
- **FMS**: `vfmsub132ps`, `vfmsub132pd`, `vfmsub213ps`, `vfmsub213pd`, `vfmsub231ps`, `vfmsub231pd`
- **FNMA**: `vfnmadd132ps`, `vfnmadd132pd`, `vfnmadd213ps`, `vfnmadd213pd`, `vfnmadd231ps`, `vfnmadd231pd`
- **FNMS**: `vfnmsub132ps`, `vfnmsub132pd`, `vfnmsub213ps`, `vfnmsub213pd`, `vfnmsub231ps`, `vfnmsub231pd`

### AVX2

- **Permutations**: `vperm2i128`, `vpermd`, `vpermq`
- **Gather**: `vgatherdps`, `vgatherdpd`, `vgatherqps`, `vgatherqpd`
- **Masked Moves**: `vpmaskmovd`, `vpmaskmovq`

### AVX-512 Foundation

**Registers**: 
- `zmm0`-`zmm31` (32 512-bit vector registers)
- `k0`-`k7` (8 opmask registers for predication)
- Extends `xmm0`-`xmm31`, `ymm0`-`ymm31` (high 16 registers)

#### Opmask Operations
- **Move**: `kmovw`, `kmovb`, `kmovq`, `kmovd` (between masks, GPRs, memory)
- **Logical**: `kandw`, `kandb`, `kandq`, `kandd`, `korw`, `korb`, `korq`, `kord`, `kxorw`, `kxorb`, `kxorq`, `kxord`, `knotw`, `knotb`, `knotq`, `knotd`

#### 512-bit Arithmetic (ZMM)
- **Floating-Point**: `vaddps.512`, `vaddpd.512`, `vsubps.512`, `vsubpd.512`, `vmulps.512`, `vmulpd.512`, `vdivps.512`, `vdivpd.512`

#### 512-bit Data Movement
- **Aligned**: `vmovaps.512`, `vmovapd.512`, `vmovdqa32`, `vmovdqa64`
- **Unaligned**: `vmovups.512`, `vmovupd.512`, `vmovdqu32`, `vmovdqu64`

#### Broadcast Operations
- **Scalar**: `vbroadcastss`, `vbroadcastsd`, `vpbroadcastd`, `vpbroadcastq`
- **Vector**: `vbroadcasti32x4`, `vbroadcasti64x4`

## Architecture Behavior

### Operand Size Prefixes

The assembler automatically manages 0x66 prefixes based on target mode:

**16-bit mode** (`-m16`):
- 16-bit ops: No prefix (default)
- 32-bit ops: 0x66 prefix

**32-bit mode** (`-m32`):
- 32-bit ops: No prefix (default)
- 16-bit ops: 0x66 prefix

**64-bit mode** (`-m64`):
- 32-bit ops: No prefix (default)
- 16-bit ops: 0x66 prefix
- 64-bit ops: REX.W prefix (0x48-0x4F)

### Register Restrictions

**16-bit mode**: Cannot use r8-r15, 64-bit registers, or REX-only 8-bit registers (spl, bpl, sil, dil)

**32-bit mode**: Cannot use r8-r15, 64-bit registers, or REX-only 8-bit registers

**64-bit mode**: All registers available

### REX Prefix (64-bit mode only)
Automatically emitted when:
- Accessing 64-bit registers (REX.W = 1)
- Using r8-r15 or variants (REX.B/R/X = 1)
- Using spl, bpl, sil, dil registers

## Macro System

NASM-compatible macros with full feature support (100% NASM compatibility):

### Basic Macros
```asm
%macro PUSH_TWO 2
    push %1
    push %2
%endmacro

PUSH_TWO rax, rbx
```

### Local Labels
```asm
%macro LOOP_N 2
%%loop:
    %1
    dec %2
    jnz %%loop
%endmacro

LOOP_N nop, rcx    ; %%loop becomes __macro_0_loop
```

### Variadic Macros
```asm
%macro PUSH_MANY 1-*     ; Min 1, unlimited max
    push %1
%endmacro

PUSH_MANY rax, rbx, rcx
```

### Parameter Operators
```asm
%macro FLEXIBLE 1-*
    ; %0 = parameter count
    %if %0 == 1
        mov rax, %1
    %elif %0 > 1
        mov rax, %1
        mov rbx, %2
    %endif
    
    ; %?N = check if parameter N exists (1 if yes, 0 if no)
    %if %?3
        mov rcx, %3
    %endif
%endmacro

FLEXIBLE 10           ; Sets rax only
FLEXIBLE 20, 30       ; Sets rax and rbx
FLEXIBLE 40, 50, 60   ; Sets rax, rbx, and rcx
```

### Parameter Rotation
```asm
%macro ROTATE_DEMO 3
    mov rax, %1        ; rax = first param
    %rotate 1          ; Shift: %1←%2, %2←%3, %3←%1
    mov rbx, %1        ; rbx = second param
    %rotate 1
    mov rcx, %1        ; rcx = third param
%endmacro

ROTATE_DEMO 10, 20, 30
```

### Text Substitution
```asm
%define SYSCALL_EXIT 60
%define BUFFER_SIZE 1024

mov rax, SYSCALL_EXIT    ; Expands to: mov rax, 60
```

### Numeric Variables
```asm
%assign counter 0
%assign max_count 10

mov rax, counter         ; Expands to: mov rax, 0

%assign counter counter + 1
mov rbx, counter         ; Expands to: mov rbx, 1
```

### Expression-Based Conditionals
```asm
%assign DEBUG 1
%assign VERSION 2

%if VERSION > 1
    ; Version 2+ code
%elif VERSION == 1
    ; Version 1 code
%else
    ; Legacy code
%endif

%if DEBUG && (VERSION >= 2)
    ; Debug output for v2+
%endif
```

### Identifier-Based Conditionals
```asm
%define LINUX

%ifdef LINUX
    syscall
%else
    int 0x21
%endif

%ifndef WINDOWS
    ; Linux-specific code
%endif
```

### Repetition Loops
```asm
%rep 10
    nop                  ; Emit 10 NOPs
%endrep

%assign count 5
%rep count
    inc rax             ; Emit 5 inc instructions
%endrep

; Nested loops
%rep 3
    %rep 4
        db 0xFF         ; 3×4 = 12 bytes of 0xFF
    %endrep
%endrep
```

### File Inclusion
```asm
%include "constants.inc"
```

### String Functions
```asm
; Basic string function support
%strlen(<string>)        ; Returns string length
%substr(<str>, <pos>, <len>)  ; Extracts substring  
%strcat(<str1>, <str2>)  ; Concatenates strings
```

### Complete Feature List

**✓ Fully Supported:**
- `%macro`/`%endmacro` - Macro definitions
- `%imacro`/`%endmacro` - Case-insensitive macros
- `%macro+` - Greedy parameter matching (accepts extra params)
- `%1`-`%9` - Parameter references
- `%%label` - Macro-local labels
- `%0` - Parameter count operator
- `%?N` - Parameter existence check
- `%+` - Token concatenation operator
- `%rotate N` - Rotate macro parameters
- `%define` - Text substitution
- `%deftok` - Define without adding quotes
- `%defstr` - Define with automatic quotes
- `%assign` - Numeric variable assignment
- `%ifdef`/`%ifndef` - Identifier conditionals
- `%if`/`%elif`/`%else`/`%endif` - Expression conditionals
- `%rep`/`%endrep` - Repetition loops
- `%include` - File inclusion
- `%push`/`%pop` - Context stack management
- `%$` - Context-local labels (in macro bodies)
- `proc`/`endproc` - Procedure macros with stack frames
- Variadic macros with `N-M` or `N-*` syntax
- Full expression evaluation in `%if` and `%assign`
- String functions: `%strlen`, `%substr`, `%strcat`

See [MACROS.md](MACROS.md) for complete documentation.

## Expression Evaluation

Full support for C-like expressions:

### Operators
- **Arithmetic**: `+`, `-`, `*`, `/`, `%`
- **Bitwise**: `&`, `|`, `^`, `~`, `<<`, `>>`
- **Grouping**: `( )`

### Position Symbols
- `$` - Current address (section start + offset)
- `$$` - Section start address

### Examples
```asm
mov rax, (1 << 10) + 5          ; 1029
mov rbx, msg_end - msg          ; Calculate size
times 512-($-$$) db 0           ; Pad to 512 bytes
jmp $                           ; Infinite loop
```

## Local Labels

Labels starting with `.` are scoped to the preceding global label:

```asm
_start:
    jmp .skip
.skip:
    ret

helper:
    jmp .loop    ; Different from _start.skip
.loop:
    ret
```

## Building

```bash
make        # Build assembler
make clean  # Clean build artifacts
```

## Usage Examples

### Hello World (Linux x64)
```asm
section .data
    msg db 'Hello, World!', 10
    len equ $ - msg

section .text
    global _start

_start:
    mov rax, 1        ; sys_write
    mov rdi, 1        ; stdout
    mov rsi, msg
    mov rdx, len
    syscall

    mov rax, 60       ; sys_exit
    xor rdi, rdi
    syscall
```

### Bootloader (16-bit)
```asm
bits 16
org 0x7C00

start:
    mov ax, 0x07C0
    mov ds, ax
    mov si, msg
    call print
    jmp $

print:
    lodsb
    or al, al
    jz .done
    mov ah, 0x0E
    int 0x10
    jmp print
.done:
    ret

msg db 'Booting...', 0

times 510-($-$$) db 0
dw 0xAA55
```

### AVX-512 Example
```asm
bits 64

section .text
    global vector_add

vector_add:
    ; Load 512-bit vectors
    vmovups.512 zmm0, [rdi]      ; Load first vector
    vmovups.512 zmm1, [rsi]      ; Load second vector
    
    ; Add vectors
    vaddps.512 zmm2, zmm0, zmm1
    
    ; Store result
    vmovups.512 [rdx], zmm2
    ret
```

## License

See LICENSE file for details.

## Documentation

- [MACROS.md](MACROS.md) - Complete macro system documentation
- [tests/examples/](tests/examples/) - Example assembly files

## Project Structure

```
rasm/
├── src/
│   ├── assembler.c    # Core assembler
│   └── main.c         # CLI interface
├── include/
│   ├── assembler.h
│   └── common.h
├── tests/
│   └── examples/      # Test programs
├── Makefile
└── README.md
```
