# RASM - x86-64 Assembler

A from-scratch x86-64 assembler written in C17 that produces ELF64 relocatable object files.

## Features

### Supported Instruction Set

**General Purpose (64-bit)**
- **Data Movement**: `mov`, `movzx`, `movsx`, `movsxd`, `lea`, `push`, `pop`
- **Arithmetic**: `add`, `sub`, `cmp`, `inc`, `dec`, `neg`, `mul`, `imul`, `div`, `idiv`, `cqo`
- **Logical**: `xor`, `and`, `or`, `not`, `test`
- **Shifts**: `shl`/`sal`, `shr`, `sar` (immediate or cl register)
- **Control Flow**: 
  - Unconditional: `jmp`, `call`, `ret`
  - Conditional jumps: `je`/`jz`, `jne`/`jnz`, `ja`, `jae`, `jb`, `jbe`, `jg`, `jge`, `jl`, `jle`, `jo`, `jno`, `js`, `jns`, `jp`, `jnp`
  - Conditional moves: `cmove`, `cmovne`, `cmova`, `cmovae`, etc. (all 16 conditions)
  - Conditional sets: `sete`, `setne`, `seta`, `setae`, etc. (all 16 conditions, byte-sized)
- **System**: `syscall`, `nop`

**SSE/AVX Packed Floating-Point**
- **SSE Packed** (128-bit XMM): `movaps`, `movups`, `movdqa`, `movdqu`, `addps`, `addpd`, `subps`, `subpd`, `mulps`, `mulpd`, `divps`, `divpd`, `sqrtps`, `sqrtpd`, `cmpps`, `cmppd`, `xorps`, `xorpd`
- **AVX Packed** (128/256-bit XMM/YMM): `vmovaps`, `vmovups`, `vmovdqa`, `vmovdqu`, `vaddps`, `vaddpd`, `vsubps`, `vsubpd`, `vmulps`, `vmulpd`, `vdivps`, `vdivpd`, `vsqrtps`, `vsqrtpd`, `vcmpps`, `vcmppd`, `vxorps`, `vxorpd`
- **AVX Conversions**: `vcvtps2pd`, `vcvtpd2ps`, `vcvtps2dq`, `vcvtpd2dq`, `vcvtdq2ps`, `vcvtdq2pd`
- **SSE3/AVX Horizontal**: `haddps`, `haddpd`, `hsubps`, `hsubpd`, `vhaddps`, `vhaddpd`, `vhsubps`, `vhsubpd`
- **SSE4.1 Blend/Insert/Extract**: `blendps`, `blendpd`, `vblendps`, `vblendpd`, `insertps`, `extractps`, `pblendw`
- **SSE4.1 Scalar Rounding**: `roundss`, `roundsd`
- **SSE4.1 Dot Product**: `dpps`, `dppd`
- **FMA3 (Fused Multiply-Add)**: `vfmadd132ps`, `vfmadd132pd`, `vfmadd213ps`, `vfmadd213pd`, `vfmadd231ps`, `vfmadd231pd`, `vfmsub132ps`, `vfmsub132pd`, `vfmsub213ps`, `vfmsub213pd`, `vfmsub231ps`, `vfmsub231pd`, `vfnmadd132ps`, `vfnmadd132pd`, `vfnmadd213ps`, `vfnmadd213pd`, `vfnmadd231ps`, `vfnmadd231pd`, `vfnmsub132ps`, `vfnmsub132pd`, `vfnmsub213ps`, `vfnmsub213pd`, `vfnmsub231ps`, `vfnmsub231pd`
- **AVX2 Permutations**: `vperm2i128`, `vpermd`, `vpermq`
- **AVX2 Gather**: `vgatherdps`, `vgatherdpd`, `vgatherqps`, `vgatherqpd`
- **AVX2 Masked Moves**: `vpmaskmovd`, `vpmaskmovq`
- **AVX Utilities**: `vptest`, `vroundps`, `vroundpd`, `vpermilps`, `vpermilpd`

**SSE Scalar Floating-Point**
- **Arithmetic**: `addss`, `addsd`, `subss`, `subsd`, `mulss`, `mulsd`, `divss`, `divsd`
- **Math**: `sqrtss`, `sqrtsd`
- **Data Movement**: `movss`, `movsd`
- **Comparisons**: `comiss`, `comisd`, `ucomiss`, `ucomisd`
- **Conversions**: 
  - Float ↔ Double: `cvtss2sd`, `cvtsd2ss`
  - Integer → Float: `cvtsi2ss`, `cvtsi2sd`
  - Float → Integer: `cvtss2si`, `cvtsd2si` (rounding), `cvttss2si`, `cvttsd2si` (truncating)

### Addressing Modes

- **Register Direct**: `mov rax, rbx`
- **Immediate**: `mov rax, 42`, `mov rax, symbol`
- **RIP-Relative** (position-independent): `mov rax, [rip+label]`
- **Memory Indirect with SIB**: 
  - `[base + index*scale + disp]`
  - `[rax+rbx*4+16]`
  - `[rbp-8]`
- **Absolute**: `[0x1234]` (no base/index)

### Assembly Directives

- **Sections**: `section .text`, `section .data`, `section .bss` (or `.text`, `.data`, `.bss`)
- **Symbol Visibility**: `global symbol_name`, `extern external_fn`
- **Data Definition**: `db`, `dw`, `dd`, `dq` (byte/word/dword/qword)
- **Space Reservation**: `resb`, `resw`, `resd`, `resq`
- **Alignment**: `align N`
- **Macros**: `%macro NAME count` ... `%endmacro` (see [MACROS.md](MACROS.md))
- **Local Labels**: `.label` (scoped to preceding global label)
- **Expressions**: Full arithmetic and bitwise expressions in operands

### Expression Evaluation

Supports symbolic expressions with C-like operators:
- **Arithmetic**: `+`, `-`, `*`, `/`, `%`
- **Bitwise**: `&`, `|`, `^`, `~`, `<<`, `>>`
- **Grouping**: `( )`

Examples:
```asm
mov rax, (1 << 10) + 5          ; 1029
mov rbx, msg_end - msg          ; Calculate size
mov rcx, (array_size * 8) >> 3  ; Complex expression
```

### Local Labels

Labels starting with `.` are scoped to the most recent global label:
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

### Macro System (Phases 1, 2, 3 & 4)

NASM-compatible macros with parameters, local labels, text substitution, conditional assembly, and file inclusion:

**Phase 1 - Basic Macros:**
```asm
%macro PUSH_TWO 2
    push %1
    push %2
%endmacro

%macro LOOP_N 2
%%loop:
    %1
    dec %2
    jnz %%loop
%endmacro

PUSH_TWO rax, rbx        ; Expands with parameters
LOOP_N nop, rcx          ; Local label becomes __macro_0_loop
```

**Phase 2 - Text Substitution:**
```asm
%define SYSCALL_EXIT 60
%define BUFFER_SIZE 1024

mov rax, SYSCALL_EXIT    ; Expands to: mov rax, 60
mov rcx, BUFFER_SIZE     ; Expands to: mov rcx, 1024
```

**Phase 3 - Conditional Assembly:**
```asm
%define LINUX

%ifdef LINUX
    mov rax, 60          ; Included only if LINUX defined
%else
    int 0x21             ; Skipped
%endif

%ifndef WINDOWS
    syscall              ; Included if WINDOWS not defined
%endif
```

**Phase 4 - File Inclusion:**
```asm
; constants.inc
%define SYSCALL_EXIT 60
%define BUFFER_SIZE 1024

; main.asm
%include "constants.inc"

mov rax, SYSCALL_EXIT    ; Uses define from included file
mov rcx, BUFFER_SIZE
```

**Variadic Macros:**
```asm
; Minimum 1 parameter, unlimited maximum
%macro PUSH_MANY 1-*
    push %1
%endmacro

PUSH_MANY rax                    ; 1 parameter
PUSH_MANY rbx, rcx               ; 2 parameters
PUSH_MANY rdx, rsi, rdi, r8      ; 4 parameters

; Minimum 2 parameters, maximum 4
%macro ADD_RANGE 2-4
    add %1, %2
%endmacro

ADD_RANGE rax, rbx               ; 2 parameters
ADD_RANGE rcx, rdx, rsi          ; 3 parameters
```

#### Macro System Details

**Parameter Substitution:**
Parameters are referenced using `%1`, `%2`, ..., `%9`:
```asm
%macro PUSH_TWO 2
    push %1
    push %2
%endmacro

PUSH_TWO rax, rbx    ; Expands to: push rax / push rbx
```

**Macro-Local Labels:**
Use `%%label` for labels unique to each macro invocation:
```asm
%macro LOOP_N 2
%%loop:
    %1
    dec %2
    jnz %%loop
%endmacro

LOOP_N nop, rcx    ; Creates __macro_0_loop
LOOP_N nop, rdx    ; Creates __macro_1_loop (different label)
```

**Define Directive:**
Create text substitutions that apply throughout your code:
```asm
%define name value
```

Simple constants:
```asm
%define SYSCALL_EXIT 60
%define EXIT_SUCCESS 0

mov rax, SYSCALL_EXIT  ; Expands to: mov rax, 60
mov rdi, EXIT_SUCCESS  ; Expands to: mov rdi, 0
```

Register aliases:
```asm
%define COUNTER rcx
%define ACCUMULATOR rax

mov COUNTER, 10        ; Expands to: mov rcx, 10
add ACCUMULATOR, 5     ; Expands to: add rax, 5
```

**Conditional Assembly:**
Conditionally include code based on whether a symbol is defined:
```asm
%ifdef LINUX
    mov rax, 60      ; Included only if LINUX is defined
    syscall
%endif

%ifndef WINDOWS
    nop              ; Included only if WINDOWS is NOT defined
%endif
```

Nesting conditionals:
```asm
%ifdef LINUX
    %ifdef DEBUG
        call linux_debug
    %else
        call linux_release
    %endif
%else
    call other_os
%endif
```

**File Inclusion:**
Include external files during preprocessing:
```asm
%include "file.inc"
```

Features:
- **Path Resolution**: Relative to including file's directory
- **Recursive**: Included files can %include other files
- **Context Sharing**: All macros, defines, and conditionals are shared
- **Preprocessing**: Files are fully preprocessed before inclusion

**Variadic Macro Syntax:**
- `%macro NAME N` - Fixed N parameters (backward compatible)
- `%macro NAME N-M` - Minimum N, maximum M parameters
- `%macro NAME N-*` - Minimum N, unlimited maximum

Parameter validation:
```asm
%macro TEST 2-4
    mov %1, %2
%endmacro
TEST rax        ; Error: requires at least 2 parameters
TEST a, b, c, d, e    ; Error: accepts at most 4 parameters
```

### Additional Parsing Features

**String Initialization:**
Both single and double quotes supported:
```asm
section .data
    msg1: db "Double quoted string", 0
    msg2: db 'Single quoted string', 0
```

**Times Directive:**
Repeat data or reserve directives:
```asm
section .data
    zeros: times 10 db 0              ; 10 zero bytes
    pattern: times 5 db 0xAA, 0x55    ; Pattern repeated 5 times
    words: times 4 dw 0x1234          ; 4 words (8 bytes)

section .bss
    buffer: times 256 resb 1          ; 256 byte buffer
    array: times 64 resq 1            ; Array of 64 qwords
```

### Output Format

- Standard ELF64 relocatable object files (.o)
- Proper section headers (.text, .data, .bss, .note.GNU-stack)
- Symbol table with correct local/global ordering
- RELA relocations (R_X86_64_PC32, R_X86_64_PLT32, R_X86_64_64)
- Compatible with GNU `ld` and `gcc` linkers
- RIP-relative addressing for position-independent code
- PIE-compatible: external function calls use PLT32 relocations

## Building

```bash
make
```

Requirements: C17 compiler (gcc/clang), standard headers

## Usage

### Basic Assembly

```bash
./rasm input.asm -o output.o
```

### Multiple Source Files

Assemble multiple source files (concatenated):
```bash
./rasm file1.asm file2.asm file3.asm -o output.o
```

### Listing File Generation

Generate an assembly listing showing addresses, hex bytes, and source:
```bash
./rasm input.asm -o output.o -l output.lst
```

**Example listing output:**
```
RASM Listing File
=================

0000: .data    msg:
0000: .data    48 65 6C 6C 6F 2C 20 77 6F 72 6C 64 21 00
              db "Hello, world!", 0

0000: .text    main:
0000: .text    48 83 EC 08
              sub rsp, 8
0004: .text    48 8D 3D 00 00 00 00
              lea rdi, [rip+msg]
000B: .text    E8 00 00 00 00
              call puts
```

### Library Generation

Create static library archives (`.a`) from assembled object files:
```bash
./rasm lib_func1.asm lib_func2.asm -o libmath.o -a libmath.a
```

Use the library when linking:
```bash
./rasm main.asm -o main.o
gcc -o program main.o libmath.a
```

The `-a` flag uses `ar rcs` to create a standard Unix archive containing the assembled object file.

### Linking

With `ld`:
```bash
ld -o program output.o -e entry_point
```

With `gcc` (for libc functions):
```bash
gcc -o program output.o
```

With PIE (Position Independent Executable):
```bash
gcc -pie -o program output.o
```

### Example Program

**hello.asm:**
```asm
global main
extern puts
extern exit

section .data
msg: db "Hello, world!", 0

section .text
main:
    sub rsp, 8              ; align stack
    lea rdi, [rip+msg]      ; arg0 = message
    call puts
    add rsp, 8
    mov rax, 0              ; return 0
    ret
```

**Assembly and linking:**
```bash
./rasm hello.asm -o hello.o
gcc -o hello hello.o
./hello
```

### Scalar Floating-Point Example

**float_test.asm:**
```asm
global _start

section .data
fval1: dd 3.14159
fval2: dd 2.71828

section .text
_start:
    movss xmm0, [rip+fval1]
    movss xmm1, [rip+fval2]
    addss xmm0, xmm1        ; xmm0 = fval1 + fval2
    mulss xmm0, xmm1        ; xmm0 *= fval2
    sqrtss xmm2, xmm0       ; xmm2 = sqrt(xmm0)
    
    mov rax, 60             ; exit syscall
    xor rdi, rdi
    syscall
```

### AVX Vector Example

**vector.asm:**
```asm
global _start

section .data
vec: dd 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0

section .text
_start:
    vmovups ymm0, [rip+vec]     ; load 8 floats
    vmovaps ymm1, ymm0
    vaddps ymm2, ymm1, ymm0     ; ymm2 = ymm1 + ymm0
    vmulps ymm3, ymm2, ymm0     ; ymm3 = ymm2 * ymm0
    
    mov rax, 60
    xor rdi, rdi
    syscall
```

## Syntax

### Intel Syntax

- Case-insensitive instructions and registers
- Destination operand first: `mov dest, src`
- Memory operands in brackets: `[rip+label]`
- Comments start with `;`

### Labels

```asm
label:              ; local label
global_label:       ; can be exported with 'global'
.local_label:       ; local to current scope (not yet implemented)
```

### Numeric Literals

- Decimal: `42`, `-10`
- Hexadecimal: `0x2A`, `0xFF`

## Testing

Run the test suite:
```bash
make test
```

Tests include:
- Comprehensive instruction encoding
- ALU operations with immediate forms
- Unary and shift operations  
- SSE/AVX packed vector operations
- Scalar floating-point operations
- Conditional branches and setcc
- Sign/zero extension instructions

## Architecture

**Two-Pass Assembly:**
1. **First Pass**: Calculates instruction sizes by encoding into scratch buffers, assigns symbol offsets
2. **Second Pass**: Emits final machine code with relocations

**Key Components:**
- Parser: Intel-syntax assembly → internal IR
- Encoder: IR → x86-64 machine code (REX, VEX, ModR/M, SIB)
- ELF Writer: Machine code → ELF64 object file

## Future Enhancements

### Instruction Encoding
No outstanding instruction encoding tasks at this time!

**Recently Implemented:**
- [x] Additional SSE4.1 instructions: `pblendw`, `roundss`, `roundsd`, `dpps`, `dppd`
- [x] Additional FMA variants: `vfmsub`, `vfnmadd`, `vfnmsub` (132/213/231 forms)
- [x] Additional AVX2 instructions: `vpermq`, `vgather*`, `vpmaskmov*`

### Parsing & Semantics
No outstanding parsing features at this time!

**Recently Implemented:**
- [x] Expression evaluation in operands (full arithmetic/bitwise support)
- [x] Local labels (`.label` syntax)
- [x] Macro system (Phase 1: `%macro`/`%endmacro` with parameters and `%%local` labels)
- [x] Text substitution (Phase 2: `%define` directives)
- [x] Conditional assembly (Phase 3: `%ifdef`, `%ifndef`, `%else`, `%endif`)
- [x] File inclusion (Phase 4: `%include "file.inc"` with recursive preprocessing and shared context)
- [x] Data initialization from strings: `db "string"` with both double and single quote support
- [x] Duplicate data: `times N <directive> <args>` for repeating data/reserve directives
- [x] Variadic macros: `%macro NAME N-M` (range) and `%macro NAME N-*` (unlimited) with parameter validation
- [x] AVX conversion instructions: `vcvtps2pd`, `vcvtpd2ps`, `vcvtps2dq`, `vcvtpd2dq`, `vcvtdq2ps`, `vcvtdq2pd`
- [x] SSE3/AVX horizontal operations: `haddps`, `haddpd`, `hsubps`, `hsubpd`, `vhaddps`, `vhaddpd`, `vhsubps`, `vhsubpd`
- [x] SSE4.1 blend operations: `blendps`, `blendpd`, `vblendps`, `vblendpd`
- [x] SSE4.1 insert/extract: `insertps`, `extractps`
- [x] SSE4.1 additional: `pblendw`, `roundss`, `roundsd`, `dpps`, `dppd`
- [x] FMA3 instructions: `vfmadd132ps/pd`, `vfmadd213ps/pd`, `vfmadd231ps/pd`, `vfmsub132ps/pd`, `vfmsub213ps/pd`, `vfmsub231ps/pd`, `vfnmadd132ps/pd`, `vfnmadd213ps/pd`, `vfnmadd231ps/pd`, `vfnmsub132ps/pd`, `vfnmsub213ps/pd`, `vfnmsub231ps/pd`
- [x] AVX2 permutations: `vperm2i128`, `vpermd`, `vpermq`
- [x] AVX2 gather operations: `vgatherdps`, `vgatherdpd`, `vgatherqps`, `vgatherqpd`
- [x] AVX2 masked moves: `vpmaskmovd`, `vpmaskmovq`
- [x] 32/16-bit operand variants: `mov`, bit manipulation (`bsf`, `bsr`, `bt`, `btc`, `btr`, `bts`, `bswap`), BMI/BMI2 instructions
- [x] 8/16/32-bit operand support for ALU instructions: `add`, `sub`, `xor`, `and`, `or`, `cmp`, `test` (all operand sizes)
- [x] SSE2 integer operations: `paddd`, `psubd`, `pmulld`, etc.
- [x] SSE/AVX packed comparisons: `cmpps`, `cmppd`, `vcmpps`, `vcmppd` (with predicates)
- [x] SSE/AVX packed division/sqrt: `divps`, `divpd`, `sqrtps`, `sqrtpd`, `vdivps`, `vdivpd`, `vsqrtps`, `vsqrtpd`
- [x] BMI/BMI2 instructions: `andn`, `bextr`, `bzhi`, `pdep`, `pext`, `lzcnt`, `tzcnt`, `popcnt`, etc.
- [x] Bit manipulation: `bsf`, `bsr`, `bswap`, `bt`, `btc`, `btr`, `bts`
- [x] String operations: `movsb`, `stosb`, `lodsb`, `scasb`, `cmpsb` (and word/dword/qword variants)

**Optimization:**
- [x] Short branch selection (2-byte vs 5/6-byte): Automatically uses short form when target is within ±128 bytes
- [x] Optimal immediate encoding (sign-extension): Implemented via `is_simm8()` checks throughout instruction encoding

**Validation:**
- [x] Immediate range validation: Validates immediate values fit within operand size (8/16/32/64-bit)
- [x] Register size matching: Prevents encoding mismatched register sizes (e.g., `mov al, rax`)
- [x] Undefined symbol detection: Reports undefined symbols at assembly time (excluding externs)
- [x] Error messages with line numbers: Line numbers shown for parse errors, encode errors, and data errors

**Advanced Features (Compiler-Level):**
Note: The following features are typically implemented in compilers rather than assemblers:
- Dead code elimination - Requires control flow analysis
- Instruction scheduling - Requires dataflow analysis and CPU-specific timing models


**Features:**
- [x] Multiple source file support (concatenated assembly)
- [x] Listing file generation (`.lst` with addresses/bytes/source)
- [x] Position-independent executable (PIE) support: External function calls use `R_X86_64_PLT32` relocations
- [x] Library generation (static `.a` archives via `ar` tool)
- [x] DWARF debug information: Generates `.debug_line`, `.debug_info`, and `.debug_abbrev` sections (DWARF v2)
- [x] Symbol table ordering: Properly orders local and global symbols for linker compatibility


## Contributing

Key areas for contribution:
- Adding missing instruction encodings
- Improving error messages
- Adding more operand validation
- Implementing optimal immediate encoding
- Adding expression evaluation improvements

## License

MIT

## Credits

Written as a from-scratch educational/practical x86-64 assembler project.
