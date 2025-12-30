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
- **SSE4.1 Blend/Insert/Extract**: `blendps`, `blendpd`, `vblendps`, `vblendpd`, `insertps`, `extractps`
- **FMA3 (Fused Multiply-Add)**: `vfmadd132ps`, `vfmadd132pd`, `vfmadd213ps`, `vfmadd213pd`, `vfmadd231ps`, `vfmadd231pd`
- **AVX2 Permutations**: `vperm2i128`, `vpermd`
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

### Macro System (Phases 1, 2 & 3)

NASM-compatible macros with parameters, local labels, text substitution, and conditional assembly:

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

See [MACROS.md](MACROS.md) for complete documentation.

### Output Format

- Standard ELF64 relocatable object files (.o)
- Proper section headers (.text, .data, .bss, .note.GNU-stack)
- Symbol table with correct local/global ordering
- RELA relocations (R_X86_64_PC32, R_X86_64_64)
- Compatible with GNU `ld` and `gcc` linkers

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

### Linking

With `ld`:
```bash
ld -o program output.o -e entry_point
```

With `gcc` (for libc functions):
```bash
gcc -no-pie -o program output.o
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
gcc -no-pie -o hello hello.o
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
- [ ] Additional SSE4.1 instructions: `pblendw`, `roundss`, `roundsd`, `dpps`, `dppd`, etc.
- [ ] Additional FMA variants: `vfmsub`, `vfnmadd`, `vfnmsub` (132/213/231 forms)
- [ ] Additional AVX2 instructions: `vpermq`, `vgather*`, `vpmaskmov*`, etc.

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
- [x] FMA3 instructions: `vfmadd132ps/pd`, `vfmadd213ps/pd`, `vfmadd231ps/pd`
- [x] AVX2 permutations: `vperm2i128`, `vpermd`
- [x] 32/16-bit operand variants: `mov`, bit manipulation (`bsf`, `bsr`, `bt`, `btc`, `btr`, `bts`, `bswap`), BMI/BMI2 instructions
- [x] 8/16/32-bit operand support for ALU instructions: `add`, `sub`, `xor`, `and`, `or`, `cmp`, `test` (all operand sizes)
- [x] SSE2 integer operations: `paddd`, `psubd`, `pmulld`, etc.
- [x] SSE/AVX packed comparisons: `cmpps`, `cmppd`, `vcmpps`, `vcmppd` (with predicates)
- [x] SSE/AVX packed division/sqrt: `divps`, `divpd`, `sqrtps`, `sqrtpd`, `vdivps`, `vdivpd`, `vsqrtps`, `vsqrtpd`
- [x] BMI/BMI2 instructions: `andn`, `bextr`, `bzhi`, `pdep`, `pext`, `lzcnt`, `tzcnt`, `popcnt`, etc.
- [x] Bit manipulation: `bsf`, `bsr`, `bswap`, `bt`, `btc`, `btr`, `bts`
- [x] String operations: `movsb`, `stosb`, `lodsb`, `scasb`, `cmpsb` (and word/dword/qword variants)

**Optimization:**
- [ ] Short branch selection (2-byte vs 5/6-byte)
- [ ] Optimal immediate encoding (sign-extension)
- [ ] Dead code elimination
- [ ] Instruction scheduling hints

**Validation:**
- [ ] Register size matching (prevent encoding `mov al, rax`)
- [ ] Operand type checking (immediate range validation)
- [ ] Better error messages with line numbers
- [ ] Undefined symbol detection at assembly time

**Features:**
- [ ] DWARF debug information
- [ ] Position-independent executable (PIE) support improvements
- [ ] Multiple source file support
- [ ] Library generation (static .a)
- [ ] Listing file generation

### Nice to Have

- [ ] AT&T syntax support
- [ ] 32-bit mode / i386 target
- [ ] Windows COFF/PE object format
- [ ] Disassembler
- [ ] Interactive REPL mode

## Known Limitations

1. **Branch Encoding**: Currently forces all branches to near (5/6-byte) form for stability; no short (2-byte) optimization
2. **Symbol Table**: Some edge cases with symbol ordering cause linker warnings (rare)
3. **Immediate Validation**: Doesn't validate immediate value ranges; truncates silently

## Contributing

The codebase is ~2700 lines of C17 in a single file for simplicity. Key areas for contribution:
- Adding missing instruction encodings
- Improving error messages
- Adding operand validation
- Implementing short branch optimization
- Adding expression evaluation

## License

MIT

## Credits

Written as a from-scratch educational/practical x86-64 assembler project.
