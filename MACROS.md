# Macro System - Phases 1, 2, 3 & 4

## Overview
The macro system provides NASM-compatible preprocessing with macros, text substitution, conditional assembly, and file inclusion.

**Phase 1** (Complete): Basic macros with parameters and local labels  
**Phase 2** (Complete): %define text substitution  
**Phase 3** (Complete): Conditional assembly (%ifdef, %ifndef, %else, %endif)  
**Phase 4** (Complete): File inclusion (%include with recursive preprocessing)

## Phase 1: Basic Macros

### Macro Definition
Define macros using `%macro` directive:
```asm
%macro NAME param_count
    ; macro body
%endmacro
```

### Parameter Substitution
Parameters are referenced using `%1`, `%2`, ..., `%9`:
```asm
%macro PUSH_TWO 2
    push %1
    push %2
%endmacro

; Usage:
PUSH_TWO rax, rbx    ; Expands to: push rax / push rbx
```

### Macro-Local Labels
Use `%%label` for labels that are unique to each macro invocation:
```asm
%macro LOOP_N 2
%%loop:
    %1
    dec %2
    jnz %%loop
%endmacro

; First call creates __macro_0_loop
LOOP_N nop, rcx

; Second call creates __macro_1_loop (different label)
LOOP_N nop, rdx
```

## Examples

### Zero-Parameter Macro
```asm
%macro SETUP 0
    mov rax, 1
    mov rdi, 1
%endmacro

SETUP    ; No parameters needed
```

### Multi-Parameter Macro
```asm
%macro CLEAR_REGS 3
    xor %1, %1
    xor %2, %2
    xor %3, %3
%endmacro

CLEAR_REGS rax, rbx, rcx
```

### Conditional with Local Labels
```asm
%macro COND_MOVE 3
    cmp %1, %2
    je %%skip
    mov %1, %3
%%skip:
%endmacro

COND_MOVE rax, rbx, 99
```

## Phase 2: Text Substitution (%define)

### Define Directive
Create text substitutions that apply throughout your code:
```asm
%define name value
```

### Simple Constants
```asm
%define SYSCALL_EXIT 60
%define EXIT_SUCCESS 0

mov rax, SYSCALL_EXIT  ; Expands to: mov rax, 60
mov rdi, EXIT_SUCCESS  ; Expands to: mov rdi, 0
```

### Register Aliases
```asm
%define COUNTER rcx
%define ACCUMULATOR rax

mov COUNTER, 10        ; Expands to: mov rcx, 10
add ACCUMULATOR, 5     ; Expands to: add rax, 5
```

### Using Defines with Macros
```asm
%define REG1 rax
%define REG2 rbx

%macro SWAP 2
    mov rcx, %1
    mov %1, %2
    mov %2, rcx
%endmacro

SWAP REG1, REG2        ; Expands with defines substituted
```

### Substitution Rules
- Defines are substituted before macro expansion
- Only complete identifiers are replaced (not substrings)
- Substitution skips:
  - Label definitions (`label:`)
  - Directive lines (`section`, `global`, etc.)
  - Comments
- Defines can be redefined (last definition wins)

## Phase 3: Conditional Assembly

### %ifdef / %ifndef
Conditionally include code based on whether a symbol is defined:
```asm
%define LINUX

%ifdef LINUX
    mov rax, 60      ; Included only if LINUX is defined
    syscall
%endif

%ifndef WINDOWS
    ; Included only if WINDOWS is NOT defined
    nop
%endif
```

### %else
Provide alternative code when condition is false:
```asm
%ifdef DEBUG
    ; Debug code
    call print_debug
%else
    ; Release code
    nop
%endif
```

### Nesting
Conditionals can be nested to any depth:
```asm
%ifdef LINUX
    %ifdef DEBUG
        ; Both LINUX and DEBUG defined
        call linux_debug
    %else
        ; LINUX defined, DEBUG not defined
        call linux_release
    %endif
%else
    %ifdef DEBUG
        ; LINUX not defined, DEBUG defined
        call other_debug
    %else
        ; Neither defined
        call other_release
    %endif
%endif
```

### Rules
- `%ifdef NAME` - true if NAME is defined (via %define)
- `%ifndef NAME` - true if NAME is NOT defined
- `%else` - inverts the condition of current block
- `%endif` - closes conditional block
- Conditionals are processed before macros and defines
- Nested conditionals require matching %endif for each level
- Code in inactive blocks is completely skipped (not parsed)

## Phase 4: File Inclusion

### Include Directive
Include external files during preprocessing:
```asm
%include "file.inc"
```

### Basic Usage
**constants.inc:**
```asm
%define SYSCALL_EXIT 60
%define SYSCALL_WRITE 1
%define STDOUT 1
```

**main.asm:**
```asm
%include "constants.inc"

section .text
global _start
_start:
    mov rax, SYSCALL_EXIT
    xor rdi, rdi
    syscall
```

### Recursive Inclusion
Included files can include other files:

**platform.inc:**
```asm
%define LINUX
%include "syscalls.inc"
```

**syscalls.inc:**
```asm
%ifdef LINUX
    %define SYS_EXIT 60
%else
    %define SYS_EXIT 1
%endif
```

### Shared Context
- Macros defined in included files are available to the including file
- %define substitutions work across file boundaries
- Conditional state is maintained across inclusions
- Each file is only included once (no duplicate inclusion)

### Features
- **Path Resolution**: Relative to including file's directory
- **Recursive**: Included files can %include other files
- **Context Sharing**: All macros, defines, and conditionals are shared
- **Preprocessing**: Files are fully preprocessed before inclusion

### Example with Macros
**macros.inc:**
```asm
%macro SAVE_REGS 0
    push rax
    push rbx
    push rcx
%endmacro

%macro RESTORE_REGS 0
    pop rcx
    pop rbx
    pop rax
%endmacro
```

**program.asm:**
```asm
%include "macros.inc"

section .text
function:
    SAVE_REGS
    ; function body
    RESTORE_REGS
    ret
```

## Implementation Details

### Preprocessing
Macros, defines, and conditionals are processed in a single preprocessing pass:
1. Scan source for `%define`, `%macro`, and conditional directives
2. Store definitions in hash table (defines) and vector (macros)
3. Track conditional nesting with a stack
4. For each line:
   - Process conditional directives (%ifdef, %ifndef, %else, %endif)
   - Skip lines in inactive conditional blocks
   - Apply define substitutions to active lines
   - Check for macro invocations and expand
   - Substitute `%N` parameters in macro bodies
   - Replace `%%label` with unique `__macro_ID_label`
5. Pass expanded source to assembler parser

### Parameter Parsing
Parameters can contain spaces and are separated by commas:
```asm
MACRO_CALL arg1, arg2 with spaces, arg3
```

### Expansion
Each macro invocation gets a unique expansion ID for generating distinct local labels.

## Testing
See test files:
- `tests/examples/macros.asm`: Phase 1 macro features  
- `tests/examples/macro_comprehensive.asm`: Advanced Phase 1 usage
- `tests/examples/defines.asm`: Phase 2 %define directives
- `tests/examples/defines_macros.asm`: Combining defines with macros
- `tests/examples/conditionals.asm`: Phase 3 conditional assembly
- `tests/examples/conditionals_complex.asm`: Nested conditionals
- Files with `%include` directives: Phase 4 file inclusion

## Limitations

### Current Limitations
- Maximum 32 parameters for variadic macros (reasonable limit)
- No macro nesting (defining macros within macros)
- No string operations (concatenation, substring, etc.)
- Defines are simple text replacement (no parameterized defines)
- No numeric expressions in conditionals (only %ifdef/%ifndef, no %if with expressions)
- Parameters beyond %9 require special syntax (not yet implemented)

## Future Enhancements
- Parameterized defines: `%define ADD(a,b) ((a)+(b))`
- String operations: `%substr`, `%strlen`, `%strcat`
- Numeric conditionals: `%if EXPR`, `%elif EXPR`
- Token operations: `%token`, `%iftoken`
