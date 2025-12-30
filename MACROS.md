# Macro System - Phases 1, 2 & 3

## Overview
The macro system provides NASM-compatible preprocessing with macros, text substitution, and conditional assembly.

**Phase 1** (Complete): Basic macros with parameters and local labels  
**Phase 2** (Complete): %define text substitution  
**Phase 3** (Complete): Conditional assembly (%ifdef, %ifndef, %else, %endif)

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

## Limitations

### Phases 1-3 Combined
- Maximum 9 parameters (%1-%9)
- No variadic macros
- No macro nesting (defining macros within macros)
- No string operations
- Defines are simple text replacement (no parameters)
- No numeric expressions in conditionals (only %ifdef/%ifndef, no %if with expressions)

## Future Phases
- **Phase 4**: Advanced features (variadic macros, string operations, %include, numeric %if)
