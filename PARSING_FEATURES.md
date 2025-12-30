# New Parsing Features - Implementation Summary

## Overview
Three major parsing features have been implemented to enhance RASM's assembler directives:

1. **String Initialization** - Support for both single and double quotes
2. **Times Directive** - Repeat data/reserve directives efficiently
3. **Variadic Macros** - Flexible parameter counts for macros

## 1. String Initialization

### Feature
Both single quotes (`'`) and double quotes (`"`) can now be used for string literals in data directives.

### Syntax
```asm
section .data
    msg1: db "Double quoted string", 0
    msg2: db 'Single quoted string', 0
```

### Implementation Details
- Modified string parsing in data directive handler (lines 2730-2780)
- Tracks opening quote character and requires matching closing quote
- Supports escape sequences (`\n`, `\t`, `\\`, etc.) in both quote styles
- Validates that strings are only used with `db` directive

### Test Files
- `tests/examples/test_strings.asm` - Basic string test
- `tests/examples/parsing_features.asm` - Comprehensive test

## 2. Times Directive

### Feature
Repeat a data or reserve directive a specified number of times without manually duplicating code.

### Syntax
```asm
section .data
    zeros: times 10 db 0              ; 10 zero bytes
    pattern: times 5 db 0xAA, 0x55    ; Pattern repeated 5 times
    words: times 4 dw 0x1234          ; 4 words (8 bytes)
    dwords: times 3 dd 0xDEADBEEF     ; 3 dwords (12 bytes)

section .bss
    buffer: times 256 resb 1          ; 256 byte buffer
    array: times 64 resq 1            ; Array of 64 qwords
```

### Implementation Details
- Added times directive parsing before data directive section (lines 2660-2686)
- Parses count as expression (supports numeric literals)
- Wraps data directive parsing in loop for `times_count` iterations
- For reserve directives, multiplies count directly
- Default `times_count` is 1 (no times directive)

### Behavior
- **Data directives** (`db`, `dw`, `dd`, `dq`): Repeats the entire value list N times
- **Reserve directives** (`resb`, `resw`, `resd`, `resq`): Multiplies the reservation count

### Test Files
- `tests/examples/times_test.asm` - Comprehensive times directive test
- `tests/examples/parsing_features.asm` - Combined feature test

### Verified Output
```
$ size times_test.o
   text    data     bss     dec     hex filename
     15      69     220     304     130 times_test.o
```

BSS calculation verified:
- 100 bytes + 40 bytes + 40 bytes + 40 bytes = 220 bytes ✓

## 3. Variadic Macros

### Feature
Define macros that accept a variable number of parameters within a specified range.

### Syntax
```asm
; Minimum 1 parameter, unlimited maximum
%macro PUSH_MANY 1-*
    push %1
%endmacro

; Minimum 2 parameters, maximum 4
%macro ADD_RANGE 2-4
    add %1, %2
%endmacro

; Zero parameters accepted
%macro SAVE_REGS 0-*
    ; Implementation
%endmacro
```

### Usage
```asm
PUSH_MANY rax                    ; 1 parameter (minimum)
PUSH_MANY rbx, rcx               ; 2 parameters
PUSH_MANY rdx, rsi, rdi, r8      ; 4 parameters

ADD_RANGE rax, rbx               ; 2 parameters (minimum)
ADD_RANGE rcx, rdx, rsi          ; 3 parameters
ADD_RANGE rdi, r8, r9, r10       ; 4 parameters (maximum)
```

### Implementation Details

#### Data Structure (lines 658-665)
```c
typedef struct {
    char *name;
    int param_count;     // For fixed parameter macros (backward compatible)
    int min_params;      // Minimum parameters (for variadic)
    int max_params;      // Maximum parameters, or -1 for unlimited
    bool is_variadic;    // True if this is a variadic macro
    char **lines;
    size_t line_count;
} macro_def;
```

#### Parsing (lines 1664-1717)
- Parses parameter specification: `N`, `N-M`, or `N-*`
- `N` = fixed N parameters (backward compatible)
- `N-M` = minimum N, maximum M parameters
- `N-*` = minimum N, unlimited maximum
- Sets `is_variadic` flag and min/max parameters

#### Invocation (lines 1775-1870)
- Parses all provided parameters (up to 32 limit)
- Validates parameter count against min/max constraints
- For variadic macros:
  - Checks `actual_param_count >= min_params`
  - If `max_params >= 0`, checks `actual_param_count <= max_params`
- Reports clear error messages for parameter count mismatches

### Parameter Validation
```asm
; Error: Too few parameters
%macro TEST 2-4
    mov %1, %2
%endmacro
TEST rax        ; Error: requires at least 2 parameters, got 1

; Error: Too many parameters
%macro TEST2 1-3
    mov rax, %1
%endmacro
TEST2 1, 2, 3, 4, 5    ; Error: accepts at most 3 parameters, got 5
```

### Test Files
- `tests/examples/variadic_simple.asm` - Basic variadic test
- `tests/examples/variadic.asm` - Comprehensive variadic features
- `tests/examples/variadic_error.asm` - Minimum parameter validation
- `tests/examples/variadic_error2.asm` - Maximum parameter validation
- `tests/examples/parsing_features.asm` - All features combined

### Backward Compatibility
Fixed-parameter macros continue to work exactly as before:
```asm
%macro OLD_STYLE 2
    mov %1, %2
%endmacro
OLD_STYLE rax, rbx    ; Still works
```

## Code Size Impact

- Total lines added/modified: ~150 lines
- New functionality integrated seamlessly into existing parser
- No breaking changes to existing code
- All existing test cases still pass

## Future Considerations

### Potential Enhancements
1. **%0 Parameter**: Could add `%0` to represent actual parameter count
2. **Default Parameters**: Support `%macro NAME 1-* default_value`
3. **%{N} Syntax**: For parameters beyond %9 (if needed)

### Current Limitations
- Maximum 32 parameters can be parsed (reasonable limit)
- Empty parameters in middle of list not supported (by design)
- Parameters can only be referenced up to %9 in macro body (NASM limitation)

## Documentation Updates

Updated `README.md`:
- Moved three parsing features from "Future Enhancements" to "Recently Implemented"
- Updated "Parsing & Semantics" section to show no outstanding features
- Added comprehensive examples and test files

## Testing Summary

All features verified with:
1. **Compilation**: Clean build with only minor unused variable warnings
2. **Assembly**: All test files assemble successfully
3. **Validation**: objdump confirms correct encoding and sizes
4. **Error Handling**: Invalid usage produces clear error messages
5. **Integration**: Existing examples and smoke tests still pass

## Files Modified

### Core Implementation
- `src/assembler.c`: ~150 lines modified/added
  - Lines 658-665: macro_def structure
  - Lines 2660-2686: Times directive parsing
  - Lines 2730-2780: String quote support
  - Lines 1664-1717: Variadic macro definition parsing
  - Lines 1775-1870: Variadic macro invocation

### Documentation
- `README.md`: Future Enhancements section updated

### Test Files Added
- `tests/examples/test_strings.asm`
- `tests/examples/times_test.asm`
- `tests/examples/variadic_simple.asm`
- `tests/examples/variadic.asm`
- `tests/examples/variadic_error.asm`
- `tests/examples/variadic_error2.asm`
- `tests/examples/parsing_features.asm`

## Conclusion

All three parsing features are fully implemented, tested, and documented. The implementation maintains backward compatibility while adding powerful new assembler directives that match NASM's behavior.
