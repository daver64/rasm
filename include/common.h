#ifndef RASM_COMMON_H
#define RASM_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef enum {
    ARCH_X86_16,  // 16-bit (8086, 80286, real/protected)
    ARCH_X86_32,  // 32-bit (i386, protected mode)
    ARCH_X86_64   // 64-bit (x86-64, long mode)
} target_arch;

typedef enum {
    FORMAT_ELF64,
    FORMAT_ELF32,
    FORMAT_PE64,
    FORMAT_PE32,
    FORMAT_BIN,   // Flat binary
    FORMAT_COM    // DOS COM file
} output_format;

#endif // RASM_COMMON_H
