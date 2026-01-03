#ifndef RASM_COMMON_H
#define RASM_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef enum {
    FORMAT_ELF64,
    FORMAT_PE64,
    FORMAT_PE32
} output_format;

#endif // RASM_COMMON_H
