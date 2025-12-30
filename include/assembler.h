#ifndef RASM_ASSEMBLER_H
#define RASM_ASSEMBLER_H

#include "common.h"

typedef enum {
    RASM_OK = 0,
    RASM_ERR_IO,
    RASM_ERR_INVALID_ARGUMENT,
    RASM_ERR_NOT_IMPLEMENTED
} rasm_status;

rasm_status assemble_file(const char *input_path, const char *output_path, FILE *log);

const char *rasm_status_message(rasm_status status);

#endif // RASM_ASSEMBLER_H
