#include "assembler.h"
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_usage(const char *prog) {
    fprintf(stderr, "usage: %s <input.asm> [-o output.o]\n", prog);
}

int main(int argc, char **argv) {
    const char *input = NULL;
    const char *output = "a.o";

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-o") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "error: missing argument for -o\n");
                print_usage(argv[0]);
                return EXIT_FAILURE;
            }
            output = argv[++i];
            continue;
        }

        if (!input) {
            input = argv[i];
        } else {
            fprintf(stderr, "error: unexpected argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (!input) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    rasm_status status = assemble_file(input, output, stderr);
    if (status != RASM_OK) {
        fprintf(stderr, "assembly failed: %s\n", rasm_status_message(status));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
