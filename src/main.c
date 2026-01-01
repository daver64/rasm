#include "assembler.h"
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_usage(const char *prog) {
    fprintf(stderr, "usage: %s <input.asm> [-o output.o] [-l listing.lst] [-a libname.a] [input2.asm ...]\n", prog);
    fprintf(stderr, "  -o <file>    Specify output object file (default: a.o)\n");
    fprintf(stderr, "  -l <file>    Generate listing file\n");
    fprintf(stderr, "  -a <file>    Create static library archive (.a) from object file(s)\n");
}

int main(int argc, char **argv) {
    const char **inputs = NULL;
    size_t input_count = 0;
    size_t input_cap = 0;
    const char *output = "a.o";
    const char *listing = NULL;
    const char *archive = NULL;

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

        if (strcmp(argv[i], "-l") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "error: missing argument for -l\n");
                print_usage(argv[0]);
                return EXIT_FAILURE;
            }
            listing = argv[++i];
            continue;
        }

        if (strcmp(argv[i], "-a") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "error: missing argument for -a\n");
                print_usage(argv[0]);
                return EXIT_FAILURE;
            }
            archive = argv[++i];
            continue;
        }

        // Input file
        if (input_count >= input_cap) {
            input_cap = input_cap ? input_cap * 2 : 4;
            inputs = realloc(inputs, input_cap * sizeof(const char *));
            if (!inputs) {
                fprintf(stderr, "error: out of memory\n");
                return EXIT_FAILURE;
            }
        }
        inputs[input_count++] = argv[i];
    }

    if (input_count == 0) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    // For multiple files, concatenate them
    if (input_count > 1) {
        FILE *temp = tmpfile();
        if (!temp) {
            fprintf(stderr, "error: failed to create temporary file\n");
            free(inputs);
            return EXIT_FAILURE;
        }

        for (size_t i = 0; i < input_count; ++i) {
            FILE *in = fopen(inputs[i], "rb");
            if (!in) {
                fprintf(stderr, "error: failed to open %s: %s\n", inputs[i], strerror(errno));
                fclose(temp);
                free(inputs);
                return EXIT_FAILURE;
            }

            char buf[4096];
            size_t n;
            while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
                if (fwrite(buf, 1, n, temp) != n) {
                    fprintf(stderr, "error: failed to write to temp file\n");
                    fclose(in);
                    fclose(temp);
                    free(inputs);
                    return EXIT_FAILURE;
                }
            }
            fclose(in);
            
            // Add newline between files
            fprintf(temp, "\n");
        }

        rewind(temp);

        // Assemble from the concatenated temp file
        FILE *out = fopen(output, "wb");
        if (!out) {
            fprintf(stderr, "error: failed to create %s: %s\n", output, strerror(errno));
            fclose(temp);
            free(inputs);
            return EXIT_FAILURE;
        }

        FILE *lst = NULL;
        if (listing) {
            lst = fopen(listing, "w");
            if (!lst) {
                fprintf(stderr, "error: failed to create %s: %s\n", listing, strerror(errno));
                fclose(temp);
                fclose(out);
                free(inputs);
                return EXIT_FAILURE;
            }
        }

        rasm_status status = assemble_stream(temp, out, lst, stderr);
        fclose(temp);
        fclose(out);
        if (lst) fclose(lst);

        if (status != RASM_OK) {
            fprintf(stderr, "assembly failed: %s\n", rasm_status_message(status));
            free(inputs);
            return EXIT_FAILURE;
        }
    } else {
        // Single file - use assemble_file
        rasm_status status = assemble_file(inputs[0], output, listing, stderr);
        if (status != RASM_OK) {
            fprintf(stderr, "assembly failed: %s\n", rasm_status_message(status));
            free(inputs);
            return EXIT_FAILURE;
        }
    }

    // Create static library if requested
    if (archive) {
        char cmd[4096];
        snprintf(cmd, sizeof(cmd), "ar rcs %s %s", archive, output);
        int ret = system(cmd);
        if (ret != 0) {
            fprintf(stderr, "error: failed to create archive %s\n", archive);
            free(inputs);
            return EXIT_FAILURE;
        }
    }

    free(inputs);
    return EXIT_SUCCESS;
}
