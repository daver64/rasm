#include "assembler.h"
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static output_format detect_format_from_filename(const char *filename) {
    if (!filename) return FORMAT_ELF64;
    
    const char *ext = strrchr(filename, '.');
    if (!ext) return FORMAT_ELF64;
    
    if (strcmp(ext, ".obj") == 0) return FORMAT_PE64;  // Default .obj to 64-bit for Windows
    if (strcmp(ext, ".o") == 0) return FORMAT_ELF64;   // .o defaults to 64-bit
    if (strcmp(ext, ".bin") == 0) return FORMAT_BIN;   // Flat binary
    if (strcmp(ext, ".com") == 0) return FORMAT_COM;   // DOS COM file
    return FORMAT_ELF64; // Default
}

static target_arch default_arch_for_format(output_format fmt) {
    switch (fmt) {
        case FORMAT_ELF32:
        case FORMAT_PE32:
            return ARCH_X86_32;
        case FORMAT_BIN:
        case FORMAT_COM:
            return ARCH_X86_16;
        case FORMAT_ELF64:
        case FORMAT_PE64:
        default:
            return ARCH_X86_64;
    }
}

static void print_usage(const char *prog) {
    fprintf(stderr, "usage: %s <input.asm> [-o output] [-f format] [-m mode] [-l listing.lst] [-a libname.a] [input2.asm ...]\n", prog);
    fprintf(stderr, "  -o <file>    Specify output file (default: a.o)\n");
    fprintf(stderr, "  -f <format>  Specify output format: elf64, elf32, pe64, pe32, bin, com\n");
    fprintf(stderr, "               (default: auto-detect from extension: .o=elf64, .obj=pe64, .bin=bin, .com=com)\n");
    fprintf(stderr, "  -m <mode>    Specify target architecture: 16, 32, 64 (default: auto from format)\n");
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
    output_format format = FORMAT_ELF64;
    target_arch arch = ARCH_X86_64;
    bool format_specified = false;
    bool arch_specified = false;

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

        if (strcmp(argv[i], "-f") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "error: missing argument for -f\n");
                print_usage(argv[0]);
                return EXIT_FAILURE;
            }
            const char *fmt = argv[++i];
            if (strcmp(fmt, "elf64") == 0) {
                format = FORMAT_ELF64;
            } else if (strcmp(fmt, "elf32") == 0) {
                format = FORMAT_ELF32;
            } else if (strcmp(fmt, "pe64") == 0) {
                format = FORMAT_PE64;
            } else if (strcmp(fmt, "pe32") == 0) {
                format = FORMAT_PE32;
            } else if (strcmp(fmt, "bin") == 0 || strcmp(fmt, "binary") == 0) {
                format = FORMAT_BIN;
            } else if (strcmp(fmt, "com") == 0) {
                format = FORMAT_COM;
            } else {
                fprintf(stderr, "error: unknown format '%s'\n", fmt);
                print_usage(argv[0]);
                return EXIT_FAILURE;
            }
            format_specified = true;
            continue;
        }

        if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "-m16") == 0 || 
            strcmp(argv[i], "-m32") == 0 || strcmp(argv[i], "-m64") == 0) {
            const char *mode_str;
            if (strcmp(argv[i], "-m") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "error: missing argument for -m\n");
                    print_usage(argv[0]);
                    return EXIT_FAILURE;
                }
                mode_str = argv[++i];
            } else {
                mode_str = argv[i] + 2; // Skip "-m" prefix
            }
            
            if (strcmp(mode_str, "16") == 0) {
                arch = ARCH_X86_16;
            } else if (strcmp(mode_str, "32") == 0) {
                arch = ARCH_X86_32;
            } else if (strcmp(mode_str, "64") == 0) {
                arch = ARCH_X86_64;
            } else {
                fprintf(stderr, "error: unknown architecture mode '%s'\n", mode_str);
                print_usage(argv[0]);
                return EXIT_FAILURE;
            }
            arch_specified = true;
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

    // Auto-detect format from output filename if not specified
    if (!format_specified) {
        format = detect_format_from_filename(output);
        
        // If architecture was specified but conflicts with auto-detected format, adjust format
        if (arch_specified) {
            if (arch == ARCH_X86_32 && (format == FORMAT_ELF64 || format == FORMAT_PE64)) {
                // Change to 32-bit equivalent
                if (format == FORMAT_ELF64) format = FORMAT_ELF32;
                if (format == FORMAT_PE64) format = FORMAT_PE32;
            } else if (arch == ARCH_X86_64 && (format == FORMAT_ELF32 || format == FORMAT_PE32)) {
                // Change to 64-bit equivalent
                if (format == FORMAT_ELF32) format = FORMAT_ELF64;
                if (format == FORMAT_PE32) format = FORMAT_PE64;
            }
        }
    }
    
    // Auto-detect architecture from format if not specified
    if (!arch_specified) {
        arch = default_arch_for_format(format);
    }
    
    // Validate format/arch combinations
    if ((format == FORMAT_ELF64 || format == FORMAT_PE64) && arch != ARCH_X86_64) {
        fprintf(stderr, "error: 64-bit formats require -m64\n");
        return EXIT_FAILURE;
    }
    if ((format == FORMAT_ELF32 || format == FORMAT_PE32) && arch != ARCH_X86_32) {
        fprintf(stderr, "error: 32-bit formats require -m32\n");
        return EXIT_FAILURE;
    }
    if ((format == FORMAT_BIN || format == FORMAT_COM) && arch == ARCH_X86_64) {
        fprintf(stderr, "warning: binary/COM formats with 64-bit mode unusual, assuming 16-bit\n");
        arch = ARCH_X86_16;
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

        rasm_status status = assemble_stream(temp, out, lst, format, arch, stderr);
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
        rasm_status status = assemble_file(inputs[0], output, listing, format, arch, stderr);
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
