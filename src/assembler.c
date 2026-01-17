#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
#include "assembler.h"
#include <ctype.h>
#include <elf.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

// PE/COFF structures for Windows object files
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define IMAGE_FILE_MACHINE_I386  0x014c

#define IMAGE_SCN_CNT_CODE               0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA   0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#define IMAGE_SCN_MEM_EXECUTE            0x20000000
#define IMAGE_SCN_MEM_READ               0x40000000
#define IMAGE_SCN_MEM_WRITE              0x80000000
#define IMAGE_SCN_ALIGN_16BYTES          0x00500000
#define IMAGE_SCN_ALIGN_8BYTES           0x00400000

#define IMAGE_SYM_UNDEFINED 0
#define IMAGE_SYM_ABSOLUTE  -1
#define IMAGE_SYM_DEBUG     -2

#define IMAGE_SYM_CLASS_EXTERNAL        2
#define IMAGE_SYM_CLASS_STATIC          3
#define IMAGE_SYM_CLASS_LABEL           6
#define IMAGE_SYM_CLASS_SECTION         104

#define IMAGE_REL_AMD64_ADDR64  0x0001
#define IMAGE_REL_AMD64_ADDR32  0x0002
#define IMAGE_REL_AMD64_REL32   0x0004
#define IMAGE_REL_AMD64_REL32_1 0x0005
#define IMAGE_REL_AMD64_REL32_2 0x0006
#define IMAGE_REL_AMD64_REL32_3 0x0007
#define IMAGE_REL_AMD64_REL32_4 0x0008
#define IMAGE_REL_AMD64_REL32_5 0x0009

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} pe_file_header;

typedef struct {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} pe_section_header;

typedef struct {
    union {
        char ShortName[8];
        struct {
            uint32_t Zeros;
            uint32_t Offset;
        } Name;
    } N;
    uint32_t Value;
    int16_t  SectionNumber;
    uint16_t Type;
    uint8_t  StorageClass;
    uint8_t  NumberOfAuxSymbols;
} pe_symbol;

typedef struct {
    uint32_t VirtualAddress;
    uint32_t SymbolTableIndex;
    uint16_t Type;
} pe_relocation;

static void *xrealloc(void *ptr, size_t new_cap_bytes) {
    void *p = realloc(ptr, new_cap_bytes);
    if (!p && new_cap_bytes != 0) {
        fprintf(stderr, "fatal: out of memory\n");
        exit(EXIT_FAILURE);
    }
    return p;
}

static void vec_reserve_raw(void **data, size_t *cap, size_t elem_size, size_t need) {
    if (*cap >= need) {
        return;
    }
    size_t new_cap = *cap ? *cap * 2 : 8;
    if (new_cap < need) {
        new_cap = need;
    }
    *data = xrealloc(*data, new_cap * elem_size);
    *cap = new_cap;
}

// Forward declarations
static char *str_dup(const char *s);
static bool starts_with(const char *s, const char *prefix);

// Expression AST for symbolic expressions
typedef enum {
    EXPR_CONST,      // Constant integer
    EXPR_SYMBOL,     // Symbol reference
    EXPR_ADD,
    EXPR_SUB,
    EXPR_MUL,
    EXPR_DIV,
    EXPR_MOD,
    EXPR_SHL,
    EXPR_SHR,
    EXPR_AND,
    EXPR_OR,
    EXPR_XOR,
    EXPR_NEG,
} expr_op;

typedef struct expr_node expr_node;
struct expr_node {
    expr_op op;
    union {
        int64_t constant;
        char *symbol;
        struct {
            expr_node *left;
            expr_node *right;
        } binary;
        expr_node *unary;
    } v;
};

static expr_node *expr_new_const(int64_t val) {
    expr_node *n = malloc(sizeof(expr_node));
    if (!n) {
        fprintf(stderr, "fatal: out of memory\n");
        exit(EXIT_FAILURE);
    }
    n->op = EXPR_CONST;
    n->v.constant = val;
    return n;
}

static expr_node *expr_new_symbol(const char *name) {
    expr_node *n = malloc(sizeof(expr_node));
    if (!n) {
        fprintf(stderr, "fatal: out of memory\n");
        exit(EXIT_FAILURE);
    }
    n->op = EXPR_SYMBOL;
    n->v.symbol = str_dup(name);
    return n;
}

static expr_node *expr_new_binary(expr_op op, expr_node *left, expr_node *right) {
    expr_node *n = malloc(sizeof(expr_node));
    if (!n) {
        fprintf(stderr, "fatal: out of memory\n");
        exit(EXIT_FAILURE);
    }
    n->op = op;
    n->v.binary.left = left;
    n->v.binary.right = right;
    return n;
}

static expr_node *expr_new_unary(expr_op op, expr_node *operand) {
    expr_node *n = malloc(sizeof(expr_node));
    if (!n) {
        fprintf(stderr, "fatal: out of memory\n");
        exit(EXIT_FAILURE);
    }
    n->op = op;
    n->v.unary = operand;
    return n;
}

static void expr_free(expr_node *n) {
    if (!n) return;
    switch (n->op) {
        case EXPR_CONST:
            break;
        case EXPR_SYMBOL:
            free(n->v.symbol);
            break;
        case EXPR_ADD: case EXPR_SUB: case EXPR_MUL: case EXPR_DIV:
        case EXPR_MOD: case EXPR_SHL: case EXPR_SHR: case EXPR_AND:
        case EXPR_OR: case EXPR_XOR:
            expr_free(n->v.binary.left);
            expr_free(n->v.binary.right);
            break;
        case EXPR_NEG:
            expr_free(n->v.unary);
            break;
    }
    free(n);
}

#if 0
static expr_node *expr_clone(const expr_node *n) {
    if (!n) return NULL;
    switch (n->op) {
        case EXPR_CONST:
            return expr_new_const(n->v.constant);
        case EXPR_SYMBOL:
            return expr_new_symbol(n->v.symbol);
        case EXPR_ADD: case EXPR_SUB: case EXPR_MUL: case EXPR_DIV:
        case EXPR_MOD: case EXPR_SHL: case EXPR_SHR: case EXPR_AND:
        case EXPR_OR: case EXPR_XOR:
            return expr_new_binary(n->op, expr_clone(n->v.binary.left), expr_clone(n->v.binary.right));
        case EXPR_NEG:
            return expr_new_unary(n->op, expr_clone(n->v.unary));
    }
    return NULL;
}
#endif

typedef enum {
    OP_IMM,
    OP_REG,
    OP_SYMBOL,
    OP_MEM,
    OP_EXPR,
    OP_INVALID
} operand_kind;

typedef enum {
    // 64-bit GPRs
    REG_RAX,
    REG_RCX,
    REG_RDX,
    REG_RBX,
    REG_RSP,
    REG_RBP,
    REG_RSI,
    REG_RDI,
    REG_R8,
    REG_R9,
    REG_R10,
    REG_R11,
    REG_R12,
    REG_R13,
    REG_R14,
    REG_R15,
    REG_RIP,
    // 32-bit GPRs
    REG_EAX,
    REG_ECX,
    REG_EDX,
    REG_EBX,
    REG_ESP,
    REG_EBP,
    REG_ESI,
    REG_EDI,
    REG_R8D,
    REG_R9D,
    REG_R10D,
    REG_R11D,
    REG_R12D,
    REG_R13D,
    REG_R14D,
    REG_R15D,
    // 16-bit GPRs
    REG_AX,
    REG_CX,
    REG_DX,
    REG_BX,
    REG_SP,
    REG_BP,
    REG_SI,
    REG_DI,
    REG_R8W,
    REG_R9W,
    REG_R10W,
    REG_R11W,
    REG_R12W,
    REG_R13W,
    REG_R14W,
    REG_R15W,
    // 8-bit GPRs
    REG_AL,
    REG_CL,
    REG_DL,
    REG_BL,
    REG_SPL,
    REG_BPL,
    REG_SIL,
    REG_DIL,
    REG_R8B,
    REG_R9B,
    REG_R10B,
    REG_R11B,
    REG_R12B,
    REG_R13B,
    REG_R14B,
    REG_R15B,
    // 8-bit high byte registers (ah, bh, ch, dh)
    REG_AH,
    REG_CH,
    REG_DH,
    REG_BH,
    // Vector registers
    REG_XMM0,
    REG_XMM1,
    REG_XMM2,
    REG_XMM3,
    REG_XMM4,
    REG_XMM5,
    REG_XMM6,
    REG_XMM7,
    REG_XMM8,
    REG_XMM9,
    REG_XMM10,
    REG_XMM11,
    REG_XMM12,
    REG_XMM13,
    REG_XMM14,
    REG_XMM15,
    REG_XMM16,
    REG_XMM17,
    REG_XMM18,
    REG_XMM19,
    REG_XMM20,
    REG_XMM21,
    REG_XMM22,
    REG_XMM23,
    REG_XMM24,
    REG_XMM25,
    REG_XMM26,
    REG_XMM27,
    REG_XMM28,
    REG_XMM29,
    REG_XMM30,
    REG_XMM31,
    REG_YMM0,
    REG_YMM1,
    REG_YMM2,
    REG_YMM3,
    REG_YMM4,
    REG_YMM5,
    REG_YMM6,
    REG_YMM7,
    REG_YMM8,
    REG_YMM9,
    REG_YMM10,
    REG_YMM11,
    REG_YMM12,
    REG_YMM13,
    REG_YMM14,
    REG_YMM15,
    REG_YMM16,
    REG_YMM17,
    REG_YMM18,
    REG_YMM19,
    REG_YMM20,
    REG_YMM21,
    REG_YMM22,
    REG_YMM23,
    REG_YMM24,
    REG_YMM25,
    REG_YMM26,
    REG_YMM27,
    REG_YMM28,
    REG_YMM29,
    REG_YMM30,
    REG_YMM31,
    // Segment registers
    REG_ES,
    REG_CS,
    REG_SS,
    REG_DS,
    REG_FS,
    REG_GS,
    // Control registers
    REG_CR0,
    REG_CR1,
    REG_CR2,
    REG_CR3,
    REG_CR4,
    REG_CR8,
    // Debug registers
    REG_DR0,
    REG_DR1,
    REG_DR2,
    REG_DR3,
    REG_DR4,
    REG_DR5,
    REG_DR6,
    REG_DR7,
    // x87 FPU stack registers
    REG_ST0,
    REG_ST1,
    REG_ST2,
    REG_ST3,
    REG_ST4,
    REG_ST5,
    REG_ST6,
    REG_ST7,
    // MMX registers
    REG_MM0,
    REG_MM1,
    REG_MM2,
    REG_MM3,
    REG_MM4,
    REG_MM5,
    REG_MM6,
    REG_MM7,
    // AVX-512 ZMM registers (512-bit)
    REG_ZMM0,
    REG_ZMM1,
    REG_ZMM2,
    REG_ZMM3,
    REG_ZMM4,
    REG_ZMM5,
    REG_ZMM6,
    REG_ZMM7,
    REG_ZMM8,
    REG_ZMM9,
    REG_ZMM10,
    REG_ZMM11,
    REG_ZMM12,
    REG_ZMM13,
    REG_ZMM14,
    REG_ZMM15,
    REG_ZMM16,
    REG_ZMM17,
    REG_ZMM18,
    REG_ZMM19,
    REG_ZMM20,
    REG_ZMM21,
    REG_ZMM22,
    REG_ZMM23,
    REG_ZMM24,
    REG_ZMM25,
    REG_ZMM26,
    REG_ZMM27,
    REG_ZMM28,
    REG_ZMM29,
    REG_ZMM30,
    REG_ZMM31,
    // AVX-512 Opmask registers
    REG_K0,
    REG_K1,
    REG_K2,
    REG_K3,
    REG_K4,
    REG_K5,
    REG_K6,
    REG_K7,
    REG_INVALID
} reg_kind;

typedef struct {
    reg_kind base;
    reg_kind index;
    uint8_t scale;
    int64_t disp;
    const char *sym; // optional symbol reference
    bool rip_relative;
    reg_kind seg_override; // segment override (ES/CS/SS/DS/FS/GS or REG_INVALID)
} mem_ref;

typedef enum {
    SEC_TEXT,
    SEC_DATA,
    SEC_BSS,
    SEC_ABS    // Absolute symbols (like EQU constants)
} section_kind;

typedef enum {
    MNEM_MOV,
    MNEM_ADD,
    MNEM_SUB,
    MNEM_CMP,
    MNEM_XOR,
    MNEM_AND,
    MNEM_OR,
    MNEM_TEST,
    MNEM_LEA,
    MNEM_PUSH,
    MNEM_POP,
    MNEM_INC,
    MNEM_DEC,
    MNEM_NEG,
    MNEM_NOT,
    MNEM_SHL,
    MNEM_SAL,
    MNEM_SHR,
    MNEM_SAR,
    MNEM_MOVAPS,
    MNEM_MOVUPS,
    MNEM_MOVDQA,
    MNEM_MOVDQU,
    MNEM_ADDPS,
    MNEM_ADDPD,
    MNEM_SUBPS,
    MNEM_SUBPD,
    MNEM_MULPS,
    MNEM_MULPD,
    MNEM_DIVPS,
    MNEM_DIVPD,
    MNEM_SQRTPS,
    MNEM_SQRTPD,
    MNEM_CMPPS,
    MNEM_CMPPD,
    MNEM_XORPS,
    MNEM_XORPD,
    MNEM_MOVSS,
    MNEM_MOVSD,
    MNEM_ADDSS,
    MNEM_ADDSD,
    MNEM_SUBSS,
    MNEM_SUBSD,
    MNEM_MULSS,
    MNEM_MULSD,
    MNEM_DIVSS,
    MNEM_DIVSD,
    MNEM_SQRTSS,
    MNEM_SQRTSD,
    MNEM_COMISS,
    MNEM_COMISD,
    MNEM_UCOMISS,
    MNEM_UCOMISD,
    MNEM_CVTSS2SD,
    MNEM_CVTSD2SS,
    MNEM_CVTSI2SS,
    MNEM_CVTSI2SD,
    MNEM_CVTSS2SI,
    MNEM_CVTSD2SI,
    MNEM_CVTTSS2SI,
    MNEM_CVTTSD2SI,
    MNEM_VMOVAPS,
    MNEM_VMOVUPS,
    MNEM_VMOVDQA,
    MNEM_VMOVDQU,
    MNEM_VADDPS,
    MNEM_VADDPD,
    MNEM_VSUBPS,
    MNEM_VSUBPD,
    MNEM_VMULPS,
    MNEM_VMULPD,
    MNEM_VDIVPS,
    MNEM_VDIVPD,
    MNEM_VSQRTPS,
    MNEM_VSQRTPD,
    MNEM_VCMPPS,
    MNEM_VCMPPD,
    MNEM_VXORPS,
    MNEM_VXORPD,
    MNEM_VPTEST,
    MNEM_VROUNDPS,
    MNEM_VROUNDPD,
    MNEM_VPERMILPS,
    MNEM_VPERMILPD,
    // AVX Conversions
    MNEM_VCVTPS2PD,
    MNEM_VCVTPD2PS,
    MNEM_VCVTPS2DQ,
    MNEM_VCVTPD2DQ,
    MNEM_VCVTDQ2PS,
    MNEM_VCVTDQ2PD,
    // SSE/AVX Horizontal operations
    MNEM_HADDPS,
    MNEM_HADDPD,
    MNEM_HSUBPS,
    MNEM_HSUBPD,
    MNEM_VHADDPS,
    MNEM_VHADDPD,
    MNEM_VHSUBPS,
    MNEM_VHSUBPD,
    // SSE4.1 instructions
    MNEM_BLENDPS,
    MNEM_BLENDPD,
    MNEM_VBLENDPS,
    MNEM_VBLENDPD,
    MNEM_INSERTPS,
    MNEM_EXTRACTPS,
    MNEM_PBLENDW,
    MNEM_ROUNDSS,
    MNEM_ROUNDSD,
    MNEM_DPPS,
    MNEM_DPPD,
    // FMA instructions (FMA3)
    MNEM_VFMADD132PS,
    MNEM_VFMADD132PD,
    MNEM_VFMADD213PS,
    MNEM_VFMADD213PD,
    MNEM_VFMADD231PS,
    MNEM_VFMADD231PD,
    MNEM_VFMSUB132PS,
    MNEM_VFMSUB132PD,
    MNEM_VFMSUB213PS,
    MNEM_VFMSUB213PD,
    MNEM_VFMSUB231PS,
    MNEM_VFMSUB231PD,
    MNEM_VFNMADD132PS,
    MNEM_VFNMADD132PD,
    MNEM_VFNMADD213PS,
    MNEM_VFNMADD213PD,
    MNEM_VFNMADD231PS,
    MNEM_VFNMADD231PD,
    MNEM_VFNMSUB132PS,
    MNEM_VFNMSUB132PD,
    MNEM_VFNMSUB213PS,
    MNEM_VFNMSUB213PD,
    MNEM_VFNMSUB231PS,
    MNEM_VFNMSUB231PD,
    // AVX2 instructions  
    MNEM_VPERM2I128,
    MNEM_VPERMD,
    MNEM_VPERMQ,
    MNEM_VGATHERDPS,
    MNEM_VGATHERDPD,
    MNEM_VGATHERQPS,
    MNEM_VGATHERQPD,
    MNEM_VPMASKMOVD,
    MNEM_VPMASKMOVQ,
    // SSE/SSE2 Packed moves
    MNEM_MOVHPS,
    MNEM_MOVLPS,
    MNEM_MOVHPD,
    MNEM_MOVLPD,
    // SSE/SSE2 Unpack
    MNEM_UNPCKLPS,
    MNEM_UNPCKHPS,
    MNEM_UNPCKLPD,
    MNEM_UNPCKHPD,
    // SSE/SSE2 Shuffle
    MNEM_SHUFPS,
    MNEM_SHUFPD,
    MNEM_PSHUFW,
    MNEM_PSHUFD,
    MNEM_PSHUFHW,
    MNEM_PSHUFLW,
    // SSE/SSE2 Logical
    MNEM_ANDPS,
    MNEM_ANDPD,
    MNEM_ANDNPS,
    MNEM_ANDNPD,
    MNEM_ORPS,
    MNEM_ORPD,
    // Note: XORPS, XORPD already defined in basic SSE section above
    // SSE/SSE2 Min/Max
    MNEM_MINPS,
    MNEM_MINPD,
    MNEM_MINSS,
    MNEM_MINSD,
    MNEM_MAXPS,
    MNEM_MAXPD,
    MNEM_MAXSS,
    MNEM_MAXSD,
    // SSE Reciprocal
    MNEM_RCPPS,
    MNEM_RCPSS,
    MNEM_RSQRTPS,
    MNEM_RSQRTSS,
    // SSE/SSE2 MMX Conversions
    MNEM_CVTPI2PS,
    MNEM_CVTPS2PI,
    MNEM_CVTPI2PD,
    MNEM_CVTPD2PI,
    MNEM_CVTTPS2PI,
    MNEM_CVTTPD2PI,
    // SSE/SSE2 Masked moves
    MNEM_MASKMOVDQU,
    // SSE/SSE2 Non-temporal stores
    MNEM_MOVNTPS,
    MNEM_MOVNTPD,
    MNEM_MOVNTDQ,
    // SSE3 Instructions
    MNEM_MOVDDUP,
    MNEM_MOVSHDUP,
    MNEM_MOVSLDUP,
    MNEM_ADDSUBPS,
    MNEM_ADDSUBPD,
    // SSSE3 Instructions
    MNEM_PABSB,
    MNEM_PABSW,
    MNEM_PABSD,
    MNEM_PSIGNB,
    MNEM_PSIGNW,
    MNEM_PSIGND,
    MNEM_PALIGNR,
    MNEM_PSHUFB,
    MNEM_PMULHRSW,
    // SSE4.1 Instructions (note: pminub, pminsw, pmaxub, pmaxsw already in MMX section)
    MNEM_PMINSB,
    MNEM_PMINUW,
    MNEM_PMINUD,
    MNEM_PMINSD,
    MNEM_PMAXSB,
    MNEM_PMAXUW,
    MNEM_PMAXUD,
    MNEM_PMAXSD,
    MNEM_PMULDQ,
    MNEM_MOVNTDQA,
    MNEM_PINSRB,
    MNEM_PINSRD,
    MNEM_PINSRQ,
    MNEM_PEXTRB,
    MNEM_PEXTRD,
    MNEM_PEXTRQ,
    // SSE4.2 Instructions
    MNEM_PCMPESTRI,
    MNEM_PCMPESTRM,
    MNEM_PCMPISTRI,
    MNEM_PCMPISTRM,
    MNEM_CRC32,
    // AES-NI Instructions
    MNEM_AESENC,
    MNEM_AESENCLAST,
    MNEM_AESDEC,
    MNEM_AESDECLAST,
    MNEM_AESKEYGENASSIST,
    MNEM_AESIMC,
    // AVX-512 Foundation Instructions (subset - most commonly used)
    MNEM_VADDPS_512,
    MNEM_VADDPD_512,
    MNEM_VSUBPS_512,
    MNEM_VSUBPD_512,
    MNEM_VMULPS_512,
    MNEM_VMULPD_512,
    MNEM_VDIVPS_512,
    MNEM_VDIVPD_512,
    MNEM_VMOVAPS_512,
    MNEM_VMOVAPD_512,
    MNEM_VMOVUPS_512,
    MNEM_VMOVUPD_512,
    MNEM_VMOVDQA32,
    MNEM_VMOVDQA64,
    MNEM_VMOVDQU32,
    MNEM_VMOVDQU64,
    MNEM_VBROADCASTSS,
    MNEM_VBROADCASTSD,
    MNEM_VBROADCASTI32X4,
    MNEM_VBROADCASTI64X4,
    MNEM_VPBROADCASTD,
    MNEM_VPBROADCASTQ,
    // AVX-512 Opmask operations
    MNEM_KMOVW,
    MNEM_KMOVB,
    MNEM_KMOVQ,
    MNEM_KMOVD,
    MNEM_KANDW,
    MNEM_KANDB,
    MNEM_KANDQ,
    MNEM_KANDD,
    MNEM_KORW,
    MNEM_KORB,
    MNEM_KORQ,
    MNEM_KORD,
    MNEM_KXORW,
    MNEM_KXORB,
    MNEM_KXORQ,
    MNEM_KXORD,
    MNEM_KNOTW,
    MNEM_KNOTB,
    MNEM_KNOTQ,
    MNEM_KNOTD,
    // SSE2 Integer operations
    MNEM_PADDD,
    MNEM_PADDQ,
    MNEM_PSUBD,
    MNEM_PSUBQ,
    MNEM_PMULUDQ,
    MNEM_PMULLD,
    MNEM_PAND,
    MNEM_POR,
    MNEM_PXOR,
    MNEM_PSLLQ,
    MNEM_PSRLQ,
    MNEM_PSRAQ,
    MNEM_PCMPEQD,
    MNEM_PCMPGTD,
    // AVX Integer operations
    MNEM_VPADDD,
    MNEM_VPADDQ,
    MNEM_VPSUBD,
    MNEM_VPSUBQ,
    MNEM_VPMULUDQ,
    MNEM_VPMULLD,
    MNEM_VPAND,
    MNEM_VPOR,
    MNEM_VPXOR,
    // BMI/BMI2
    MNEM_ANDN,
    MNEM_BEXTR,
    MNEM_BLSI,
    MNEM_BLSMSK,
    MNEM_BLSR,
    MNEM_BZHI,
    MNEM_LZCNT,
    MNEM_TZCNT,
    MNEM_POPCNT,
    MNEM_PDEP,
    MNEM_PEXT,
    MNEM_RORX,
    MNEM_SARX,
    MNEM_SHLX,
    MNEM_SHRX,
    // Bit manipulation
    MNEM_BSF,
    MNEM_BSR,
    MNEM_BT,
    MNEM_BTC,
    MNEM_BTR,
    MNEM_BTS,
    MNEM_BSWAP,
    // String operations
    MNEM_MOVSB,
    MNEM_MOVSW,
    MNEM_MOVSD_STR,
    MNEM_MOVSQ,
    MNEM_STOSB,
    MNEM_STOSW,
    MNEM_STOSD,
    MNEM_STOSQ,
    MNEM_LODSB,
    MNEM_LODSW,
    MNEM_LODSD,
    MNEM_LODSQ,
    MNEM_SCASB,
    MNEM_SCASW,
    MNEM_SCASD,
    MNEM_SCASQ,
    MNEM_CMPSB,
    MNEM_CMPSW,
    MNEM_CMPSD_STR,
    MNEM_CMPSQ,
    MNEM_REP,
    MNEM_REPE,
    MNEM_REPZ,
    MNEM_REPNE,
    MNEM_REPNZ,
    MNEM_JE,
    MNEM_JNE,
    MNEM_JA,
    MNEM_JAE,
    MNEM_JB,
    MNEM_JBE,
    MNEM_JG,
    MNEM_JGE,
    MNEM_JL,
    MNEM_JLE,
    MNEM_JO,
    MNEM_JNO,
    MNEM_JS,
    MNEM_JNS,
    MNEM_JP,
    MNEM_JNP,
    MNEM_SETE,
    MNEM_SETNE,
    MNEM_SETA,
    MNEM_SETAE,
    MNEM_SETB,
    MNEM_SETBE,
    MNEM_SETG,
    MNEM_SETGE,
    MNEM_SETL,
    MNEM_SETLE,
    MNEM_SETO,
    MNEM_SETNO,
    MNEM_SETS,
    MNEM_SETNS,
    MNEM_SETP,
    MNEM_SETNP,
    MNEM_MOVZX,
    MNEM_MOVSX,
    MNEM_MOVSXD,
    MNEM_CMOVE,
    MNEM_CMOVNE,
    MNEM_CMOVA,
    MNEM_CMOVAE,
    MNEM_CMOVB,
    MNEM_CMOVBE,
    MNEM_CMOVG,
    MNEM_CMOVGE,
    MNEM_CMOVL,
    MNEM_CMOVLE,
    MNEM_CMOVO,
    MNEM_CMOVNO,
    MNEM_CMOVS,
    MNEM_CMOVNS,
    MNEM_CMOVP,
    MNEM_CMOVNP,
    MNEM_JMP,
    MNEM_CALL,
    MNEM_SYSCALL,
    MNEM_MUL,
    MNEM_IMUL,
    MNEM_DIV,
    MNEM_IDIV,
    MNEM_CQO,
    MNEM_RET,
    MNEM_NOP,
    // Rotate instructions
    MNEM_ROL,
    MNEM_ROR,
    MNEM_RCL,
    MNEM_RCR,
    // Stack frame instructions
    MNEM_ENTER,
    MNEM_LEAVE,
    // Exchange instructions
    MNEM_XCHG,
    MNEM_XADD,
    // Atomic operations
    MNEM_CMPXCHG,
    MNEM_CMPXCHG8B,
    MNEM_CMPXCHG16B,
    // Carry arithmetic
    MNEM_ADC,
    MNEM_SBB,
    // Flag manipulation
    MNEM_CLC,
    MNEM_STC,
    MNEM_CMC,
    MNEM_CLD,
    MNEM_STD,
    MNEM_CLI,
    MNEM_STI,
    MNEM_LAHF,
    MNEM_SAHF,
    MNEM_PUSHF,
    MNEM_POPF,
    MNEM_PUSHFQ,
    MNEM_POPFQ,
    // Conversion instructions
    MNEM_CDQ,
    MNEM_CDQE,
    MNEM_CBW,
    MNEM_CWDE,
    // Loop instructions
    MNEM_LOOP,
    MNEM_LOOPE,
    MNEM_LOOPZ,
    MNEM_LOOPNE,
    MNEM_LOOPNZ,
    // Miscellaneous
    MNEM_XLAT,
    MNEM_XLATB,
    MNEM_IN,
    MNEM_OUT,
    MNEM_INSB,
    MNEM_INSW,
    MNEM_INSD,
    MNEM_OUTSB,
    MNEM_OUTSW,
    MNEM_OUTSD,
    MNEM_MOVBE,
    MNEM_INT,
    MNEM_HLT,
    MNEM_PAUSE,
    MNEM_CPUID,
    MNEM_RDTSC,
    MNEM_RDTSCP,
    // Protected mode instructions
    MNEM_LGDT,
    MNEM_LIDT,
    MNEM_SGDT,
    MNEM_SIDT,
    MNEM_LTR,
    MNEM_STR,
    MNEM_LLDT,
    MNEM_SLDT,
    MNEM_LAR,
    MNEM_LSL,
    MNEM_VERR,
    MNEM_VERW,
    MNEM_CLTS,
    MNEM_LMSW,
    MNEM_SMSW,
    MNEM_INVLPG,
    MNEM_INVD,
    MNEM_WBINVD,
    // Double-precision shifts
    MNEM_SHLD,
    MNEM_SHRD,
    // Memory fences
    MNEM_MFENCE,
    MNEM_LFENCE,
    MNEM_SFENCE,
    // System instructions
    MNEM_UD2,
    MNEM_IRET,
    MNEM_IRETD,
    MNEM_IRETQ,
    MNEM_JCXZ,
    MNEM_JECXZ,
    MNEM_JRCXZ,
    MNEM_RETF,
    MNEM_SYSENTER,
    MNEM_SYSEXIT,
    MNEM_SYSRET,
    // Cache control
    MNEM_PREFETCHNTA,
    MNEM_PREFETCHT0,
    MNEM_PREFETCHT1,
    MNEM_PREFETCHT2,
    MNEM_CLFLUSH,
    MNEM_CLFLUSHOPT,
    // Random number generation
    MNEM_RDRAND,
    MNEM_RDSEED,
    // Segment register loads
    MNEM_LDS,
    MNEM_LES,
    MNEM_LFS,
    MNEM_LGS,
    MNEM_LSS,
    // BCD arithmetic
    MNEM_AAA,
    MNEM_AAD,
    MNEM_AAM,
    MNEM_AAS,
    MNEM_DAA,
    MNEM_DAS,
    // Legacy instructions
    MNEM_BOUND,
    MNEM_ARPL,
    MNEM_INTO,
    MNEM_SALC,
    // Extended state save/restore
    MNEM_XSAVE,
    MNEM_XSAVE64,
    MNEM_XRSTOR,
    MNEM_XRSTOR64,
    MNEM_XSAVEOPT,
    MNEM_XSAVEOPT64,
    MNEM_XSAVEC,
    MNEM_XSAVEC64,
    MNEM_XSAVES,
    MNEM_XSAVES64,
    MNEM_XRSTORS,
    MNEM_XRSTORS64,
    // Extended control registers
    MNEM_XGETBV,
    MNEM_XSETBV,
    // CPU monitoring
    MNEM_MONITOR,
    MNEM_MWAIT,
    // x87 FPU instructions
    // Data transfer
    MNEM_FLD,
    MNEM_FST,
    MNEM_FSTP,
    MNEM_FILD,
    MNEM_FIST,
    MNEM_FISTP,
    MNEM_FBLD,
    MNEM_FBSTP,
    MNEM_FXCH,
    // Arithmetic
    MNEM_FADD,
    MNEM_FADDP,
    MNEM_FIADD,
    MNEM_FSUB,
    MNEM_FSUBP,
    MNEM_FISUB,
    MNEM_FSUBR,
    MNEM_FSUBRP,
    MNEM_FISUBR,
    MNEM_FMUL,
    MNEM_FMULP,
    MNEM_FIMUL,
    MNEM_FDIV,
    MNEM_FDIVP,
    MNEM_FIDIV,
    MNEM_FDIVR,
    MNEM_FDIVRP,
    MNEM_FIDIVR,
    MNEM_FSQRT,
    MNEM_FSCALE,
    MNEM_FPREM,
    MNEM_FPREM1,
    MNEM_FRNDINT,
    MNEM_FXTRACT,
    MNEM_FABS,
    MNEM_FCHS,
    // Comparison
    MNEM_FCOM,
    MNEM_FCOMP,
    MNEM_FCOMPP,
    MNEM_FUCOM,
    MNEM_FUCOMP,
    MNEM_FUCOMPP,
    MNEM_FICOM,
    MNEM_FICOMP,
    MNEM_FCOMI,
    MNEM_FCOMIP,
    MNEM_FUCOMI,
    MNEM_FUCOMIP,
    MNEM_FTST,
    MNEM_FXAM,
    // Transcendental
    MNEM_FSIN,
    MNEM_FCOS,
    MNEM_FSINCOS,
    MNEM_FPTAN,
    MNEM_FPATAN,
    MNEM_F2XM1,
    MNEM_FYL2X,
    MNEM_FYL2XP1,
    // Load constants
    MNEM_FLD1,
    MNEM_FLDL2T,
    MNEM_FLDL2E,
    MNEM_FLDPI,
    MNEM_FLDLG2,
    MNEM_FLDLN2,
    MNEM_FLDZ,
    // Control
    MNEM_FINIT,
    MNEM_FNINIT,
    MNEM_FCLEX,
    MNEM_FNCLEX,
    MNEM_FSTCW,
    MNEM_FNSTCW,
    MNEM_FLDCW,
    MNEM_FSTENV,
    MNEM_FNSTENV,
    MNEM_FLDENV,
    MNEM_FSAVE,
    MNEM_FNSAVE,
    MNEM_FRSTOR,
    MNEM_FSTSW,
    MNEM_FNSTSW,
    MNEM_FINCSTP,
    MNEM_FDECSTP,
    MNEM_FFREE,
    MNEM_FFREEP,
    MNEM_FNOP,
    MNEM_FWAIT,
    // MMX instructions (note: some shared with SSE2 like PADDD, PAND, POR, etc.)
    MNEM_EMMS,
    MNEM_MOVD,
    MNEM_MOVQ,
    MNEM_PACKSSWB,
    MNEM_PACKSSDW,
    MNEM_PACKUSWB,
    MNEM_PADDB,
    MNEM_PADDW,
    MNEM_PADDSB,
    MNEM_PADDSW,
    MNEM_PADDUSB,
    MNEM_PADDUSW,
    MNEM_PANDN,
    MNEM_PCMPEQB,
    MNEM_PCMPEQW,
    MNEM_PCMPGTB,
    MNEM_PCMPGTW,
    MNEM_PMADDWD,
    MNEM_PMULHW,
    MNEM_PMULLW,
    MNEM_PSLLD,
    MNEM_PSLLW,
    MNEM_PSRAD,
    MNEM_PSRAW,
    MNEM_PSRLD,
    MNEM_PSRLW,
    MNEM_PSUBB,
    MNEM_PSUBW,
    MNEM_PSUBSB,
    MNEM_PSUBSW,
    MNEM_PSUBUSB,
    MNEM_PSUBUSW,
    MNEM_PUNPCKHBW,
    MNEM_PUNPCKHWD,
    MNEM_PUNPCKHDQ,
    MNEM_PUNPCKLBW,
    MNEM_PUNPCKLWD,
    MNEM_PUNPCKLDQ,
    MNEM_PMULHUW,
    MNEM_PAVGB,
    MNEM_PAVGW,
    MNEM_PMAXSW,
    MNEM_PMAXUB,
    MNEM_PMINSW,
    MNEM_PMINUB,
    MNEM_PMOVMSKB,
    MNEM_PSADBW,
    MNEM_PEXTRW,
    MNEM_PINSRW,
    MNEM_MASKMOVQ,
    MNEM_MOVNTQ,
    // Prefix
    MNEM_LOCK,
    MNEM_INVALID
} mnemonic;

typedef struct {
    operand_kind kind;
    union {
        uint64_t imm;
        reg_kind reg;
        const char *sym;
        mem_ref mem;
        expr_node *expr;
    } v;
} operand;

typedef enum {
    STMT_LABEL,
    STMT_INSTR,
    STMT_DATA,
    STMT_RESERVE,
    STMT_ALIGN,
    STMT_TIMES
} stmt_kind;

typedef enum {
    PREFIX_NONE = 0,
    PREFIX_LOCK = 0xF0,
    PREFIX_REPNE = 0xF2,
    PREFIX_REP = 0xF3
} instr_prefix;

typedef struct {
    mnemonic mnem;
    operand ops[4];
    size_t op_count;
    instr_prefix prefix;
    size_t line;
} instr_stmt;

typedef struct {
    size_t line;
    const char *name; // label name
} label_stmt;

typedef enum {
    DATA_DB,
    DATA_DW,
    DATA_DD,
    DATA_DQ
} data_width;

typedef struct {
    data_width width;
    operand value;
    size_t line;
} data_item;

typedef struct {
    size_t count; // bytes/words/etc to reserve
    data_width width;
    size_t line;
} reserve_stmt;

typedef struct {
    size_t align;
    size_t line;
} align_stmt;

typedef enum {
    TIMES_DATA,
    TIMES_INSTR
} times_kind;

typedef struct {
    times_kind kind;
    expr_node *count_expr;  // Expression to evaluate for repeat count
    union {
        struct {
            data_width width;
            operand value;
        } data;
        instr_stmt instr;
    } u;
    size_t line;
} times_stmt;

typedef struct {
    stmt_kind kind;
    section_kind section;
    union {
        label_stmt label;
        instr_stmt instr;
        data_item data;
        reserve_stmt res;
        align_stmt align;
        times_stmt times;
    } v;
} statement;

typedef struct {
    const char *name;
    section_kind section;
    uint64_t value;
    bool is_defined;
    bool is_global;
    bool is_extern;
} symbol;

typedef enum {
    RELOC_NONE,
    RELOC_ABS32,
    RELOC_ABS64,
    RELOC_PC32,
    RELOC_PLT32
} reloc_kind;

typedef struct {
    reloc_kind kind;
    const char *symbol; // name reference
    uint64_t offset;    // where relocation applies within section
    int64_t addend;     // addend for relocation
} relocation;

// Struct system for NASM-compatible struct definitions
typedef struct {
    char *name;      // Field name (e.g., ".x", ".y")
    size_t offset;   // Offset within struct
    size_t size;     // Size of field in bytes
} struct_field;

typedef struct {
    char *name;                    // Struct name
    struct_field *fields;          // Array of fields
    size_t field_count;
    size_t total_size;             // Total size of struct
} struct_def;

typedef struct {
    struct_def *data;
    size_t len;
    size_t cap;
} vec_struct_def;

#define VEC_STRUCT_PUSH(vec, value) do { \
    vec_struct_def *_v = &(vec); \
    vec_reserve_raw((void**)&_v->data, &_v->cap, sizeof(*_v->data), _v->len + 1); \
    _v->data[_v->len++] = (value); \
} while (0)

// Simple typed vectors
typedef struct { uint8_t *data; size_t len; size_t cap; } vec_uint8_t;
typedef struct { statement *data; size_t len; size_t cap; } vec_statement;
typedef struct { symbol *data; size_t len; size_t cap; } vec_symbol;
typedef struct { relocation *data; size_t len; size_t cap; } vec_relocation;
typedef struct { Elf64_Sym *data; size_t len; size_t cap; } vec_Elf64_Sym;

#define VEC(type) vec_##type
#define VEC_PUSH(vec, value) do { \
    __typeof__(vec) *_v = &(vec); \
    vec_reserve_raw((void**)&_v->data, &_v->cap, sizeof(*_v->data), _v->len + 1); \
    _v->data[_v->len++] = (value); \
} while (0)

typedef struct {
    VEC(statement) stmts;
    VEC(symbol) symbols;
    VEC(relocation) text_relocs;
    VEC(relocation) data_relocs;
    VEC(uint8_t) text;
    VEC(uint8_t) data;
    uint64_t bss_size;
    section_kind current_section;
    const char *current_global_label; // For local label scoping
    target_arch arch;  // Target architecture (16/32/64-bit)
    uint64_t origin;   // ORG directive - base address for position-dependent code
    vec_struct_def structs; // Struct definitions
} asm_unit;

// Macro system
typedef struct {
    char *name;
    int param_count;     // For fixed parameter macros (backward compatible)
    int min_params;      // Minimum parameters (for variadic)
    int max_params;      // Maximum parameters, or -1 for unlimited
    bool is_variadic;    // True if this is a variadic macro
    bool case_insensitive; // True for %imacro
    bool greedy;         // True for %macro+ (greedy parameters)
    char **lines;        // Body lines with %1, %2, etc.
    size_t line_count;
} macro_def;

typedef struct {
    macro_def **data;
    size_t len;
    size_t cap;
} vec_macro_def;

typedef struct {
    vec_macro_def macros;
    int expansion_counter; // For %%local labels
    
    // Phase 2: %define hash table
    struct define_entry {
        char *name;
        char *value;
        struct define_entry *next;
    } **define_table;
    size_t define_table_size;
    
    // Phase 2b: %assign variables (numeric)
    struct assign_entry {
        char *name;
        int64_t value;
        struct assign_entry *next;
    } **assign_table;
    size_t assign_table_size;
    
    // Phase 3: Conditional assembly stack
    struct {
        bool *data;
        size_t len;
        size_t cap;
    } cond_stack;  // Stack of "is this level active?"
    bool skip_mode; // Are we currently skipping lines?
    
    // Phase 4: Context stack for %push/%pop
    struct context_frame {
        char *name;
        struct define_entry **local_defines;
        size_t local_defines_size;
        struct context_frame *next;
    } *context_stack;
    
    // Phase 5: %rep loop state
    struct rep_state {
        int remaining_reps;
        size_t body_start;   // Position in source where rep body starts
        size_t body_end;     // Position where %endrep is
    } *current_rep;
} macro_ctx;

#define VEC_MACRO_PUSH(vec, value) do { \
    vec_macro_def *_v = &(vec); \
    vec_reserve_raw((void**)&_v->data, &_v->cap, sizeof(*_v->data), _v->len + 1); \
    _v->data[_v->len++] = (value); \
} while (0)

// Forward declarations
static char *read_entire_file(FILE *f, size_t *out_size);
static rasm_status parse_source(const char *src, asm_unit *unit, FILE *log);
static rasm_status first_pass_sizes(asm_unit *unit, FILE *log);
static rasm_status second_pass_encode(asm_unit *unit, FILE *log);
static rasm_status write_elf64(const asm_unit *unit, FILE *out, FILE *log);
static void free_unit(asm_unit *unit);
static const symbol *find_symbol(const asm_unit *unit, const char *name);

// Helpers
static const char *trim_leading(const char *s) {
    while (*s && isspace((unsigned char)*s)) {
        s++;
    }
    return s;
}

static char *str_dup(const char *s) {
    size_t n = strlen(s);
    char *p = malloc(n + 1);
    if (!p) {
        fprintf(stderr, "fatal: out of memory\n");
        exit(EXIT_FAILURE);
    }
    memcpy(p, s, n + 1);
    return p;
}

// Expression parser - recursive descent
typedef struct {
    const char *input;
    const char *pos;
    char error[256];
} expr_parser;

static void expr_parser_init(expr_parser *p, const char *input) {
    p->input = input;
    p->pos = input;
    p->error[0] = '\0';
}

static void expr_skip_whitespace(expr_parser *p) {
    while (*p->pos && isspace((unsigned char)*p->pos)) p->pos++;
}

static bool expr_parse_number(expr_parser *p, int64_t *out) {
    expr_skip_whitespace(p);
    const char *start = p->pos;
    int base = 10;
    
    if (starts_with(p->pos, "0x") || starts_with(p->pos, "0X")) {
        base = 16;
        p->pos += 2;
        start = p->pos;
    }
    
    if (!*p->pos || (!isdigit((unsigned char)*p->pos) && (base != 16 || !isxdigit((unsigned char)*p->pos)))) {
        p->pos = start;
        if (base == 16) p->pos -= 2;
        return false;
    }
    
    char *end = NULL;
    errno = 0;
    int64_t val = (int64_t)strtoull(p->pos, &end, base);
    if (errno != 0 || end == p->pos) {
        return false;
    }
    p->pos = end;
    *out = val;
    return true;
}

static bool expr_is_ident_start(char c) {
    return isalpha((unsigned char)c) || c == '_' || c == '.';
}

static bool expr_is_ident_cont(char c) {
    return isalnum((unsigned char)c) || c == '_' || c == '.';
}

static bool expr_parse_identifier(expr_parser *p, char *buf, size_t buf_size) {
    expr_skip_whitespace(p);
    if (!expr_is_ident_start(*p->pos)) return false;
    
    size_t i = 0;
    while (*p->pos && expr_is_ident_cont(*p->pos) && i < buf_size - 1) {
        buf[i++] = *p->pos++;
    }
    buf[i] = '\0';
    return i > 0;
}

static expr_node *expr_parse_primary(expr_parser *p);
static expr_node *expr_parse_unary(expr_parser *p);
static expr_node *expr_parse_multiplicative(expr_parser *p);
static expr_node *expr_parse_additive(expr_parser *p);
static expr_node *expr_parse_shift(expr_parser *p);
static expr_node *expr_parse_and(expr_parser *p);
static expr_node *expr_parse_xor(expr_parser *p);
static expr_node *expr_parse_or(expr_parser *p);

static expr_node *expr_parse_primary(expr_parser *p) {
    expr_skip_whitespace(p);
    
    // Try $$ (section start) or $ (current position)
    if (*p->pos == '$') {
        if (*(p->pos + 1) == '$') {
            p->pos += 2;
            return expr_new_symbol("$$");
        } else {
            p->pos++;
            return expr_new_symbol("$");
        }
    }
    
    // Try number
    int64_t num;
    if (expr_parse_number(p, &num)) {
        return expr_new_const(num);
    }
    
    // Try parenthesized expression
    if (*p->pos == '(') {
        p->pos++;
        expr_node *n = expr_parse_or(p);
        if (!n) return NULL;
        expr_skip_whitespace(p);
        if (*p->pos != ')') {
            snprintf(p->error, sizeof(p->error), "expected ')'");
            expr_free(n);
            return NULL;
        }
        p->pos++;
        return n;
    }
    
    // Try identifier/symbol
    char ident[256];
    if (expr_parse_identifier(p, ident, sizeof(ident))) {
        return expr_new_symbol(ident);
    }
    
    snprintf(p->error, sizeof(p->error), "expected number, symbol, or '('");
    return NULL;
}

static expr_node *expr_parse_unary(expr_parser *p) {
    expr_skip_whitespace(p);
    
    if (*p->pos == '-') {
        p->pos++;
        expr_node *operand = expr_parse_unary(p);
        if (!operand) return NULL;
        return expr_new_unary(EXPR_NEG, operand);
    }
    
    if (*p->pos == '+') {
        p->pos++;
        return expr_parse_unary(p);
    }
    
    if (*p->pos == '~') {
        p->pos++;
        expr_node *operand = expr_parse_unary(p);
        if (!operand) return NULL;
        // ~x is equivalent to -1 ^ x
        return expr_new_binary(EXPR_XOR, expr_new_const(-1), operand);
    }
    
    return expr_parse_primary(p);
}

static expr_node *expr_parse_multiplicative(expr_parser *p) {
    expr_node *left = expr_parse_unary(p);
    if (!left) return NULL;
    
    while (true) {
        expr_skip_whitespace(p);
        expr_op op;
        
        if (*p->pos == '*') {
            op = EXPR_MUL;
        } else if (*p->pos == '/') {
            op = EXPR_DIV;
        } else if (*p->pos == '%') {
            op = EXPR_MOD;
        } else {
            break;
        }
        
        p->pos++;
        expr_node *right = expr_parse_unary(p);
        if (!right) {
            expr_free(left);
            return NULL;
        }
        left = expr_new_binary(op, left, right);
    }
    
    return left;
}

static expr_node *expr_parse_additive(expr_parser *p) {
    expr_node *left = expr_parse_multiplicative(p);
    if (!left) return NULL;
    
    while (true) {
        expr_skip_whitespace(p);
        expr_op op;
        
        if (*p->pos == '+') {
            op = EXPR_ADD;
        } else if (*p->pos == '-') {
            op = EXPR_SUB;
        } else {
            break;
        }
        
        p->pos++;
        expr_node *right = expr_parse_multiplicative(p);
        if (!right) {
            expr_free(left);
            return NULL;
        }
        left = expr_new_binary(op, left, right);
    }
    
    return left;
}

static expr_node *expr_parse_shift(expr_parser *p) {
    expr_node *left = expr_parse_additive(p);
    if (!left) return NULL;
    
    while (true) {
        expr_skip_whitespace(p);
        expr_op op;
        
        if (p->pos[0] == '<' && p->pos[1] == '<') {
            op = EXPR_SHL;
            p->pos += 2;
        } else if (p->pos[0] == '>' && p->pos[1] == '>') {
            op = EXPR_SHR;
            p->pos += 2;
        } else {
            break;
        }
        
        expr_node *right = expr_parse_additive(p);
        if (!right) {
            expr_free(left);
            return NULL;
        }
        left = expr_new_binary(op, left, right);
    }
    
    return left;
}

static expr_node *expr_parse_and(expr_parser *p) {
    expr_node *left = expr_parse_shift(p);
    if (!left) return NULL;
    
    while (true) {
        expr_skip_whitespace(p);
        if (*p->pos != '&' || p->pos[1] == '&') break;
        
        p->pos++;
        expr_node *right = expr_parse_shift(p);
        if (!right) {
            expr_free(left);
            return NULL;
        }
        left = expr_new_binary(EXPR_AND, left, right);
    }
    
    return left;
}

static expr_node *expr_parse_xor(expr_parser *p) {
    expr_node *left = expr_parse_and(p);
    if (!left) return NULL;
    
    while (true) {
        expr_skip_whitespace(p);
        if (*p->pos != '^') break;
        
        p->pos++;
        expr_node *right = expr_parse_and(p);
        if (!right) {
            expr_free(left);
            return NULL;
        }
        left = expr_new_binary(EXPR_XOR, left, right);
    }
    
    return left;
}

static expr_node *expr_parse_or(expr_parser *p) {
    expr_node *left = expr_parse_xor(p);
    if (!left) return NULL;
    
    while (true) {
        expr_skip_whitespace(p);
        if (*p->pos != '|' || p->pos[1] == '|') break;
        
        p->pos++;
        expr_node *right = expr_parse_xor(p);
        if (!right) {
            expr_free(left);
            return NULL;
        }
        left = expr_new_binary(EXPR_OR, left, right);
    }
    
    return left;
}

static expr_node *parse_expression(const char *str) {
    expr_parser p;
    expr_parser_init(&p, str);
    expr_node *result = expr_parse_or(&p);
    if (!result) return NULL;
    
    expr_skip_whitespace(&p);
    if (*p.pos != '\0') {
        expr_free(result);
        return NULL;
    }
    
    return result;
}

// Expression evaluation with symbol resolution
static bool eval_expression(const expr_node *expr, const asm_unit *unit, int64_t *result, const char **unresolved_sym) {
    if (!expr) return false;
    
    switch (expr->op) {
        case EXPR_CONST:
            *result = expr->v.constant;
            return true;
            
        case EXPR_SYMBOL: {
            // Handle special symbols
            if (strcmp(expr->v.symbol, "$") == 0) {
                // $ = current runtime position = origin + section offset
                if (unit->current_section == SEC_TEXT) {
                    *result = (int64_t)(unit->origin + unit->text.len);
                } else if (unit->current_section == SEC_DATA) {
                    *result = (int64_t)(unit->origin + unit->data.len);
                } else {
                    *result = (int64_t)(unit->origin + unit->bss_size);
                }
                return true;
            }
            if (strcmp(expr->v.symbol, "$$") == 0) {
                // $$ = section start = origin
                *result = (int64_t)unit->origin;
                return true;
            }
            
            // Try to resolve symbol
            if (unit) {
                for (size_t i = 0; i < unit->symbols.len; ++i) {
                    if (strcmp(unit->symbols.data[i].name, expr->v.symbol) == 0) {
                        if (!unit->symbols.data[i].is_defined && !unit->symbols.data[i].is_extern) {
                            *unresolved_sym = expr->v.symbol;
                            return false;
                        }
                        *result = (int64_t)unit->symbols.data[i].value;
                        return true;
                    }
                }
            }
            // Symbol not found or not resolved yet
            *unresolved_sym = expr->v.symbol;
            return false;
        }
            
        case EXPR_NEG: {
            int64_t val;
            if (!eval_expression(expr->v.unary, unit, &val, unresolved_sym)) return false;
            *result = -val;
            return true;
        }
            
        case EXPR_ADD: case EXPR_SUB: case EXPR_MUL: case EXPR_DIV:
        case EXPR_MOD: case EXPR_SHL: case EXPR_SHR: case EXPR_AND:
        case EXPR_OR: case EXPR_XOR: {
            int64_t left, right;
            if (!eval_expression(expr->v.binary.left, unit, &left, unresolved_sym)) return false;
            if (!eval_expression(expr->v.binary.right, unit, &right, unresolved_sym)) return false;
            
            switch (expr->op) {
                case EXPR_ADD: *result = left + right; break;
                case EXPR_SUB: *result = left - right; break;
                case EXPR_MUL: *result = left * right; break;
                case EXPR_DIV:
                    if (right == 0) return false;
                    *result = left / right;
                    break;
                case EXPR_MOD:
                    if (right == 0) return false;
                    *result = left % right;
                    break;
                case EXPR_SHL: *result = left << right; break;
                case EXPR_SHR: *result = left >> right; break;
                case EXPR_AND: *result = left & right; break;
                case EXPR_OR: *result = left | right; break;
                case EXPR_XOR: *result = left ^ right; break;
                default: return false;
            }
            return true;
        }
    }
    
    return false;
}

// Macro preprocessing
static void macro_ctx_init(macro_ctx *ctx) {
    ctx->macros.data = NULL;
    ctx->macros.len = 0;
    ctx->macros.cap = 0;
    ctx->expansion_counter = 0;
    
    // Initialize define hash table
    ctx->define_table_size = 64;
    ctx->define_table = calloc(ctx->define_table_size, sizeof(struct define_entry*));
    if (!ctx->define_table) {
        fprintf(stderr, "fatal: out of memory\n");
        exit(EXIT_FAILURE);
    }
    
    // Initialize assign hash table
    ctx->assign_table_size = 64;
    ctx->assign_table = calloc(ctx->assign_table_size, sizeof(struct assign_entry*));
    if (!ctx->assign_table) {
        fprintf(stderr, "fatal: out of memory\n");
        exit(EXIT_FAILURE);
    }
    
    // Initialize conditional stack
    ctx->cond_stack.data = NULL;
    ctx->cond_stack.len = 0;
    ctx->cond_stack.cap = 0;
    ctx->skip_mode = false;
    
    // Initialize context stack
    ctx->context_stack = NULL;
    
    // Initialize rep state
    ctx->current_rep = NULL;
}

static void free_macro_def(macro_def *m) {
    if (!m) return;
    free(m->name);
    for (size_t i = 0; i < m->line_count; ++i) {
        free(m->lines[i]);
    }
    free(m->lines);
    free(m);
}

static void macro_ctx_free(macro_ctx *ctx) {
    for (size_t i = 0; i < ctx->macros.len; ++i) {
        free_macro_def(ctx->macros.data[i]);
    }
    free(ctx->macros.data);
    
    // Free define hash table
    if (ctx->define_table) {
        for (size_t i = 0; i < ctx->define_table_size; ++i) {
            struct define_entry *e = ctx->define_table[i];
            while (e) {
                struct define_entry *next = e->next;
                free(e->name);
                free(e->value);
                free(e);
                e = next;
            }
        }
        free(ctx->define_table);
    }
    
    // Free assign hash table
    if (ctx->assign_table) {
        for (size_t i = 0; i < ctx->assign_table_size; ++i) {
            struct assign_entry *e = ctx->assign_table[i];
            while (e) {
                struct assign_entry *next = e->next;
                free(e->name);
                free(e);
                e = next;
            }
        }
        free(ctx->assign_table);
    }
    
    // Free context stack
    while (ctx->context_stack) {
        struct context_frame *frame = ctx->context_stack;
        ctx->context_stack = frame->next;
        free(frame->name);
        if (frame->local_defines) {
            for (size_t i = 0; i < frame->local_defines_size; ++i) {
                struct define_entry *e = frame->local_defines[i];
                while (e) {
                    struct define_entry *next = e->next;
                    free(e->name);
                    free(e->value);
                    free(e);
                    e = next;
                }
            }
            free(frame->local_defines);
        }
        free(frame);
    }
    
    // Free rep state
    free(ctx->current_rep);
    
    // Free conditional stack
    free(ctx->cond_stack.data);
}

static macro_def *find_macro(macro_ctx *ctx, const char *name) {
    for (size_t i = 0; i < ctx->macros.len; ++i) {
        macro_def *m = ctx->macros.data[i];
        if (m->case_insensitive) {
            if (strcasecmp(m->name, name) == 0) {
                return m;
            }
        } else {
            if (strcmp(m->name, name) == 0) {
                return m;
            }
        }
    }
    return NULL;
}

// Hash function for defines
static size_t hash_string(const char *s, size_t table_size) {
    size_t hash = 5381;
    while (*s) {
        hash = ((hash << 5) + hash) + (unsigned char)*s++;
    }
    return hash % table_size;
}

// Add or update a define
static void add_define(macro_ctx *ctx, const char *name, const char *value) {
    size_t hash = hash_string(name, ctx->define_table_size);
    
    // Check if already exists
    struct define_entry *e = ctx->define_table[hash];
    while (e) {
        if (strcmp(e->name, name) == 0) {
            // Update existing
            free(e->value);
            size_t val_len = strlen(value);
            e->value = malloc(val_len + 1);
            memcpy(e->value, value, val_len + 1);
            return;
        }
        e = e->next;
    }
    
    // Add new entry
    struct define_entry *new_entry = malloc(sizeof(struct define_entry));
    if (!new_entry) {
        fprintf(stderr, "fatal: out of memory\n");
        exit(EXIT_FAILURE);
    }
    size_t name_len = strlen(name);
    size_t val_len = strlen(value);
    new_entry->name = malloc(name_len + 1);
    new_entry->value = malloc(val_len + 1);
    memcpy(new_entry->name, name, name_len + 1);
    memcpy(new_entry->value, value, val_len + 1);
    new_entry->next = ctx->define_table[hash];
    ctx->define_table[hash] = new_entry;
}

// Find a define value
static const char *find_define(macro_ctx *ctx, const char *name) {
    size_t hash = hash_string(name, ctx->define_table_size);
    struct define_entry *e = ctx->define_table[hash];
    while (e) {
        if (strcmp(e->name, name) == 0) {
            return e->value;
        }
        e = e->next;
    }
    return NULL;
}

// Add or update an assign variable
static void add_assign(macro_ctx *ctx, const char *name, int64_t value) {
    size_t hash = hash_string(name, ctx->assign_table_size);
    
    // Check if already exists
    struct assign_entry *e = ctx->assign_table[hash];
    while (e) {
        if (strcmp(e->name, name) == 0) {
            // Update existing
            e->value = value;
            return;
        }
        e = e->next;
    }
    
    // Add new entry
    struct assign_entry *new_entry = malloc(sizeof(struct assign_entry));
    if (!new_entry) {
        fprintf(stderr, "fatal: out of memory\n");
        exit(EXIT_FAILURE);
    }
    size_t name_len = strlen(name);
    new_entry->name = malloc(name_len + 1);
    memcpy(new_entry->name, name, name_len + 1);
    new_entry->value = value;
    new_entry->next = ctx->assign_table[hash];
    ctx->assign_table[hash] = new_entry;
}

// Find an assign variable
static bool find_assign(macro_ctx *ctx, const char *name, int64_t *out_value) {
    size_t hash = hash_string(name, ctx->assign_table_size);
    struct assign_entry *e = ctx->assign_table[hash];
    while (e) {
        if (strcmp(e->name, name) == 0) {
            *out_value = e->value;
            return true;
        }
        e = e->next;
    }
    return false;
}

// Evaluate an expression for %if/%elif (supports simple numeric expressions)
static bool eval_condition_expr(macro_ctx *ctx, const char *expr_str, int64_t *result) {
    // Skip leading whitespace
    while (*expr_str && isspace((unsigned char)*expr_str)) expr_str++;
    
    // Check for string functions that return numbers
    if (starts_with(expr_str, "%strlen(")) {
        const char *p = expr_str + 8; // After "%strlen("
        // Find closing paren
        const char *end = strchr(p, ')');
        if (end) {
            size_t str_len = (size_t)(end - p);
            *result = (int64_t)str_len;
            return true;
        }
    }
    
    // Make a working copy for expression evaluation
    size_t expr_len = strlen(expr_str);
    char *expr_copy = malloc(expr_len + 1);
    if (!expr_copy) return false;
    strcpy(expr_copy, expr_str);
    
    // First pass: substitute all identifiers with their values
    char *substituted = malloc(expr_len * 10); // Extra space for substitutions
    if (!substituted) {
        free(expr_copy);
        return false;
    }
    substituted[0] = '\0';
    
    const char *p = expr_copy;
    char *out = substituted;
    size_t remaining = expr_len * 10;
    
    while (*p) {
        if (isalpha((unsigned char)*p) || *p == '_') {
            // Extract identifier
            const char *id_start = p;
            while (*p && (isalnum((unsigned char)*p) || *p == '_')) p++;
            size_t id_len = (size_t)(p - id_start);
            
            char *id = malloc(id_len + 1);
            memcpy(id, id_start, id_len);
            id[id_len] = '\0';
            
            // Look up identifier value
            int64_t id_value = 0;
            if (find_assign(ctx, id, &id_value)) {
                int written = snprintf(out, remaining, "%lld", (long long)id_value);
                if (written > 0 && (size_t)written < remaining) {
                    out += written;
                    remaining -= written;
                }
            } else {
                // Keep identifier as-is (might be part of another construct)
                if (id_len < remaining) {
                    memcpy(out, id_start, id_len);
                    out += id_len;
                    remaining -= id_len;
                }
            }
            free(id);
        } else {
            if (remaining > 1) {
                *out++ = *p++;
                remaining--;
            } else {
                break;
            }
        }
    }
    *out = '\0';
    
    free(expr_copy);
    
    // Now try to evaluate the substituted expression
    const char *eval_str = substituted;
    while (*eval_str && isspace((unsigned char)*eval_str)) eval_str++;
    
    // Try to parse as simple number first
    char *end;
    errno = 0;
    int64_t val = (int64_t)strtoll(eval_str, &end, 0);
    if (errno == 0 && (*end == '\0' || isspace((unsigned char)*end))) {
        *result = val;
        free(substituted);
        return true;
    }
    
    // For more complex expressions, try basic binary operations
    // Find operator (scan from right to left for correct precedence)
    char *op_pos = NULL;
    char op = '\0';
    
    for (char *scan = substituted; *scan; scan++) {
        if (*scan == '+' || *scan == '-' || *scan == '*' || *scan == '/' || 
            *scan == '&' || *scan == '|' || *scan == '^' ||
            (*scan == '=' && *(scan+1) == '=') ||
            (*scan == '!' && *(scan+1) == '=') ||
            (*scan == '>' && *(scan+1) != '=') ||
            (*scan == '<' && *(scan+1) != '=')) {
            op_pos = scan;
            op = *scan;
        }
    }
    
    if (op_pos) {
        // Handle two-character operators
        bool is_two_char = (op == '=' || op == '!' || (op == '>' || op == '<')) && *(op_pos+1) == '=';
        
        // Split and recursively evaluate
        char saved = *op_pos;
        char saved2 = is_two_char ? *(op_pos+1) : '\0';
        *op_pos = '\0';
        
        int64_t left, right;
        bool ok1 = eval_condition_expr(ctx, substituted, &left);
        bool ok2 = eval_condition_expr(ctx, op_pos + (is_two_char ? 2 : 1), &right);
        
        *op_pos = saved;
        if (is_two_char) *(op_pos+1) = saved2;
        
        if (ok1 && ok2) {
            switch (op) {
                case '+': *result = left + right; break;
                case '-': *result = left - right; break;
                case '*': *result = left * right; break;
                case '/': *result = right != 0 ? left / right : 0; break;
                case '&': *result = left & right; break;
                case '|': *result = left | right; break;
                case '^': *result = left ^ right; break;
                case '=': *result = (left == right) ? 1 : 0; break; // ==
                case '!': *result = (left != right) ? 1 : 0; break; // !=
                case '>': *result = (left > right) ? 1 : 0; break;
                case '<': *result = (left < right) ? 1 : 0; break;
                default: 
                    free(substituted);
                    return false;
            }
            free(substituted);
            return true;
        }
    }
    
    free(substituted);
    return false;
}

// Context stack management for %push/%pop
static void context_push(macro_ctx *ctx, const char *name) {
    struct context_frame *frame = malloc(sizeof(struct context_frame));
    if (!frame) {
        fprintf(stderr, "fatal: out of memory\n");
        exit(EXIT_FAILURE);
    }
    
    frame->name = str_dup(name);
    frame->local_defines_size = 16; // Start small
    frame->local_defines = calloc(frame->local_defines_size, sizeof(struct define_entry*));
    if (!frame->local_defines) {
        fprintf(stderr, "fatal: out of memory\n");
        exit(EXIT_FAILURE);
    }
    
    // Push onto stack
    frame->next = ctx->context_stack;
    ctx->context_stack = frame;
}

static void context_pop(macro_ctx *ctx) {
    if (!ctx->context_stack) return;
    
    struct context_frame *frame = ctx->context_stack;
    ctx->context_stack = frame->next;
    
    // Free local defines
    if (frame->local_defines) {
        for (size_t i = 0; i < frame->local_defines_size; ++i) {
            struct define_entry *e = frame->local_defines[i];
            while (e) {
                struct define_entry *next = e->next;
                free(e->name);
                free(e->value);
                free(e);
                e = next;
            }
        }
        free(frame->local_defines);
    }
    
    free(frame->name);
    free(frame);
}

static const char *context_current_name(macro_ctx *ctx) {
    return ctx->context_stack ? ctx->context_stack->name : NULL;
}

// String manipulation functions for NASM compatibility
static char *eval_string_func(const char *func_call) {
    // %strlen(str) - returns length as string
    if (starts_with(func_call, "%strlen(")) {
        const char *p = func_call + 8;
        const char *end = strchr(p, ')');
        if (end) {
            size_t str_len = (size_t)(end - p);
            char *result = malloc(32);
            snprintf(result, 32, "%zu", str_len);
            return result;
        }
    }
    
    // %substr(str, start, len) - extract substring
    if (starts_with(func_call, "%substr(")) {
        const char *p = func_call + 8;
        
        // Find first comma
        const char *comma1 = strchr(p, ',');
        if (!comma1) return NULL;
        
        size_t str_len = (size_t)(comma1 - p);
        char *str = malloc(str_len + 1);
        memcpy(str, p, str_len);
        str[str_len] = '\0';
        
        // Parse start position
        p = comma1 + 1;
        while (*p && isspace((unsigned char)*p)) p++;
        int start = atoi(p);
        
        // Find second comma
        const char *comma2 = strchr(p, ',');
        if (!comma2) {
            free(str);
            return NULL;
        }
        
        // Parse length
        p = comma2 + 1;
        while (*p && isspace((unsigned char)*p)) p++;
        int len = atoi(p);
        
        // Find closing paren
        const char *end_paren = strchr(p, ')');
        if (!end_paren) {
            free(str);
            return NULL;
        }
        
        // Extract substring
        size_t actual_str_len = strlen(str);
        if (start < 0) start = 0;
        if ((size_t)start >= actual_str_len) {
            free(str);
            return str_dup("");
        }
        if (len < 0 || (size_t)(start + len) > actual_str_len) {
            len = (int)(actual_str_len - start);
        }
        
        char *result = malloc(len + 1);
        memcpy(result, str + start, len);
        result[len] = '\0';
        free(str);
        return result;
    }
    
    // %strcat(str1, str2) - concatenate strings
    if (starts_with(func_call, "%strcat(")) {
        const char *p = func_call + 8;
        
        // Find comma
        const char *comma = strchr(p, ',');
        if (!comma) return NULL;
        
        size_t str1_len = (size_t)(comma - p);
        char *str1 = malloc(str1_len + 1);
        memcpy(str1, p, str1_len);
        str1[str1_len] = '\0';
        
        // Parse second string
        p = comma + 1;
        while (*p && isspace((unsigned char)*p)) p++;
        const char *end_paren = strchr(p, ')');
        if (!end_paren) {
            free(str1);
            return NULL;
        }
        
        size_t str2_len = (size_t)(end_paren - p);
        char *str2 = malloc(str2_len + 1);
        memcpy(str2, p, str2_len);
        str2[str2_len] = '\0';
        
        // Concatenate
        char *result = malloc(str1_len + str2_len + 1);
        memcpy(result, str1, str1_len);
        memcpy(result + str1_len, str2, str2_len);
        result[str1_len + str2_len] = '\0';
        
        free(str1);
        free(str2);
        return result;
    }
    
    return NULL;
}

// Phase 3: Conditional assembly helpers
static void cond_push(macro_ctx *ctx, bool active) {
    if (ctx->cond_stack.len >= ctx->cond_stack.cap) {
        size_t new_cap = ctx->cond_stack.cap == 0 ? 8 : ctx->cond_stack.cap * 2;
        ctx->cond_stack.data = realloc(ctx->cond_stack.data, new_cap * sizeof(bool));
        if (!ctx->cond_stack.data) {
            fprintf(stderr, "fatal: out of memory\n");
            exit(EXIT_FAILURE);
        }
        ctx->cond_stack.cap = new_cap;
    }
    ctx->cond_stack.data[ctx->cond_stack.len++] = active;
    ctx->skip_mode = !active;
}

static void cond_pop(macro_ctx *ctx) {
    if (ctx->cond_stack.len > 0) {
        ctx->cond_stack.len--;
    }
    // Update skip_mode: skip if any level in stack is false
    ctx->skip_mode = false;
    for (size_t i = 0; i < ctx->cond_stack.len; ++i) {
        if (!ctx->cond_stack.data[i]) {
            ctx->skip_mode = true;
            break;
        }
    }
}

static void cond_else(macro_ctx *ctx) {
    if (ctx->cond_stack.len > 0) {
        // Flip the top of stack
        ctx->cond_stack.data[ctx->cond_stack.len - 1] = 
            !ctx->cond_stack.data[ctx->cond_stack.len - 1];
        
        // Update skip_mode
        ctx->skip_mode = false;
        for (size_t i = 0; i < ctx->cond_stack.len; ++i) {
            if (!ctx->cond_stack.data[i]) {
                ctx->skip_mode = true;
                break;
            }
        }
    }
}

static bool is_currently_active(macro_ctx *ctx) {
    return !ctx->skip_mode;
}

// Substitute defines in a line
static char *substitute_defines(macro_ctx *ctx, const char *line) {
    // Quick check: if no defines or assigns exist, return line as-is
    bool has_defines = false;
    for (size_t i = 0; i < ctx->define_table_size; ++i) {
        if (ctx->define_table[i]) {
            has_defines = true;
            break;
        }
    }
    bool has_assigns = false;
    if (!has_defines) {
        for (size_t i = 0; i < ctx->assign_table_size; ++i) {
            if (ctx->assign_table[i]) {
                has_assigns = true;
                break;
            }
        }
    }
    if (!has_defines && !has_assigns) {
        size_t len = strlen(line);
        char *result = malloc(len + 1);
        memcpy(result, line, len + 1);
        return result;
    }
    
    // Skip substitution for lines that are directives, labels, or comments
    const char *trimmed = line;
    while (*trimmed && isspace((unsigned char)*trimmed)) trimmed++;
    
    // Skip empty lines and comments
    if (*trimmed == '\0' || *trimmed == ';' || *trimmed == '#') {
        size_t len = strlen(line);
        char *result = malloc(len + 1);
        memcpy(result, line, len + 1);
        return result;
    }
    
    // Don't substitute in directive lines (section, global, extern, align, etc.)
    if (*trimmed == '.' || *trimmed == '%' ||
        starts_with(trimmed, "section ") || starts_with(trimmed, "global ") ||
        starts_with(trimmed, "extern ") || starts_with(trimmed, "align ")) {
        size_t len = strlen(line);
        char *result = malloc(len + 1);
        memcpy(result, line, len + 1);
        return result;
    }
    
    // Check if line contains ':' before any instruction (label definition)
    // Skip strings when looking for the label colon
    const char *colon = NULL;
    const char *p_colon = trimmed;
    bool in_string = false;
    char string_char = '\0';
    while (*p_colon && !colon) {
        if (!in_string && (*p_colon == '"' || *p_colon == '\'')) {
            in_string = true;
            string_char = *p_colon;
        } else if (in_string && *p_colon == string_char && (p_colon == trimmed || *(p_colon - 1) != '\\')) {
            in_string = false;
        } else if (!in_string && *p_colon == ':') {
            colon = p_colon;
        }
        if (*p_colon == ';' && !in_string) break; // Stop at comment
        p_colon++;
    }
    
    const char *space = trimmed;
    while (*space && !isspace((unsigned char)*space) && *space != ';') space++;
    
    if (colon && colon < space) {
        // This is a label definition, don't substitute
        size_t len = strlen(line);
        char *result = malloc(len + 1);
        memcpy(result, line, len + 1);
        return result;
    }
    
    size_t output_cap = strlen(line) * 2 + 256;
    char *output = malloc(output_cap);
    if (!output) {
        fprintf(stderr, "fatal: out of memory\n");
        exit(EXIT_FAILURE);
    }
    size_t output_len = 0;
    
    const char *p = line;
    while (*p) {
        // Check for string functions (%strlen, %substr, %strcat)
        if (*p == '%' && (starts_with(p, "%strlen(") || starts_with(p, "%substr(") || starts_with(p, "%strcat("))) {
            // Find the end of the function call (find matching paren)
            const char *func_start = p;
            int paren_depth = 0;
            const char *scan = p;
            while (*scan) {
                if (*scan == '(') paren_depth++;
                else if (*scan == ')') {
                    paren_depth--;
                    if (paren_depth == 0) {
                        scan++;
                        break;
                    }
                }
                scan++;
            }
            
            if (paren_depth == 0) {
                // Extract and evaluate function call
                size_t func_len = (size_t)(scan - func_start);
                char *func_call = malloc(func_len + 1);
                memcpy(func_call, func_start, func_len);
                func_call[func_len] = '\0';
                
                char *func_result = eval_string_func(func_call);
                free(func_call);
                
                if (func_result) {
                    size_t result_len = strlen(func_result);
                    while (output_len + result_len + 1 > output_cap) {
                        output_cap *= 2;
                        output = realloc(output, output_cap);
                        if (!output) {
                            fprintf(stderr, "fatal: out of memory\n");
                            exit(EXIT_FAILURE);
                        }
                    }
                    memcpy(output + output_len, func_result, result_len);
                    output_len += result_len;
                    free(func_result);
                    p = scan;
                    continue;
                }
            }
        }
        
        // Check if this looks like an identifier
        if (isalpha((unsigned char)*p) || *p == '_') {
            const char *id_start = p;
            while (*p && (isalnum((unsigned char)*p) || *p == '_')) p++;
            size_t id_len = (size_t)(p - id_start);
            
            // Check if it's a define
            char *id_buf = malloc(id_len + 1);
            memcpy(id_buf, id_start, id_len);
            id_buf[id_len] = '\0';
            
            const char *def_value = find_define(ctx, id_buf);
            
            if (def_value) {
                // Substitute with define value
                free(id_buf);
                size_t val_len = strlen(def_value);
                while (output_len + val_len + 1 > output_cap) {
                    output_cap *= 2;
                    output = realloc(output, output_cap);
                    if (!output) {
                        fprintf(stderr, "fatal: out of memory\n");
                        exit(EXIT_FAILURE);
                    }
                }
                memcpy(output + output_len, def_value, val_len);
                output_len += val_len;
            } else {
                // Check if it's an %assign variable
                int64_t assign_value;
                if (find_assign(ctx, id_buf, &assign_value)) {
                    // Substitute with numeric value
                    free(id_buf);
                    char num_buf[32];
                    int written = snprintf(num_buf, sizeof(num_buf), "%lld", (long long)assign_value);
                    if (written > 0) {
                        while (output_len + (size_t)written + 1 > output_cap) {
                            output_cap *= 2;
                            output = realloc(output, output_cap);
                            if (!output) {
                                fprintf(stderr, "fatal: out of memory\n");
                                exit(EXIT_FAILURE);
                            }
                        }
                        memcpy(output + output_len, num_buf, written);
                        output_len += written;
                    }
                } else {
                    // Keep original identifier
                    free(id_buf);
                    while (output_len + id_len + 1 > output_cap) {
                        output_cap *= 2;
                        output = realloc(output, output_cap);
                        if (!output) {
                            fprintf(stderr, "fatal: out of memory\n");
                            exit(EXIT_FAILURE);
                        }
                    }
                    memcpy(output + output_len, id_start, id_len);
                    output_len += id_len;
                }
            }
        } else {
            // Copy character as-is
            if (output_len + 2 > output_cap) {
                output_cap *= 2;
                output = realloc(output, output_cap);
                if (!output) {
                    fprintf(stderr, "fatal: out of memory\n");
                    exit(EXIT_FAILURE);
                }
            }
            output[output_len++] = *p++;
        }
    }
    
    output[output_len] = '\0';
    return output;
}

static char *substitute_macro_params(const char *line, char **params, int param_count, int expansion_id, macro_ctx *ctx) {
    // Estimate output size (conservative)
    size_t max_len = strlen(line) * 2 + 256;
    char *result = malloc(max_len);
    if (!result) {
        fprintf(stderr, "fatal: out of memory\n");
        exit(EXIT_FAILURE);
    }
    
    const char *src = line;
    char *dst = result;
    size_t remaining = max_len;
    
    while (*src) {
        if (*src == '%') {
            src++;
            if (*src == '$') {
                // %$label - context-local label
                src++;
                // Get context name
                const char *ctx_name = context_current_name(ctx);
                if (ctx_name) {
                    // Generate label: __ctx_contextname_labelname
                    const char *label_start = src;
                    while (*src && (isalnum((unsigned char)*src) || *src == '_')) src++;
                    size_t label_len = (size_t)(src - label_start);
                    
                    int written = snprintf(dst, remaining, "__ctx_%s_", ctx_name);
                    if (written < 0 || (size_t)written >= remaining) {
                        free(result);
                        return NULL;
                    }
                    dst += written;
                    remaining -= written;
                    
                    if (label_len > 0 && label_len < remaining) {
                        memcpy(dst, label_start, label_len);
                        dst += label_len;
                        remaining -= label_len;
                    }
                } else {
                    // No context, just skip
                    while (*src && (isalnum((unsigned char)*src) || *src == '_')) src++;
                }
            } else if (*src == '%') {
                // %%label - macro-local label
                src++;
                // Collect label name
                const char *label_start = src;
                while (*src && (isalnum((unsigned char)*src) || *src == '_')) src++;
                size_t label_len = (size_t)(src - label_start);
                
                // Generate unique label: __macro_N_labelname
                int written = snprintf(dst, remaining, "__macro_%d_", expansion_id);
                if (written < 0 || (size_t)written >= remaining) {
                    free(result);
                    return NULL;
                }
                dst += written;
                remaining -= written;
                
                if (label_len > 0) {
                    if (label_len >= remaining) {
                        free(result);
                        return NULL;
                    }
                    memcpy(dst, label_start, label_len);
                    dst += label_len;
                    remaining -= label_len;
                }
            } else if (*src == '0') {
                // %0 - parameter count
                src++;
                int written = snprintf(dst, remaining, "%d", param_count);
                if (written < 0 || (size_t)written >= remaining) {
                    free(result);
                    return NULL;
                }
                dst += written;
                remaining -= written;
            } else if (*src == '+') {
                // %+ - token concatenation (remove whitespace around)
                // For now, just skip it and don't add spaces
                src++;
            } else if (*src == '?') {
                // %? - macro parameter existence check
                // Syntax: %?N where N is parameter number
                src++;
                if (*src >= '1' && *src <= '9') {
                    int param_idx = *src - '1';
                    src++;
                    // Return 1 if parameter exists, 0 if not
                    char exists = (param_idx < param_count && params[param_idx]) ? '1' : '0';
                    if (remaining < 2) {
                        free(result);
                        return NULL;
                    }
                    *dst++ = exists;
                    remaining--;
                }
            } else if (*src >= '1' && *src <= '9') {
                // %N - parameter reference
                int param_idx = *src - '1';
                src++;
                if (param_idx < param_count && params[param_idx]) {
                    size_t param_len = strlen(params[param_idx]);
                    if (param_len >= remaining) {
                        free(result);
                        return NULL;
                    }
                    memcpy(dst, params[param_idx], param_len);
                    dst += param_len;
                    remaining -= param_len;
                }
            } else {
                // Just a literal %
                if (remaining < 2) {
                    free(result);
                    return NULL;
                }
                *dst++ = '%';
                remaining--;
            }
        } else {
            if (remaining < 2) {
                free(result);
                return NULL;
            }
            *dst++ = *src++;
            remaining--;
        }
    }
    
    *dst = '\0';
    return result;
}

// Helper function that preprocesses with an existing context
static char *preprocess_macros_with_ctx(const char *source, FILE *log, macro_ctx *ctx_ptr);

static char *preprocess_macros(const char *source, FILE *log) {
    macro_ctx ctx;
    macro_ctx_init(&ctx);
    
    char *result = preprocess_macros_with_ctx(source, log, &ctx);
    macro_ctx_free(&ctx);
    return result;
}

static char *preprocess_macros_with_ctx(const char *source, FILE *log, macro_ctx *ctx_ptr) {
    macro_ctx *ctx = ctx_ptr;  // Use provided context
    
    // First pass: collect macro definitions
    const char *cursor = source;
    size_t line_no = 1;
    
    // Estimate output size
    size_t output_cap = strlen(source) * 2 + 4096;
    char *output = malloc(output_cap);
    if (!output) {
        fprintf(stderr, "fatal: out of memory\n");
        exit(EXIT_FAILURE);
    }
    size_t output_len = 0;
    
    macro_def *current_macro = NULL;
    char **macro_lines_arr = NULL;
    size_t macro_lines_count = 0;
    size_t macro_lines_cap = 0;
    
    while (*cursor) {
        const char *nl = strchr(cursor, '\n');
        size_t line_len = nl ? (size_t)(nl - cursor) : strlen(cursor);
        
        char *line_buf = malloc(line_len + 1);
        if (!line_buf) {
            free(output);
            return NULL;
        }
        memcpy(line_buf, cursor, line_len);
        line_buf[line_len] = '\0';
        
        // Trim and check for macro directives
        char *p = line_buf;
        while (*p && isspace((unsigned char)*p)) p++;
        
        // Phase 3: Handle conditional directives (always process these to track nesting)
        if (starts_with(p, "%ifdef")) {
            p += 6;
            while (*p && isspace((unsigned char)*p)) p++;
            
            // Get identifier name
            const char *name_start = p;
            while (*p && !isspace((unsigned char)*p)) p++;
            size_t name_len = (size_t)(p - name_start);
            
            if (name_len > 0) {
                char *name = malloc(name_len + 1);
                memcpy(name, name_start, name_len);
                name[name_len] = '\0';
                
                bool is_defined = find_define(ctx, name) != NULL;
                free(name);
                
                // Only activate if parent context is active
                bool parent_active = is_currently_active(ctx);
                cond_push(ctx, parent_active && is_defined);
            } else {
                cond_push(ctx, false); // Malformed %ifdef
            }
            
        } else if (starts_with(p, "%ifndef")) {
            p += 7;
            while (*p && isspace((unsigned char)*p)) p++;
            
            // Get identifier name
            const char *name_start = p;
            while (*p && !isspace((unsigned char)*p)) p++;
            size_t name_len = (size_t)(p - name_start);
            
            if (name_len > 0) {
                char *name = malloc(name_len + 1);
                memcpy(name, name_start, name_len);
                name[name_len] = '\0';
                
                bool is_defined = find_define(ctx, name) != NULL;
                free(name);
                
                // Only activate if parent context is active
                bool parent_active = is_currently_active(ctx);
                cond_push(ctx, parent_active && !is_defined);
            } else {
                cond_push(ctx, false); // Malformed %ifndef
            }
            
        } else if (starts_with(p, "%if")) {
            // Expression-based conditional (not %ifdef)
            if (!isspace((unsigned char)p[3])) {
                // It's actually %ifdef or similar, skip
                goto not_if_directive;
            }
            p += 3;
            while (*p && isspace((unsigned char)*p)) p++;
            
            // Evaluate expression
            int64_t result = 0;
            bool eval_ok = eval_condition_expr(ctx, p, &result);
            
            bool parent_active = is_currently_active(ctx);
            cond_push(ctx, parent_active && eval_ok && (result != 0));
            
not_if_directive:
            ; // Empty statement to satisfy C standard
        } else if (starts_with(p, "%elif")) {
            // Expression-based elif
            p += 5;
            while (*p && isspace((unsigned char)*p)) p++;
            
            // Evaluate expression
            int64_t result = 0;
            bool eval_ok = eval_condition_expr(ctx, p, &result);
            
            // elif acts like else + if
            cond_else(ctx);
            bool was_active = is_currently_active(ctx);
            if (was_active && ctx->cond_stack.len > 0) {
                ctx->cond_stack.data[ctx->cond_stack.len - 1] = eval_ok && (result != 0);
            }
            
        } else if (starts_with(p, "%else")) {
            cond_else(ctx);
            
        } else if (starts_with(p, "%endif")) {
            cond_pop(ctx);
            
        } else if (!is_currently_active(ctx)) {
            // Skip this line if we're in inactive conditional block
            // (but continue processing to find %else/%endif)
            
        } else if (starts_with(p, "%push")) {
            // Push a new context onto the stack
            p += 5;
            while (*p && isspace((unsigned char)*p)) p++;
            
            // Get context name
            const char *name_start = p;
            while (*p && !isspace((unsigned char)*p)) p++;
            size_t name_len = (size_t)(p - name_start);
            
            if (name_len > 0) {
                char *ctx_name = malloc(name_len + 1);
                memcpy(ctx_name, name_start, name_len);
                ctx_name[name_len] = '\0';
                
                context_push(ctx, ctx_name);
                free(ctx_name);
            }
            // %push directive consumed
            
        } else if (starts_with(p, "%pop")) {
            // Pop a context from the stack
            context_pop(ctx);
            // %pop directive consumed
            
        } else if (starts_with(p, "%include")) {
            // Phase 4: Include another file
            p += 8;
            while (*p && isspace((unsigned char)*p)) p++;
            
            // Get filename (can be quoted or unquoted)
            const char *fname_start = p;
            const char *fname_end = p;
            
            if (*p == '"' || *p == '<') {
                // Quoted filename
                char quote = (*p == '"') ? '"' : '>';
                p++;
                fname_start = p;
                while (*p && *p != quote) p++;
                fname_end = p;
            } else {
                // Unquoted filename
                while (*p && !isspace((unsigned char)*p)) p++;
                fname_end = p;
            }
            
            size_t fname_len = (size_t)(fname_end - fname_start);
            if (fname_len > 0) {
                char *filename = malloc(fname_len + 1);
                memcpy(filename, fname_start, fname_len);
                filename[fname_len] = '\0';
                
                // Try to open and read the included file
                FILE *inc_file = fopen(filename, "rb");
                if (inc_file) {
                    size_t inc_size = 0;
                    char *inc_content = read_entire_file(inc_file, &inc_size);
                    fclose(inc_file);
                    
                    if (inc_content) {
                        // Recursively preprocess the included file with shared context
                        char *inc_preprocessed = preprocess_macros_with_ctx(inc_content, log, ctx);
                        free(inc_content);
                        
                        if (inc_preprocessed) {
                            // Insert preprocessed content into output
                            size_t inc_len = strlen(inc_preprocessed);
                            while (output_len + inc_len + 1 > output_cap) {
                                output_cap *= 2;
                                output = realloc(output, output_cap);
                                if (!output) {
                                    fprintf(stderr, "fatal: out of memory\n");
                                    exit(EXIT_FAILURE);
                                }
                            }
                            memcpy(output + output_len, inc_preprocessed, inc_len);
                            output_len += inc_len;
                            free(inc_preprocessed);
                        }
                    } else if (log) {
                        fprintf(log, "warning: failed to read included file: %s\n", filename);
                    }
                } else if (log) {
                    fprintf(log, "warning: failed to open included file: %s\n", filename);
                }
                
                free(filename);
            }
            // %include directive consumed
            
        } else if (starts_with(p, "%defstr")) {
            // Process %defstr directive - defines as quoted string
            p += 7;
            while (*p && isspace((unsigned char)*p)) p++;
            
            // Get define name
            const char *name_start = p;
            while (*p && !isspace((unsigned char)*p)) p++;
            size_t name_len = (size_t)(p - name_start);
            
            if (name_len > 0) {
                char *def_name = malloc(name_len + 1);
                memcpy(def_name, name_start, name_len);
                def_name[name_len] = '\0';
                
                // Skip whitespace before value
                while (*p && isspace((unsigned char)*p)) p++;
                
                // Rest of line becomes a quoted string
                size_t value_len = strlen(p);
                char *quoted_value = malloc(value_len + 3); // +2 for quotes, +1 for null
                quoted_value[0] = '"';
                memcpy(quoted_value + 1, p, value_len);
                quoted_value[value_len + 1] = '"';
                quoted_value[value_len + 2] = '\0';
                
                add_define(ctx, def_name, quoted_value);
                free(def_name);
                free(quoted_value);
            }
            // %defstr directive consumed, don't output it
            
        } else if (starts_with(p, "%deftok")) {
            // Process %deftok directive - defines as token
            p += 7;
            while (*p && isspace((unsigned char)*p)) p++;
            
            // Get define name
            const char *name_start = p;
            while (*p && !isspace((unsigned char)*p)) p++;
            size_t name_len = (size_t)(p - name_start);
            
            if (name_len > 0) {
                char *def_name = malloc(name_len + 1);
                memcpy(def_name, name_start, name_len);
                def_name[name_len] = '\0';
                
                // Skip whitespace before value
                while (*p && isspace((unsigned char)*p)) p++;
                
                // Rest of line is the value (as token, no quotes added)
                const char *value = p;
                
                add_define(ctx, def_name, value);
                free(def_name);
            }
            // %deftok directive consumed, don't output it
            
        } else if (starts_with(p, "%define")) {
            // Process %define directive
            p += 7;
            while (*p && isspace((unsigned char)*p)) p++;
            
            // Get define name
            const char *name_start = p;
            while (*p && !isspace((unsigned char)*p)) p++;
            size_t name_len = (size_t)(p - name_start);
            
            if (name_len > 0) {
                char *def_name = malloc(name_len + 1);
                memcpy(def_name, name_start, name_len);
                def_name[name_len] = '\0';
                
                // Skip whitespace before value
                while (*p && isspace((unsigned char)*p)) p++;
                
                // Rest of line is the value
                const char *value = p;
                
                add_define(ctx, def_name, value);
                free(def_name);
            }
            // %define directive consumed, don't output it
            
        } else if (starts_with(p, "%assign")) {
            // Process %assign directive (numeric assignment)
            p += 7;
            while (*p && isspace((unsigned char)*p)) p++;
            
            // Get variable name
            const char *name_start = p;
            while (*p && !isspace((unsigned char)*p)) p++;
            size_t name_len = (size_t)(p - name_start);
            
            if (name_len > 0) {
                char *var_name = malloc(name_len + 1);
                memcpy(var_name, name_start, name_len);
                var_name[name_len] = '\0';
                
                // Skip whitespace before expression
                while (*p && isspace((unsigned char)*p)) p++;
                
                // Evaluate expression
                int64_t value = 0;
                if (eval_condition_expr(ctx, p, &value)) {
                    add_assign(ctx, var_name, value);
                } else if (log) {
                    fprintf(log, "warning: failed to evaluate %%assign expression: %s\n", p);
                }
                
                free(var_name);
            }
            // %assign directive consumed, don't output it
            
        } else if (starts_with(p, "%rep")) {
            // Start repeat block
            p += 4;
            while (*p && isspace((unsigned char)*p)) p++;
            
            // Evaluate repeat count
            int64_t count = 0;
            if (eval_condition_expr(ctx, p, &count) && count > 0) {
                // Mark start of %rep block body - we'll need to capture lines until %endrep
                // For simplicity, we'll scan ahead to find %endrep, then repeat that section
                const char *rep_body_start = cursor + line_len + 1;
                const char *scan = rep_body_start;
                int rep_nesting = 1;
                const char *rep_body_end = NULL;
                
                // Find matching %endrep
                while (*scan) {
                    // Skip to next line
                    const char *line_start = scan;
                    while (*scan && *scan != '\n') scan++;
                    
                    // Check if this line contains %rep or %endrep
                    const char *check = line_start;
                    while (check < scan && isspace((unsigned char)*check)) check++;
                    
                    if (starts_with(check, "%rep")) {
                        rep_nesting++;
                    } else if (starts_with(check, "%endrep")) {
                        rep_nesting--;
                        if (rep_nesting == 0) {
                            rep_body_end = line_start;
                            break;
                        }
                    }
                    
                    if (*scan == '\n') scan++;
                }
                
                if (rep_body_end) {
                    // Extract body
                    size_t body_len = (size_t)(rep_body_end - rep_body_start);
                    char *rep_body = malloc(body_len + 1);
                    memcpy(rep_body, rep_body_start, body_len);
                    rep_body[body_len] = '\0';
                    
                    // Repeat the body 'count' times
                    for (int64_t i = 0; i < count; i++) {
                        // Preprocess the body (to handle nested macros)
                        char *expanded = preprocess_macros_with_ctx(rep_body, log, ctx);
                        if (expanded) {
                            size_t exp_len = strlen(expanded);
                            while (output_len + exp_len + 1 > output_cap) {
                                output_cap *= 2;
                                output = realloc(output, output_cap);
                                if (!output) {
                                    fprintf(stderr, "fatal: out of memory\\n");
                                    exit(EXIT_FAILURE);
                                }
                            }
                            memcpy(output + output_len, expanded, exp_len);
                            output_len += exp_len;
                            free(expanded);
                        }
                    }
                    
                    free(rep_body);
                    
                    // Skip past the %endrep
                    cursor = rep_body_end;
                    while (*cursor && *cursor != '\n') cursor++;
                    if (*cursor == '\n') cursor++;
                    line_no++;
                    continue; // Skip normal line processing
                }
            }
            // %rep directive consumed
            
        } else if (starts_with(p, "%endrep")) {
            // %endrep should be handled by %rep lookahead, but just in case
            // it's encountered standalone, ignore it
            
        } else if (starts_with(p, "proc ")) {
            // proc directive - simplified procedure macro
            // Syntax: proc name [param1, param2, ...]
            p += 5;
            while (*p && isspace((unsigned char)*p)) p++;
            
            // Get procedure name
            const char *name_start = p;
            while (*p && !isspace((unsigned char)*p) && *p != ',') p++;
            size_t name_len = (size_t)(p - name_start);
            
            if (name_len > 0) {
                // Emit label
                while (output_len + name_len + 3 > output_cap) {
                    output_cap *= 2;
                    output = realloc(output, output_cap);
                    if (!output) {
                        fprintf(stderr, "fatal: out of memory\n");
                        exit(EXIT_FAILURE);
                    }
                }
                memcpy(output + output_len, name_start, name_len);
                output_len += name_len;
                output[output_len++] = ':';
                output[output_len++] = '\n';
                
                // Emit stack frame setup
                const char *prologue = "    push rbp\n    mov rbp, rsp\n";
                size_t prologue_len = strlen(prologue);
                while (output_len + prologue_len + 1 > output_cap) {
                    output_cap *= 2;
                    output = realloc(output, output_cap);
                    if (!output) {
                        fprintf(stderr, "fatal: out of memory\n");
                        exit(EXIT_FAILURE);
                    }
                }
                memcpy(output + output_len, prologue, prologue_len);
                output_len += prologue_len;
            }
            // proc directive consumed
            
        } else if (starts_with(p, "endproc")) {
            // endproc directive - restore stack frame
            const char *epilogue = "    mov rsp, rbp\n    pop rbp\n    ret\n";
            size_t epilogue_len = strlen(epilogue);
            while (output_len + epilogue_len + 1 > output_cap) {
                output_cap *= 2;
                output = realloc(output, output_cap);
                if (!output) {
                    fprintf(stderr, "fatal: out of memory\n");
                    exit(EXIT_FAILURE);
                }
            }
            memcpy(output + output_len, epilogue, epilogue_len);
            output_len += epilogue_len;
            // endproc directive consumed
            
        } else if (starts_with(p, "%imacro") || starts_with(p, "%macro")) {
            // Start macro definition (case-sensitive or case-insensitive)
            bool case_insensitive = (p[1] == 'i');
            bool greedy = false;
            
            p += case_insensitive ? 7 : 6;
            
            // Check for + suffix (greedy)
            if (*p == '+') {
                greedy = true;
                p++;
            }
            
            while (*p && isspace((unsigned char)*p)) p++;
            
            // Get macro name
            const char *name_start = p;
            while (*p && !isspace((unsigned char)*p)) p++;
            size_t name_len = (size_t)(p - name_start);
            
            while (*p && isspace((unsigned char)*p)) p++;
            
            // Parse parameter count or range (e.g., "2" or "1-*")
            int param_count = 0;
            int min_params = 0;
            int max_params = 0;
            bool is_variadic = false;
            
            if (*p >= '0' && *p <= '9') {
                min_params = atoi(p);
                param_count = min_params; // For backward compatibility
                
                // Check for range syntax: N-M or N-*
                while (*p && *p >= '0' && *p <= '9') p++;
                if (*p == '-') {
                    p++;
                    if (*p == '*') {
                        // Variadic: N-* means minimum N parameters, unlimited max
                        is_variadic = true;
                        max_params = -1; // Unlimited
                        p++;
                    } else if (*p >= '0' && *p <= '9') {
                        // Range: N-M means minimum N, maximum M
                        max_params = atoi(p);
                        if (max_params >= min_params) {
                            is_variadic = true;
                        }
                    }
                } else {
                    // Fixed parameter count
                    max_params = min_params;
                }
            }
            
            current_macro = malloc(sizeof(macro_def));
            if (!current_macro) {
                free(line_buf);
                free(output);
                return NULL;
            }
            
            current_macro->name = malloc(name_len + 1);
            memcpy(current_macro->name, name_start, name_len);
            current_macro->name[name_len] = '\0';
            current_macro->param_count = param_count;
            current_macro->min_params = min_params;
            current_macro->max_params = max_params;
            current_macro->is_variadic = is_variadic;
            current_macro->case_insensitive = case_insensitive;
            current_macro->greedy = greedy;
            current_macro->lines = NULL;
            current_macro->line_count = 0;
            
            macro_lines_count = 0; // Reset collection
            
        } else if (starts_with(p, "%endmacro")) {
            // End macro definition
            if (current_macro) {
                // Convert collected lines to macro body
                current_macro->line_count = macro_lines_count;
                current_macro->lines = macro_lines_arr;
                
                VEC_MACRO_PUSH(ctx->macros, current_macro);
                current_macro = NULL;
                macro_lines_arr = NULL;
                macro_lines_count = 0;
                macro_lines_cap = 0;
            }
            
        } else if (current_macro) {
            // Inside macro definition - collect line
            if (macro_lines_count >= macro_lines_cap) {
                size_t new_cap = macro_lines_cap == 0 ? 8 : macro_lines_cap * 2;
                char **new_arr = realloc(macro_lines_arr, new_cap * sizeof(char*));
                if (!new_arr) {
                    free(line_buf);
                    free(output);
                    return NULL;
                }
                macro_lines_arr = new_arr;
                macro_lines_cap = new_cap;
            }
            macro_lines_arr[macro_lines_count++] = line_buf;
            line_buf = NULL; // Transfer ownership
            
        } else {
            // Regular line - check for macro invocation or pass through
            bool is_macro_call = false;
            char *call_name = NULL;
            char **params = NULL;
            
            // Try to parse as macro call
            const char *token_start = p;
            while (*p && !isspace((unsigned char)*p)) p++;
            size_t token_len = (size_t)(p - token_start);
            
            if (token_len > 0) {
                call_name = malloc(token_len + 1);
                memcpy(call_name, token_start, token_len);
                call_name[token_len] = '\0';
                
                macro_def *m = find_macro(ctx, call_name);
                if (m) {
                    is_macro_call = true;
                    
                    // Parse all parameters (up to reasonable limit)
                    int max_parse = 32; // Reasonable upper limit for parameter parsing
                    params = malloc(sizeof(char*) * max_parse);
                    for (int i = 0; i < max_parse; ++i) params[i] = NULL;
                    
                    while (*p && isspace((unsigned char)*p)) p++;
                    
                    int actual_param_count = 0;
                    while (*p && actual_param_count < max_parse) {
                        const char *param_start = p;
                        // Collect until comma or end of line
                        while (*p && *p != ',') p++;
                        
                        // Trim trailing spaces from parameter
                        const char *param_end = p;
                        while (param_end > param_start && isspace((unsigned char)*(param_end - 1))) {
                            param_end--;
                        }
                        
                        // Skip empty parameters at the end
                        if (param_end == param_start && *p == '\0') break;
                        
                        size_t param_len = (size_t)(param_end - param_start);
                        params[actual_param_count] = malloc(param_len + 1);
                        memcpy(params[actual_param_count], param_start, param_len);
                        params[actual_param_count][param_len] = '\0';
                        actual_param_count++;
                        
                        // Skip comma and spaces
                        if (*p == ',') {
                            p++;
                            while (*p && isspace((unsigned char)*p)) p++;
                        } else {
                            break;
                        }
                    }
                    
                    // Validate parameter count
                    if (m->is_variadic) {
                        if (actual_param_count < m->min_params) {
                            if (log) fprintf(log, "macro %s requires at least %d parameters, got %d\n", m->name, m->min_params, actual_param_count);
                            for (int i = 0; i < actual_param_count; ++i) free(params[i]);
                            free(params);
                            free(call_name);
                            free(line_buf);
                            free(output);
                            return NULL;
                        }
                        if (m->max_params >= 0 && actual_param_count > m->max_params) {
                            if (log) fprintf(log, "macro %s accepts at most %d parameters, got %d\n", m->name, m->max_params, actual_param_count);
                            for (int i = 0; i < actual_param_count; ++i) free(params[i]);
                            free(params);
                            free(call_name);
                            free(line_buf);
                            free(output);
                            return NULL;
                        }
                    }
                    
                    // Expand macro
                    int expansion_id = ctx->expansion_counter++;
                    for (size_t i = 0; i < m->line_count; ++i) {
                        // Check for %rotate directive in macro body
                        const char *line_check = m->lines[i];
                        while (*line_check && isspace((unsigned char)*line_check)) line_check++;
                        if (starts_with(line_check, "%rotate")) {
                            line_check += 7;
                            while (*line_check && isspace((unsigned char)*line_check)) line_check++;
                            int rotate_count = atoi(line_check);
                            if (rotate_count > 0 && actual_param_count > 0) {
                                // Rotate parameters: %1←%2, %2←%3, etc.
                                rotate_count = rotate_count % actual_param_count; // Normalize
                                for (int r = 0; r < rotate_count; r++) {
                                    char *temp = params[0];
                                    for (int j = 0; j < actual_param_count - 1; j++) {
                                        params[j] = params[j + 1];
                                    }
                                    params[actual_param_count - 1] = temp;
                                }
                            }
                            continue; // Don't output %rotate line
                        }
                        
                        char *expanded = substitute_macro_params(m->lines[i], params, actual_param_count, expansion_id, ctx);
                        if (expanded) {
                            // Apply define substitutions to expanded line
                            char *with_defines = substitute_defines(ctx, expanded);
                            free(expanded);
                            
                            size_t exp_len = strlen(with_defines);
                            // Ensure space in output
                            while (output_len + exp_len + 2 > output_cap) {
                                output_cap *= 2;
                                output = realloc(output, output_cap);
                                if (!output) {
                                    fprintf(stderr, "fatal: out of memory\n");
                                    exit(EXIT_FAILURE);
                                }
                            }
                            memcpy(output + output_len, with_defines, exp_len);
                            output_len += exp_len;
                            output[output_len++] = '\n';
                            free(with_defines);
                        }
                    }
                    
                    // Free params
                    for (int i = 0; i < actual_param_count; ++i) {
                        free(params[i]);
                    }
                    free(params);
                }
                free(call_name);
            }
            
            if (!is_macro_call) {
                // Pass through line with define substitutions
                char *substituted = substitute_defines(ctx, line_buf);
                size_t subst_len = strlen(substituted);
                
                while (output_len + subst_len + 2 > output_cap) {
                    output_cap *= 2;
                    output = realloc(output, output_cap);
                    if (!output) {
                        fprintf(stderr, "fatal: out of memory\n");
                        exit(EXIT_FAILURE);
                    }
                }
                memcpy(output + output_len, substituted, subst_len);
                output_len += subst_len;
                output[output_len++] = '\n';
                free(substituted);
            }
        }
        
        free(line_buf);
        cursor = nl ? nl + 1 : cursor + line_len;
        line_no++;
        if (!nl && !*cursor) break;
    }
    
    output[output_len] = '\0';
    return output;
}

static bool starts_with(const char *s, const char *prefix) {
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

static reg_kind parse_reg(const char *tok) {
    // 64-bit GPRs
    if (strcasecmp(tok, "rax") == 0) return REG_RAX;
    if (strcasecmp(tok, "rcx") == 0) return REG_RCX;
    if (strcasecmp(tok, "rdx") == 0) return REG_RDX;
    if (strcasecmp(tok, "rbx") == 0) return REG_RBX;
    if (strcasecmp(tok, "rsp") == 0) return REG_RSP;
    if (strcasecmp(tok, "rbp") == 0) return REG_RBP;
    if (strcasecmp(tok, "rsi") == 0) return REG_RSI;
    if (strcasecmp(tok, "rdi") == 0) return REG_RDI;
    if (strcasecmp(tok, "r8") == 0) return REG_R8;
    if (strcasecmp(tok, "r9") == 0) return REG_R9;
    if (strcasecmp(tok, "r10") == 0) return REG_R10;
    if (strcasecmp(tok, "r11") == 0) return REG_R11;
    if (strcasecmp(tok, "r12") == 0) return REG_R12;
    if (strcasecmp(tok, "r13") == 0) return REG_R13;
    if (strcasecmp(tok, "r14") == 0) return REG_R14;
    if (strcasecmp(tok, "r15") == 0) return REG_R15;
    if (strcasecmp(tok, "rip") == 0) return REG_RIP;
    // 32-bit GPRs
    if (strcasecmp(tok, "eax") == 0) return REG_EAX;
    if (strcasecmp(tok, "ecx") == 0) return REG_ECX;
    if (strcasecmp(tok, "edx") == 0) return REG_EDX;
    if (strcasecmp(tok, "ebx") == 0) return REG_EBX;
    if (strcasecmp(tok, "esp") == 0) return REG_ESP;
    if (strcasecmp(tok, "ebp") == 0) return REG_EBP;
    if (strcasecmp(tok, "esi") == 0) return REG_ESI;
    if (strcasecmp(tok, "edi") == 0) return REG_EDI;
    if (strcasecmp(tok, "r8d") == 0) return REG_R8D;
    if (strcasecmp(tok, "r9d") == 0) return REG_R9D;
    if (strcasecmp(tok, "r10d") == 0) return REG_R10D;
    if (strcasecmp(tok, "r11d") == 0) return REG_R11D;
    if (strcasecmp(tok, "r12d") == 0) return REG_R12D;
    if (strcasecmp(tok, "r13d") == 0) return REG_R13D;
    if (strcasecmp(tok, "r14d") == 0) return REG_R14D;
    if (strcasecmp(tok, "r15d") == 0) return REG_R15D;
    // 16-bit GPRs
    if (strcasecmp(tok, "ax") == 0) return REG_AX;
    if (strcasecmp(tok, "cx") == 0) return REG_CX;
    if (strcasecmp(tok, "dx") == 0) return REG_DX;
    if (strcasecmp(tok, "bx") == 0) return REG_BX;
    if (strcasecmp(tok, "sp") == 0) return REG_SP;
    if (strcasecmp(tok, "bp") == 0) return REG_BP;
    if (strcasecmp(tok, "si") == 0) return REG_SI;
    if (strcasecmp(tok, "di") == 0) return REG_DI;
    if (strcasecmp(tok, "r8w") == 0) return REG_R8W;
    if (strcasecmp(tok, "r9w") == 0) return REG_R9W;
    if (strcasecmp(tok, "r10w") == 0) return REG_R10W;
    if (strcasecmp(tok, "r11w") == 0) return REG_R11W;
    if (strcasecmp(tok, "r12w") == 0) return REG_R12W;
    if (strcasecmp(tok, "r13w") == 0) return REG_R13W;
    if (strcasecmp(tok, "r14w") == 0) return REG_R14W;
    if (strcasecmp(tok, "r15w") == 0) return REG_R15W;
    // 8-bit GPRs
    if (strcasecmp(tok, "al") == 0) return REG_AL;
    if (strcasecmp(tok, "cl") == 0) return REG_CL;
    if (strcasecmp(tok, "dl") == 0) return REG_DL;
    if (strcasecmp(tok, "bl") == 0) return REG_BL;
    if (strcasecmp(tok, "spl") == 0) return REG_SPL;
    if (strcasecmp(tok, "bpl") == 0) return REG_BPL;
    if (strcasecmp(tok, "sil") == 0) return REG_SIL;
    if (strcasecmp(tok, "dil") == 0) return REG_DIL;
    if (strcasecmp(tok, "r8b") == 0) return REG_R8B;
    if (strcasecmp(tok, "r9b") == 0) return REG_R9B;
    if (strcasecmp(tok, "r10b") == 0) return REG_R10B;
    if (strcasecmp(tok, "r11b") == 0) return REG_R11B;
    if (strcasecmp(tok, "r12b") == 0) return REG_R12B;
    if (strcasecmp(tok, "r13b") == 0) return REG_R13B;
    if (strcasecmp(tok, "r14b") == 0) return REG_R14B;
    if (strcasecmp(tok, "r15b") == 0) return REG_R15B;
    // 8-bit high byte registers
    if (strcasecmp(tok, "ah") == 0) return REG_AH;
    if (strcasecmp(tok, "ch") == 0) return REG_CH;
    if (strcasecmp(tok, "dh") == 0) return REG_DH;
    if (strcasecmp(tok, "bh") == 0) return REG_BH;
    if (strncasecmp(tok, "xmm", 3) == 0) {
        int n = atoi(tok + 3);
        if (n >= 0 && n <= 31) return (reg_kind)(REG_XMM0 + n);
    }
    if (strncasecmp(tok, "ymm", 3) == 0) {
        int n = atoi(tok + 3);
        if (n >= 0 && n <= 31) return (reg_kind)(REG_YMM0 + n);
    }
    // Segment registers
    if (strcasecmp(tok, "es") == 0) return REG_ES;
    if (strcasecmp(tok, "cs") == 0) return REG_CS;
    if (strcasecmp(tok, "ss") == 0) return REG_SS;
    if (strcasecmp(tok, "ds") == 0) return REG_DS;
    if (strcasecmp(tok, "fs") == 0) return REG_FS;
    if (strcasecmp(tok, "gs") == 0) return REG_GS;
    // Control registers
    if (strcasecmp(tok, "cr0") == 0) return REG_CR0;
    if (strcasecmp(tok, "cr1") == 0) return REG_CR1;
    if (strcasecmp(tok, "cr2") == 0) return REG_CR2;
    if (strcasecmp(tok, "cr3") == 0) return REG_CR3;
    if (strcasecmp(tok, "cr4") == 0) return REG_CR4;
    if (strcasecmp(tok, "cr8") == 0) return REG_CR8;
    // Debug registers
    if (strcasecmp(tok, "dr0") == 0) return REG_DR0;
    if (strcasecmp(tok, "dr1") == 0) return REG_DR1;
    if (strcasecmp(tok, "dr2") == 0) return REG_DR2;
    if (strcasecmp(tok, "dr3") == 0) return REG_DR3;
    if (strcasecmp(tok, "dr4") == 0) return REG_DR4;
    if (strcasecmp(tok, "dr5") == 0) return REG_DR5;
    if (strcasecmp(tok, "dr6") == 0) return REG_DR6;
    if (strcasecmp(tok, "dr7") == 0) return REG_DR7;
    // x87 FPU registers
    if (strcasecmp(tok, "st0") == 0 || strcasecmp(tok, "st(0)") == 0 || strcasecmp(tok, "st") == 0) return REG_ST0;
    if (strcasecmp(tok, "st1") == 0 || strcasecmp(tok, "st(1)") == 0) return REG_ST1;
    if (strcasecmp(tok, "st2") == 0 || strcasecmp(tok, "st(2)") == 0) return REG_ST2;
    if (strcasecmp(tok, "st3") == 0 || strcasecmp(tok, "st(3)") == 0) return REG_ST3;
    if (strcasecmp(tok, "st4") == 0 || strcasecmp(tok, "st(4)") == 0) return REG_ST4;
    if (strcasecmp(tok, "st5") == 0 || strcasecmp(tok, "st(5)") == 0) return REG_ST5;
    if (strcasecmp(tok, "st6") == 0 || strcasecmp(tok, "st(6)") == 0) return REG_ST6;
    if (strcasecmp(tok, "st7") == 0 || strcasecmp(tok, "st(7)") == 0) return REG_ST7;
    // MMX registers
    if (strcasecmp(tok, "mm0") == 0) return REG_MM0;
    if (strcasecmp(tok, "mm1") == 0) return REG_MM1;
    if (strcasecmp(tok, "mm2") == 0) return REG_MM2;
    if (strcasecmp(tok, "mm3") == 0) return REG_MM3;
    if (strcasecmp(tok, "mm4") == 0) return REG_MM4;
    if (strcasecmp(tok, "mm5") == 0) return REG_MM5;
    if (strcasecmp(tok, "mm6") == 0) return REG_MM6;
    if (strcasecmp(tok, "mm7") == 0) return REG_MM7;
    // AVX-512 ZMM registers
    if (strcasecmp(tok, "zmm0") == 0) return REG_ZMM0;
    if (strcasecmp(tok, "zmm1") == 0) return REG_ZMM1;
    if (strcasecmp(tok, "zmm2") == 0) return REG_ZMM2;
    if (strcasecmp(tok, "zmm3") == 0) return REG_ZMM3;
    if (strcasecmp(tok, "zmm4") == 0) return REG_ZMM4;
    if (strcasecmp(tok, "zmm5") == 0) return REG_ZMM5;
    if (strcasecmp(tok, "zmm6") == 0) return REG_ZMM6;
    if (strcasecmp(tok, "zmm7") == 0) return REG_ZMM7;
    if (strcasecmp(tok, "zmm8") == 0) return REG_ZMM8;
    if (strcasecmp(tok, "zmm9") == 0) return REG_ZMM9;
    if (strcasecmp(tok, "zmm10") == 0) return REG_ZMM10;
    if (strcasecmp(tok, "zmm11") == 0) return REG_ZMM11;
    if (strcasecmp(tok, "zmm12") == 0) return REG_ZMM12;
    if (strcasecmp(tok, "zmm13") == 0) return REG_ZMM13;
    if (strcasecmp(tok, "zmm14") == 0) return REG_ZMM14;
    if (strcasecmp(tok, "zmm15") == 0) return REG_ZMM15;
    if (strcasecmp(tok, "zmm16") == 0) return REG_ZMM16;
    if (strcasecmp(tok, "zmm17") == 0) return REG_ZMM17;
    if (strcasecmp(tok, "zmm18") == 0) return REG_ZMM18;
    if (strcasecmp(tok, "zmm19") == 0) return REG_ZMM19;
    if (strcasecmp(tok, "zmm20") == 0) return REG_ZMM20;
    if (strcasecmp(tok, "zmm21") == 0) return REG_ZMM21;
    if (strcasecmp(tok, "zmm22") == 0) return REG_ZMM22;
    if (strcasecmp(tok, "zmm23") == 0) return REG_ZMM23;
    if (strcasecmp(tok, "zmm24") == 0) return REG_ZMM24;
    if (strcasecmp(tok, "zmm25") == 0) return REG_ZMM25;
    if (strcasecmp(tok, "zmm26") == 0) return REG_ZMM26;
    if (strcasecmp(tok, "zmm27") == 0) return REG_ZMM27;
    if (strcasecmp(tok, "zmm28") == 0) return REG_ZMM28;
    if (strcasecmp(tok, "zmm29") == 0) return REG_ZMM29;
    if (strcasecmp(tok, "zmm30") == 0) return REG_ZMM30;
    if (strcasecmp(tok, "zmm31") == 0) return REG_ZMM31;
    // AVX-512 Opmask registers
    if (strcasecmp(tok, "k0") == 0) return REG_K0;
    if (strcasecmp(tok, "k1") == 0) return REG_K1;
    if (strcasecmp(tok, "k2") == 0) return REG_K2;
    if (strcasecmp(tok, "k3") == 0) return REG_K3;
    if (strcasecmp(tok, "k4") == 0) return REG_K4;
    if (strcasecmp(tok, "k5") == 0) return REG_K5;
    if (strcasecmp(tok, "k6") == 0) return REG_K6;
    if (strcasecmp(tok, "k7") == 0) return REG_K7;
    return REG_INVALID;
}

static mnemonic parse_mnemonic(const char *tok) {
    if (strcasecmp(tok, "mov") == 0) return MNEM_MOV;
    if (strcasecmp(tok, "add") == 0) return MNEM_ADD;
    if (strcasecmp(tok, "sub") == 0) return MNEM_SUB;
    if (strcasecmp(tok, "cmp") == 0) return MNEM_CMP;
    if (strcasecmp(tok, "xor") == 0) return MNEM_XOR;
    if (strcasecmp(tok, "and") == 0) return MNEM_AND;
    if (strcasecmp(tok, "or") == 0) return MNEM_OR;
    if (strcasecmp(tok, "test") == 0) return MNEM_TEST;
    if (strcasecmp(tok, "lea") == 0) return MNEM_LEA;
    if (strcasecmp(tok, "push") == 0) return MNEM_PUSH;
    if (strcasecmp(tok, "pop") == 0) return MNEM_POP;
    if (strcasecmp(tok, "inc") == 0) return MNEM_INC;
    if (strcasecmp(tok, "dec") == 0) return MNEM_DEC;
    if (strcasecmp(tok, "neg") == 0) return MNEM_NEG;
    if (strcasecmp(tok, "not") == 0) return MNEM_NOT;
    if (strcasecmp(tok, "shl") == 0) return MNEM_SHL;
    if (strcasecmp(tok, "sal") == 0) return MNEM_SAL;
    if (strcasecmp(tok, "shr") == 0) return MNEM_SHR;
    if (strcasecmp(tok, "sar") == 0) return MNEM_SAR;
    if (strcasecmp(tok, "movaps") == 0) return MNEM_MOVAPS;
    if (strcasecmp(tok, "movups") == 0) return MNEM_MOVUPS;
    if (strcasecmp(tok, "movdqa") == 0) return MNEM_MOVDQA;
    if (strcasecmp(tok, "movdqu") == 0) return MNEM_MOVDQU;
    if (strcasecmp(tok, "addps") == 0) return MNEM_ADDPS;
    if (strcasecmp(tok, "addpd") == 0) return MNEM_ADDPD;
    if (strcasecmp(tok, "subps") == 0) return MNEM_SUBPS;
    if (strcasecmp(tok, "subpd") == 0) return MNEM_SUBPD;
    if (strcasecmp(tok, "mulps") == 0) return MNEM_MULPS;
    if (strcasecmp(tok, "mulpd") == 0) return MNEM_MULPD;
    if (strcasecmp(tok, "divps") == 0) return MNEM_DIVPS;
    if (strcasecmp(tok, "divpd") == 0) return MNEM_DIVPD;
    if (strcasecmp(tok, "sqrtps") == 0) return MNEM_SQRTPS;
    if (strcasecmp(tok, "sqrtpd") == 0) return MNEM_SQRTPD;
    if (strcasecmp(tok, "cmpps") == 0) return MNEM_CMPPS;
    if (strcasecmp(tok, "cmppd") == 0) return MNEM_CMPPD;
    if (strcasecmp(tok, "xorps") == 0) return MNEM_XORPS;
    if (strcasecmp(tok, "xorpd") == 0) return MNEM_XORPD;
    if (strcasecmp(tok, "movss") == 0) return MNEM_MOVSS;
    if (strcasecmp(tok, "movsd") == 0) return MNEM_MOVSD;
    if (strcasecmp(tok, "addss") == 0) return MNEM_ADDSS;
    if (strcasecmp(tok, "addsd") == 0) return MNEM_ADDSD;
    if (strcasecmp(tok, "subss") == 0) return MNEM_SUBSS;
    if (strcasecmp(tok, "subsd") == 0) return MNEM_SUBSD;
    if (strcasecmp(tok, "mulss") == 0) return MNEM_MULSS;
    if (strcasecmp(tok, "mulsd") == 0) return MNEM_MULSD;
    if (strcasecmp(tok, "divss") == 0) return MNEM_DIVSS;
    if (strcasecmp(tok, "divsd") == 0) return MNEM_DIVSD;
    if (strcasecmp(tok, "sqrtss") == 0) return MNEM_SQRTSS;
    if (strcasecmp(tok, "sqrtsd") == 0) return MNEM_SQRTSD;
    if (strcasecmp(tok, "comiss") == 0) return MNEM_COMISS;
    if (strcasecmp(tok, "comisd") == 0) return MNEM_COMISD;
    if (strcasecmp(tok, "ucomiss") == 0) return MNEM_UCOMISS;
    if (strcasecmp(tok, "ucomisd") == 0) return MNEM_UCOMISD;
    if (strcasecmp(tok, "cvtss2sd") == 0) return MNEM_CVTSS2SD;
    if (strcasecmp(tok, "cvtsd2ss") == 0) return MNEM_CVTSD2SS;
    if (strcasecmp(tok, "cvtsi2ss") == 0) return MNEM_CVTSI2SS;
    if (strcasecmp(tok, "cvtsi2sd") == 0) return MNEM_CVTSI2SD;
    if (strcasecmp(tok, "cvtss2si") == 0) return MNEM_CVTSS2SI;
    if (strcasecmp(tok, "cvtsd2si") == 0) return MNEM_CVTSD2SI;
    if (strcasecmp(tok, "cvttss2si") == 0) return MNEM_CVTTSS2SI;
    if (strcasecmp(tok, "cvttsd2si") == 0) return MNEM_CVTTSD2SI;
    if (strcasecmp(tok, "vmovaps") == 0) return MNEM_VMOVAPS;
    if (strcasecmp(tok, "vmovups") == 0) return MNEM_VMOVUPS;
    if (strcasecmp(tok, "vmovdqa") == 0) return MNEM_VMOVDQA;
    if (strcasecmp(tok, "vmovdqu") == 0) return MNEM_VMOVDQU;
    if (strcasecmp(tok, "vaddps") == 0) return MNEM_VADDPS;
    if (strcasecmp(tok, "vaddpd") == 0) return MNEM_VADDPD;
    if (strcasecmp(tok, "vsubps") == 0) return MNEM_VSUBPS;
    if (strcasecmp(tok, "vsubpd") == 0) return MNEM_VSUBPD;
    if (strcasecmp(tok, "vmulps") == 0) return MNEM_VMULPS;
    if (strcasecmp(tok, "vmulpd") == 0) return MNEM_VMULPD;
    if (strcasecmp(tok, "vdivps") == 0) return MNEM_VDIVPS;
    if (strcasecmp(tok, "vdivpd") == 0) return MNEM_VDIVPD;
    if (strcasecmp(tok, "vsqrtps") == 0) return MNEM_VSQRTPS;
    if (strcasecmp(tok, "vsqrtpd") == 0) return MNEM_VSQRTPD;
    if (strcasecmp(tok, "vcmpps") == 0) return MNEM_VCMPPS;
    if (strcasecmp(tok, "vcmppd") == 0) return MNEM_VCMPPD;
    if (strcasecmp(tok, "vxorps") == 0) return MNEM_VXORPS;
    if (strcasecmp(tok, "vxorpd") == 0) return MNEM_VXORPD;
    if (strcasecmp(tok, "vptest") == 0) return MNEM_VPTEST;
    if (strcasecmp(tok, "vroundps") == 0) return MNEM_VROUNDPS;
    if (strcasecmp(tok, "vroundpd") == 0) return MNEM_VROUNDPD;
    if (strcasecmp(tok, "vpermilps") == 0) return MNEM_VPERMILPS;
    if (strcasecmp(tok, "vpermilpd") == 0) return MNEM_VPERMILPD;
    // AVX Conversions
    if (strcasecmp(tok, "vcvtps2pd") == 0) return MNEM_VCVTPS2PD;
    if (strcasecmp(tok, "vcvtpd2ps") == 0) return MNEM_VCVTPD2PS;
    if (strcasecmp(tok, "vcvtps2dq") == 0) return MNEM_VCVTPS2DQ;
    if (strcasecmp(tok, "vcvtpd2dq") == 0) return MNEM_VCVTPD2DQ;
    if (strcasecmp(tok, "vcvtdq2ps") == 0) return MNEM_VCVTDQ2PS;
    if (strcasecmp(tok, "vcvtdq2pd") == 0) return MNEM_VCVTDQ2PD;
    // Horizontal operations
    if (strcasecmp(tok, "haddps") == 0) return MNEM_HADDPS;
    if (strcasecmp(tok, "haddpd") == 0) return MNEM_HADDPD;
    if (strcasecmp(tok, "hsubps") == 0) return MNEM_HSUBPS;
    if (strcasecmp(tok, "hsubpd") == 0) return MNEM_HSUBPD;
    if (strcasecmp(tok, "vhaddps") == 0) return MNEM_VHADDPS;
    if (strcasecmp(tok, "vhaddpd") == 0) return MNEM_VHADDPD;
    if (strcasecmp(tok, "vhsubps") == 0) return MNEM_VHSUBPS;
    if (strcasecmp(tok, "vhsubpd") == 0) return MNEM_VHSUBPD;
    // SSE4.1
    if (strcasecmp(tok, "blendps") == 0) return MNEM_BLENDPS;
    if (strcasecmp(tok, "blendpd") == 0) return MNEM_BLENDPD;
    if (strcasecmp(tok, "vblendps") == 0) return MNEM_VBLENDPS;
    if (strcasecmp(tok, "vblendpd") == 0) return MNEM_VBLENDPD;
    if (strcasecmp(tok, "insertps") == 0) return MNEM_INSERTPS;
    if (strcasecmp(tok, "extractps") == 0) return MNEM_EXTRACTPS;
    if (strcasecmp(tok, "pblendw") == 0) return MNEM_PBLENDW;
    if (strcasecmp(tok, "roundss") == 0) return MNEM_ROUNDSS;
    if (strcasecmp(tok, "roundsd") == 0) return MNEM_ROUNDSD;
    if (strcasecmp(tok, "dpps") == 0) return MNEM_DPPS;
    if (strcasecmp(tok, "dppd") == 0) return MNEM_DPPD;
    // FMA3
    if (strcasecmp(tok, "vfmadd132ps") == 0) return MNEM_VFMADD132PS;
    if (strcasecmp(tok, "vfmadd132pd") == 0) return MNEM_VFMADD132PD;
    if (strcasecmp(tok, "vfmadd213ps") == 0) return MNEM_VFMADD213PS;
    if (strcasecmp(tok, "vfmadd213pd") == 0) return MNEM_VFMADD213PD;
    if (strcasecmp(tok, "vfmadd231ps") == 0) return MNEM_VFMADD231PS;
    if (strcasecmp(tok, "vfmadd231pd") == 0) return MNEM_VFMADD231PD;
    if (strcasecmp(tok, "vfmsub132ps") == 0) return MNEM_VFMSUB132PS;
    if (strcasecmp(tok, "vfmsub132pd") == 0) return MNEM_VFMSUB132PD;
    if (strcasecmp(tok, "vfmsub213ps") == 0) return MNEM_VFMSUB213PS;
    if (strcasecmp(tok, "vfmsub213pd") == 0) return MNEM_VFMSUB213PD;
    if (strcasecmp(tok, "vfmsub231ps") == 0) return MNEM_VFMSUB231PS;
    if (strcasecmp(tok, "vfmsub231pd") == 0) return MNEM_VFMSUB231PD;
    if (strcasecmp(tok, "vfnmadd132ps") == 0) return MNEM_VFNMADD132PS;
    if (strcasecmp(tok, "vfnmadd132pd") == 0) return MNEM_VFNMADD132PD;
    if (strcasecmp(tok, "vfnmadd213ps") == 0) return MNEM_VFNMADD213PS;
    if (strcasecmp(tok, "vfnmadd213pd") == 0) return MNEM_VFNMADD213PD;
    if (strcasecmp(tok, "vfnmadd231ps") == 0) return MNEM_VFNMADD231PS;
    if (strcasecmp(tok, "vfnmadd231pd") == 0) return MNEM_VFNMADD231PD;
    if (strcasecmp(tok, "vfnmsub132ps") == 0) return MNEM_VFNMSUB132PS;
    if (strcasecmp(tok, "vfnmsub132pd") == 0) return MNEM_VFNMSUB132PD;
    if (strcasecmp(tok, "vfnmsub213ps") == 0) return MNEM_VFNMSUB213PS;
    if (strcasecmp(tok, "vfnmsub213pd") == 0) return MNEM_VFNMSUB213PD;
    if (strcasecmp(tok, "vfnmsub231ps") == 0) return MNEM_VFNMSUB231PS;
    if (strcasecmp(tok, "vfnmsub231pd") == 0) return MNEM_VFNMSUB231PD;
    // AVX2
    if (strcasecmp(tok, "vperm2i128") == 0) return MNEM_VPERM2I128;
    if (strcasecmp(tok, "vpermd") == 0) return MNEM_VPERMD;
    if (strcasecmp(tok, "vpermq") == 0) return MNEM_VPERMQ;
    if (strcasecmp(tok, "vgatherdps") == 0) return MNEM_VGATHERDPS;
    if (strcasecmp(tok, "vgatherdpd") == 0) return MNEM_VGATHERDPD;
    if (strcasecmp(tok, "vgatherqps") == 0) return MNEM_VGATHERQPS;
    if (strcasecmp(tok, "vgatherqpd") == 0) return MNEM_VGATHERQPD;
    if (strcasecmp(tok, "vpmaskmovd") == 0) return MNEM_VPMASKMOVD;
    if (strcasecmp(tok, "vpmaskmovq") == 0) return MNEM_VPMASKMOVQ;
    // SSE/SSE2 Packed moves
    if (strcasecmp(tok, "movhps") == 0) return MNEM_MOVHPS;
    if (strcasecmp(tok, "movlps") == 0) return MNEM_MOVLPS;
    if (strcasecmp(tok, "movhpd") == 0) return MNEM_MOVHPD;
    if (strcasecmp(tok, "movlpd") == 0) return MNEM_MOVLPD;
    // SSE/SSE2 Unpack
    if (strcasecmp(tok, "unpcklps") == 0) return MNEM_UNPCKLPS;
    if (strcasecmp(tok, "unpckhps") == 0) return MNEM_UNPCKHPS;
    if (strcasecmp(tok, "unpcklpd") == 0) return MNEM_UNPCKLPD;
    if (strcasecmp(tok, "unpckhpd") == 0) return MNEM_UNPCKHPD;
    // SSE/SSE2 Shuffle
    if (strcasecmp(tok, "shufps") == 0) return MNEM_SHUFPS;
    if (strcasecmp(tok, "shufpd") == 0) return MNEM_SHUFPD;
    if (strcasecmp(tok, "pshufw") == 0) return MNEM_PSHUFW;
    if (strcasecmp(tok, "pshufd") == 0) return MNEM_PSHUFD;
    if (strcasecmp(tok, "pshufhw") == 0) return MNEM_PSHUFHW;
    if (strcasecmp(tok, "pshuflw") == 0) return MNEM_PSHUFLW;
    // SSE/SSE2 Logical
    if (strcasecmp(tok, "andps") == 0) return MNEM_ANDPS;
    if (strcasecmp(tok, "andpd") == 0) return MNEM_ANDPD;
    if (strcasecmp(tok, "andnps") == 0) return MNEM_ANDNPS;
    if (strcasecmp(tok, "andnpd") == 0) return MNEM_ANDNPD;
    if (strcasecmp(tok, "orps") == 0) return MNEM_ORPS;
    if (strcasecmp(tok, "orpd") == 0) return MNEM_ORPD;
    // xorps, xorpd already parsed above
    // SSE/SSE2 Min/Max
    if (strcasecmp(tok, "minps") == 0) return MNEM_MINPS;
    if (strcasecmp(tok, "minpd") == 0) return MNEM_MINPD;
    if (strcasecmp(tok, "minss") == 0) return MNEM_MINSS;
    if (strcasecmp(tok, "minsd") == 0) return MNEM_MINSD;
    if (strcasecmp(tok, "maxps") == 0) return MNEM_MAXPS;
    if (strcasecmp(tok, "maxpd") == 0) return MNEM_MAXPD;
    if (strcasecmp(tok, "maxss") == 0) return MNEM_MAXSS;
    if (strcasecmp(tok, "maxsd") == 0) return MNEM_MAXSD;
    // SSE Reciprocal
    if (strcasecmp(tok, "rcpps") == 0) return MNEM_RCPPS;
    if (strcasecmp(tok, "rcpss") == 0) return MNEM_RCPSS;
    if (strcasecmp(tok, "rsqrtps") == 0) return MNEM_RSQRTPS;
    if (strcasecmp(tok, "rsqrtss") == 0) return MNEM_RSQRTSS;
    // SSE/SSE2 MMX Conversions
    if (strcasecmp(tok, "cvtpi2ps") == 0) return MNEM_CVTPI2PS;
    if (strcasecmp(tok, "cvtps2pi") == 0) return MNEM_CVTPS2PI;
    if (strcasecmp(tok, "cvtpi2pd") == 0) return MNEM_CVTPI2PD;
    if (strcasecmp(tok, "cvtpd2pi") == 0) return MNEM_CVTPD2PI;
    if (strcasecmp(tok, "cvttps2pi") == 0) return MNEM_CVTTPS2PI;
    if (strcasecmp(tok, "cvttpd2pi") == 0) return MNEM_CVTTPD2PI;
    // SSE/SSE2 Masked moves
    if (strcasecmp(tok, "maskmovdqu") == 0) return MNEM_MASKMOVDQU;
    // SSE/SSE2 Non-temporal stores
    if (strcasecmp(tok, "movntps") == 0) return MNEM_MOVNTPS;
    if (strcasecmp(tok, "movntpd") == 0) return MNEM_MOVNTPD;
    if (strcasecmp(tok, "movntdq") == 0) return MNEM_MOVNTDQ;
    // SSE3
    if (strcasecmp(tok, "movddup") == 0) return MNEM_MOVDDUP;
    if (strcasecmp(tok, "movshdup") == 0) return MNEM_MOVSHDUP;
    if (strcasecmp(tok, "movsldup") == 0) return MNEM_MOVSLDUP;
    if (strcasecmp(tok, "addsubps") == 0) return MNEM_ADDSUBPS;
    if (strcasecmp(tok, "addsubpd") == 0) return MNEM_ADDSUBPD;
    // SSSE3
    if (strcasecmp(tok, "pabsb") == 0) return MNEM_PABSB;
    if (strcasecmp(tok, "pabsw") == 0) return MNEM_PABSW;
    if (strcasecmp(tok, "pabsd") == 0) return MNEM_PABSD;
    if (strcasecmp(tok, "psignb") == 0) return MNEM_PSIGNB;
    if (strcasecmp(tok, "psignw") == 0) return MNEM_PSIGNW;
    if (strcasecmp(tok, "psignd") == 0) return MNEM_PSIGND;
    if (strcasecmp(tok, "palignr") == 0) return MNEM_PALIGNR;
    if (strcasecmp(tok, "pshufb") == 0) return MNEM_PSHUFB;
    if (strcasecmp(tok, "pmulhrsw") == 0) return MNEM_PMULHRSW;
    // SSE4.1
    // SSE4.1 (pminub, pminsw, pmaxub, pmaxsw already parsed in MMX section)
    if (strcasecmp(tok, "pminsb") == 0) return MNEM_PMINSB;
    if (strcasecmp(tok, "pminuw") == 0) return MNEM_PMINUW;
    if (strcasecmp(tok, "pminud") == 0) return MNEM_PMINUD;
    if (strcasecmp(tok, "pminsd") == 0) return MNEM_PMINSD;
    if (strcasecmp(tok, "pmaxsb") == 0) return MNEM_PMAXSB;
    if (strcasecmp(tok, "pmaxuw") == 0) return MNEM_PMAXUW;
    if (strcasecmp(tok, "pmaxud") == 0) return MNEM_PMAXUD;
    if (strcasecmp(tok, "pmaxsd") == 0) return MNEM_PMAXSD;
    if (strcasecmp(tok, "pmuldq") == 0) return MNEM_PMULDQ;
    if (strcasecmp(tok, "movntdqa") == 0) return MNEM_MOVNTDQA;
    if (strcasecmp(tok, "pinsrb") == 0) return MNEM_PINSRB;
    if (strcasecmp(tok, "pinsrd") == 0) return MNEM_PINSRD;
    if (strcasecmp(tok, "pinsrq") == 0) return MNEM_PINSRQ;
    if (strcasecmp(tok, "pextrb") == 0) return MNEM_PEXTRB;
    if (strcasecmp(tok, "pextrd") == 0) return MNEM_PEXTRD;
    if (strcasecmp(tok, "pextrq") == 0) return MNEM_PEXTRQ;
    // SSE4.2
    if (strcasecmp(tok, "pcmpestri") == 0) return MNEM_PCMPESTRI;
    if (strcasecmp(tok, "pcmpestrm") == 0) return MNEM_PCMPESTRM;
    if (strcasecmp(tok, "pcmpistri") == 0) return MNEM_PCMPISTRI;
    if (strcasecmp(tok, "pcmpistrm") == 0) return MNEM_PCMPISTRM;
    if (strcasecmp(tok, "crc32") == 0) return MNEM_CRC32;
    // AES-NI
    if (strcasecmp(tok, "aesenc") == 0) return MNEM_AESENC;
    if (strcasecmp(tok, "aesenclast") == 0) return MNEM_AESENCLAST;
    if (strcasecmp(tok, "aesdec") == 0) return MNEM_AESDEC;
    if (strcasecmp(tok, "aesdeclast") == 0) return MNEM_AESDECLAST;
    if (strcasecmp(tok, "aeskeygenassist") == 0) return MNEM_AESKEYGENASSIST;
    if (strcasecmp(tok, "aesimc") == 0) return MNEM_AESIMC;
    // AVX-512 (using special suffix to distinguish from AVX versions)
    // Note: Real AVX-512 uses EVEX encoding which is automatically selected based on ZMM registers
    // For simplicity, we'll detect ZMM usage in encoding phase
    // Opmask operations
    if (strcasecmp(tok, "kmovw") == 0) return MNEM_KMOVW;
    if (strcasecmp(tok, "kmovb") == 0) return MNEM_KMOVB;
    if (strcasecmp(tok, "kmovq") == 0) return MNEM_KMOVQ;
    if (strcasecmp(tok, "kmovd") == 0) return MNEM_KMOVD;
    if (strcasecmp(tok, "kandw") == 0) return MNEM_KANDW;
    if (strcasecmp(tok, "kandb") == 0) return MNEM_KANDB;
    if (strcasecmp(tok, "kandq") == 0) return MNEM_KANDQ;
    if (strcasecmp(tok, "kandd") == 0) return MNEM_KANDD;
    if (strcasecmp(tok, "korw") == 0) return MNEM_KORW;
    if (strcasecmp(tok, "korb") == 0) return MNEM_KORB;
    if (strcasecmp(tok, "korq") == 0) return MNEM_KORQ;
    if (strcasecmp(tok, "kord") == 0) return MNEM_KORD;
    if (strcasecmp(tok, "kxorw") == 0) return MNEM_KXORW;
    if (strcasecmp(tok, "kxorb") == 0) return MNEM_KXORB;
    if (strcasecmp(tok, "kxorq") == 0) return MNEM_KXORQ;
    if (strcasecmp(tok, "kxord") == 0) return MNEM_KXORD;
    if (strcasecmp(tok, "knotw") == 0) return MNEM_KNOTW;
    if (strcasecmp(tok, "knotb") == 0) return MNEM_KNOTB;
    if (strcasecmp(tok, "knotq") == 0) return MNEM_KNOTQ;
    if (strcasecmp(tok, "knotd") == 0) return MNEM_KNOTD;
    // AVX-512 arithmetic/moves with ZMM (use separate mnemonics to distinguish from AVX)
    if (strcasecmp(tok, "vaddps.512") == 0) return MNEM_VADDPS_512;
    if (strcasecmp(tok, "vaddpd.512") == 0) return MNEM_VADDPD_512;
    if (strcasecmp(tok, "vsubps.512") == 0) return MNEM_VSUBPS_512;
    if (strcasecmp(tok, "vsubpd.512") == 0) return MNEM_VSUBPD_512;
    if (strcasecmp(tok, "vmulps.512") == 0) return MNEM_VMULPS_512;
    if (strcasecmp(tok, "vmulpd.512") == 0) return MNEM_VMULPD_512;
    if (strcasecmp(tok, "vdivps.512") == 0) return MNEM_VDIVPS_512;
    if (strcasecmp(tok, "vdivpd.512") == 0) return MNEM_VDIVPD_512;
    if (strcasecmp(tok, "vmovaps.512") == 0) return MNEM_VMOVAPS_512;
    if (strcasecmp(tok, "vmovapd.512") == 0) return MNEM_VMOVAPD_512;
    if (strcasecmp(tok, "vmovups.512") == 0) return MNEM_VMOVUPS_512;
    if (strcasecmp(tok, "vmovupd.512") == 0) return MNEM_VMOVUPD_512;
    if (strcasecmp(tok, "vmovdqa32") == 0) return MNEM_VMOVDQA32;
    if (strcasecmp(tok, "vmovdqa64") == 0) return MNEM_VMOVDQA64;
    if (strcasecmp(tok, "vmovdqu32") == 0) return MNEM_VMOVDQU32;
    if (strcasecmp(tok, "vmovdqu64") == 0) return MNEM_VMOVDQU64;
    if (strcasecmp(tok, "vbroadcastss") == 0) return MNEM_VBROADCASTSS;
    if (strcasecmp(tok, "vbroadcastsd") == 0) return MNEM_VBROADCASTSD;
    if (strcasecmp(tok, "vbroadcasti32x4") == 0) return MNEM_VBROADCASTI32X4;
    if (strcasecmp(tok, "vbroadcasti64x4") == 0) return MNEM_VBROADCASTI64X4;
    if (strcasecmp(tok, "vpbroadcastd") == 0) return MNEM_VPBROADCASTD;
    if (strcasecmp(tok, "vpbroadcastq") == 0) return MNEM_VPBROADCASTQ;
    if (strcasecmp(tok, "je") == 0 || strcasecmp(tok, "jz") == 0) return MNEM_JE;
    if (strcasecmp(tok, "jne") == 0 || strcasecmp(tok, "jnz") == 0) return MNEM_JNE;
    if (strcasecmp(tok, "ja") == 0 || strcasecmp(tok, "jnbe") == 0) return MNEM_JA;
    if (strcasecmp(tok, "jae") == 0 || strcasecmp(tok, "jnb") == 0 || strcasecmp(tok, "jnc") == 0) return MNEM_JAE;
    if (strcasecmp(tok, "jb") == 0 || strcasecmp(tok, "jnae") == 0 || strcasecmp(tok, "jc") == 0) return MNEM_JB;
    if (strcasecmp(tok, "jbe") == 0 || strcasecmp(tok, "jna") == 0) return MNEM_JBE;
    if (strcasecmp(tok, "jg") == 0 || strcasecmp(tok, "jnle") == 0) return MNEM_JG;
    if (strcasecmp(tok, "jge") == 0 || strcasecmp(tok, "jnl") == 0) return MNEM_JGE;
    if (strcasecmp(tok, "jl") == 0 || strcasecmp(tok, "jnge") == 0) return MNEM_JL;
    if (strcasecmp(tok, "jle") == 0 || strcasecmp(tok, "jng") == 0) return MNEM_JLE;
    if (strcasecmp(tok, "jo") == 0) return MNEM_JO;
    if (strcasecmp(tok, "jno") == 0) return MNEM_JNO;
    if (strcasecmp(tok, "js") == 0) return MNEM_JS;
    if (strcasecmp(tok, "jns") == 0) return MNEM_JNS;
    if (strcasecmp(tok, "jp") == 0 || strcasecmp(tok, "jpe") == 0) return MNEM_JP;
    if (strcasecmp(tok, "jnp") == 0 || strcasecmp(tok, "jpo") == 0) return MNEM_JNP;
    if (strcasecmp(tok, "sete") == 0 || strcasecmp(tok, "setz") == 0) return MNEM_SETE;
    if (strcasecmp(tok, "setne") == 0 || strcasecmp(tok, "setnz") == 0) return MNEM_SETNE;
    if (strcasecmp(tok, "seta") == 0 || strcasecmp(tok, "setnbe") == 0) return MNEM_SETA;
    if (strcasecmp(tok, "setae") == 0 || strcasecmp(tok, "setnb") == 0 || strcasecmp(tok, "setnc") == 0) return MNEM_SETAE;
    if (strcasecmp(tok, "setb") == 0 || strcasecmp(tok, "setnae") == 0 || strcasecmp(tok, "setc") == 0) return MNEM_SETB;
    if (strcasecmp(tok, "setbe") == 0 || strcasecmp(tok, "setna") == 0) return MNEM_SETBE;
    if (strcasecmp(tok, "setg") == 0 || strcasecmp(tok, "setnle") == 0) return MNEM_SETG;
    if (strcasecmp(tok, "setge") == 0 || strcasecmp(tok, "setnl") == 0) return MNEM_SETGE;
    if (strcasecmp(tok, "setl") == 0 || strcasecmp(tok, "setnge") == 0) return MNEM_SETL;
    if (strcasecmp(tok, "setle") == 0 || strcasecmp(tok, "setng") == 0) return MNEM_SETLE;
    if (strcasecmp(tok, "seto") == 0) return MNEM_SETO;
    if (strcasecmp(tok, "setno") == 0) return MNEM_SETNO;
    if (strcasecmp(tok, "sets") == 0) return MNEM_SETS;
    if (strcasecmp(tok, "setns") == 0) return MNEM_SETNS;
    if (strcasecmp(tok, "setp") == 0 || strcasecmp(tok, "setpe") == 0) return MNEM_SETP;
    if (strcasecmp(tok, "setnp") == 0 || strcasecmp(tok, "setpo") == 0) return MNEM_SETNP;
    if (strcasecmp(tok, "movzx") == 0) return MNEM_MOVZX;
    if (strcasecmp(tok, "movsx") == 0) return MNEM_MOVSX;
    if (strcasecmp(tok, "movsxd") == 0) return MNEM_MOVSXD;
    if (strcasecmp(tok, "cmove") == 0 || strcasecmp(tok, "cmovz") == 0) return MNEM_CMOVE;
    if (strcasecmp(tok, "cmovne") == 0 || strcasecmp(tok, "cmovnz") == 0) return MNEM_CMOVNE;
    if (strcasecmp(tok, "cmova") == 0 || strcasecmp(tok, "cmovnbe") == 0) return MNEM_CMOVA;
    if (strcasecmp(tok, "cmovae") == 0 || strcasecmp(tok, "cmovnb") == 0) return MNEM_CMOVAE;
    if (strcasecmp(tok, "cmovb") == 0 || strcasecmp(tok, "cmovnae") == 0) return MNEM_CMOVB;
    if (strcasecmp(tok, "cmovbe") == 0 || strcasecmp(tok, "cmovna") == 0) return MNEM_CMOVBE;
    if (strcasecmp(tok, "cmovg") == 0 || strcasecmp(tok, "cmovnle") == 0) return MNEM_CMOVG;
    if (strcasecmp(tok, "cmovge") == 0 || strcasecmp(tok, "cmovnl") == 0) return MNEM_CMOVGE;
    if (strcasecmp(tok, "cmovl") == 0 || strcasecmp(tok, "cmovnge") == 0) return MNEM_CMOVL;
    if (strcasecmp(tok, "cmovle") == 0 || strcasecmp(tok, "cmovng") == 0) return MNEM_CMOVLE;
    if (strcasecmp(tok, "cmovo") == 0) return MNEM_CMOVO;
    if (strcasecmp(tok, "cmovno") == 0) return MNEM_CMOVNO;
    if (strcasecmp(tok, "cmovs") == 0) return MNEM_CMOVS;
    if (strcasecmp(tok, "cmovns") == 0) return MNEM_CMOVNS;
    if (strcasecmp(tok, "cmovp") == 0 || strcasecmp(tok, "cmovpe") == 0) return MNEM_CMOVP;
    if (strcasecmp(tok, "cmovnp") == 0 || strcasecmp(tok, "cmovpo") == 0) return MNEM_CMOVNP;
    if (strcasecmp(tok, "jmp") == 0) return MNEM_JMP;
    if (strcasecmp(tok, "call") == 0) return MNEM_CALL;
    if (strcasecmp(tok, "syscall") == 0) return MNEM_SYSCALL;
    if (strcasecmp(tok, "mul") == 0) return MNEM_MUL;
    if (strcasecmp(tok, "imul") == 0) return MNEM_IMUL;
    if (strcasecmp(tok, "div") == 0) return MNEM_DIV;
    if (strcasecmp(tok, "idiv") == 0) return MNEM_IDIV;
    if (strcasecmp(tok, "cqo") == 0) return MNEM_CQO;
    if (strcasecmp(tok, "ret") == 0) return MNEM_RET;
    if (strcasecmp(tok, "nop") == 0) return MNEM_NOP;
    // SSE2 Integer
    if (strcasecmp(tok, "paddd") == 0) return MNEM_PADDD;
    if (strcasecmp(tok, "paddq") == 0) return MNEM_PADDQ;
    if (strcasecmp(tok, "psubd") == 0) return MNEM_PSUBD;
    if (strcasecmp(tok, "psubq") == 0) return MNEM_PSUBQ;
    if (strcasecmp(tok, "pmuludq") == 0) return MNEM_PMULUDQ;
    if (strcasecmp(tok, "pmulld") == 0) return MNEM_PMULLD;
    if (strcasecmp(tok, "pand") == 0) return MNEM_PAND;
    if (strcasecmp(tok, "por") == 0) return MNEM_POR;
    if (strcasecmp(tok, "pxor") == 0) return MNEM_PXOR;
    if (strcasecmp(tok, "psllq") == 0) return MNEM_PSLLQ;
    if (strcasecmp(tok, "psrlq") == 0) return MNEM_PSRLQ;
    if (strcasecmp(tok, "psraq") == 0) return MNEM_PSRAQ;
    if (strcasecmp(tok, "pcmpeqd") == 0) return MNEM_PCMPEQD;
    if (strcasecmp(tok, "pcmpgtd") == 0) return MNEM_PCMPGTD;
    // AVX Integer
    if (strcasecmp(tok, "vpaddd") == 0) return MNEM_VPADDD;
    if (strcasecmp(tok, "vpaddq") == 0) return MNEM_VPADDQ;
    if (strcasecmp(tok, "vpsubd") == 0) return MNEM_VPSUBD;
    if (strcasecmp(tok, "vpsubq") == 0) return MNEM_VPSUBQ;
    if (strcasecmp(tok, "vpmuludq") == 0) return MNEM_VPMULUDQ;
    if (strcasecmp(tok, "vpmulld") == 0) return MNEM_VPMULLD;
    if (strcasecmp(tok, "vpand") == 0) return MNEM_VPAND;
    if (strcasecmp(tok, "vpor") == 0) return MNEM_VPOR;
    if (strcasecmp(tok, "vpxor") == 0) return MNEM_VPXOR;
    // BMI/BMI2
    if (strcasecmp(tok, "andn") == 0) return MNEM_ANDN;
    if (strcasecmp(tok, "bextr") == 0) return MNEM_BEXTR;
    if (strcasecmp(tok, "blsi") == 0) return MNEM_BLSI;
    if (strcasecmp(tok, "blsmsk") == 0) return MNEM_BLSMSK;
    if (strcasecmp(tok, "blsr") == 0) return MNEM_BLSR;
    if (strcasecmp(tok, "bzhi") == 0) return MNEM_BZHI;
    if (strcasecmp(tok, "lzcnt") == 0) return MNEM_LZCNT;
    if (strcasecmp(tok, "tzcnt") == 0) return MNEM_TZCNT;
    if (strcasecmp(tok, "popcnt") == 0) return MNEM_POPCNT;
    if (strcasecmp(tok, "pdep") == 0) return MNEM_PDEP;
    if (strcasecmp(tok, "pext") == 0) return MNEM_PEXT;
    if (strcasecmp(tok, "rorx") == 0) return MNEM_RORX;
    if (strcasecmp(tok, "sarx") == 0) return MNEM_SARX;
    if (strcasecmp(tok, "shlx") == 0) return MNEM_SHLX;
    if (strcasecmp(tok, "shrx") == 0) return MNEM_SHRX;
    // Bit manipulation
    if (strcasecmp(tok, "bsf") == 0) return MNEM_BSF;
    if (strcasecmp(tok, "bsr") == 0) return MNEM_BSR;
    if (strcasecmp(tok, "bt") == 0) return MNEM_BT;
    if (strcasecmp(tok, "btc") == 0) return MNEM_BTC;
    if (strcasecmp(tok, "btr") == 0) return MNEM_BTR;
    if (strcasecmp(tok, "bts") == 0) return MNEM_BTS;
    if (strcasecmp(tok, "bswap") == 0) return MNEM_BSWAP;
    // String operations
    if (strcasecmp(tok, "movsb") == 0) return MNEM_MOVSB;
    if (strcasecmp(tok, "movsw") == 0) return MNEM_MOVSW;
    if (strcasecmp(tok, "movsq") == 0) return MNEM_MOVSQ;
    if (strcasecmp(tok, "stosb") == 0) return MNEM_STOSB;
    if (strcasecmp(tok, "stosw") == 0) return MNEM_STOSW;
    if (strcasecmp(tok, "stosd") == 0) return MNEM_STOSD;
    if (strcasecmp(tok, "stosq") == 0) return MNEM_STOSQ;
    if (strcasecmp(tok, "lodsb") == 0) return MNEM_LODSB;
    if (strcasecmp(tok, "lodsw") == 0) return MNEM_LODSW;
    if (strcasecmp(tok, "lodsd") == 0) return MNEM_LODSD;
    if (strcasecmp(tok, "lodsq") == 0) return MNEM_LODSQ;
    if (strcasecmp(tok, "scasb") == 0) return MNEM_SCASB;
    if (strcasecmp(tok, "scasw") == 0) return MNEM_SCASW;
    if (strcasecmp(tok, "scasd") == 0) return MNEM_SCASD;
    if (strcasecmp(tok, "scasq") == 0) return MNEM_SCASQ;
    if (strcasecmp(tok, "cmpsb") == 0) return MNEM_CMPSB;
    if (strcasecmp(tok, "cmpsw") == 0) return MNEM_CMPSW;
    if (strcasecmp(tok, "cmpsq") == 0) return MNEM_CMPSQ;
    if (strcasecmp(tok, "rep") == 0) return MNEM_REP;
    if (strcasecmp(tok, "repe") == 0 || strcasecmp(tok, "repz") == 0) return MNEM_REPE;
    if (strcasecmp(tok, "repne") == 0 || strcasecmp(tok, "repnz") == 0) return MNEM_REPNE;
    // Rotate instructions
    if (strcasecmp(tok, "rol") == 0) return MNEM_ROL;
    if (strcasecmp(tok, "ror") == 0) return MNEM_ROR;
    if (strcasecmp(tok, "rcl") == 0) return MNEM_RCL;
    if (strcasecmp(tok, "rcr") == 0) return MNEM_RCR;
    // Stack frame
    if (strcasecmp(tok, "enter") == 0) return MNEM_ENTER;
    if (strcasecmp(tok, "leave") == 0) return MNEM_LEAVE;
    // Exchange
    if (strcasecmp(tok, "xchg") == 0) return MNEM_XCHG;
    if (strcasecmp(tok, "xadd") == 0) return MNEM_XADD;
    // Atomic
    if (strcasecmp(tok, "cmpxchg") == 0) return MNEM_CMPXCHG;
    if (strcasecmp(tok, "cmpxchg8b") == 0) return MNEM_CMPXCHG8B;
    if (strcasecmp(tok, "cmpxchg16b") == 0) return MNEM_CMPXCHG16B;
    // Carry arithmetic
    if (strcasecmp(tok, "adc") == 0) return MNEM_ADC;
    if (strcasecmp(tok, "sbb") == 0) return MNEM_SBB;
    // Flag manipulation
    if (strcasecmp(tok, "clc") == 0) return MNEM_CLC;
    if (strcasecmp(tok, "stc") == 0) return MNEM_STC;
    if (strcasecmp(tok, "cmc") == 0) return MNEM_CMC;
    if (strcasecmp(tok, "cld") == 0) return MNEM_CLD;
    if (strcasecmp(tok, "std") == 0) return MNEM_STD;
    if (strcasecmp(tok, "cli") == 0) return MNEM_CLI;
    if (strcasecmp(tok, "sti") == 0) return MNEM_STI;
    if (strcasecmp(tok, "lahf") == 0) return MNEM_LAHF;
    if (strcasecmp(tok, "sahf") == 0) return MNEM_SAHF;
    if (strcasecmp(tok, "pushf") == 0) return MNEM_PUSHF;
    if (strcasecmp(tok, "popf") == 0) return MNEM_POPF;
    if (strcasecmp(tok, "pushfq") == 0) return MNEM_PUSHFQ;
    if (strcasecmp(tok, "popfq") == 0) return MNEM_POPFQ;
    // Conversions
    if (strcasecmp(tok, "cdq") == 0) return MNEM_CDQ;
    if (strcasecmp(tok, "cdqe") == 0) return MNEM_CDQE;
    if (strcasecmp(tok, "cbw") == 0) return MNEM_CBW;
    if (strcasecmp(tok, "cwde") == 0) return MNEM_CWDE;
    // Loop instructions
    if (strcasecmp(tok, "loop") == 0) return MNEM_LOOP;
    if (strcasecmp(tok, "loope") == 0 || strcasecmp(tok, "loopz") == 0) return MNEM_LOOPE;
    if (strcasecmp(tok, "loopne") == 0 || strcasecmp(tok, "loopnz") == 0) return MNEM_LOOPNE;
    // Miscellaneous
    if (strcasecmp(tok, "xlat") == 0 || strcasecmp(tok, "xlatb") == 0) return MNEM_XLAT;
    if (strcasecmp(tok, "in") == 0) return MNEM_IN;
    if (strcasecmp(tok, "out") == 0) return MNEM_OUT;
    if (strcasecmp(tok, "insb") == 0) return MNEM_INSB;
    if (strcasecmp(tok, "insw") == 0) return MNEM_INSW;
    if (strcasecmp(tok, "insd") == 0) return MNEM_INSD;
    if (strcasecmp(tok, "outsb") == 0) return MNEM_OUTSB;
    if (strcasecmp(tok, "outsw") == 0) return MNEM_OUTSW;
    if (strcasecmp(tok, "outsd") == 0) return MNEM_OUTSD;
    if (strcasecmp(tok, "movbe") == 0) return MNEM_MOVBE;
    if (strcasecmp(tok, "int") == 0) return MNEM_INT;
    if (strcasecmp(tok, "hlt") == 0) return MNEM_HLT;
    if (strcasecmp(tok, "pause") == 0) return MNEM_PAUSE;
    if (strcasecmp(tok, "cpuid") == 0) return MNEM_CPUID;
    if (strcasecmp(tok, "rdtsc") == 0) return MNEM_RDTSC;
    if (strcasecmp(tok, "rdtscp") == 0) return MNEM_RDTSCP;
    // Protected mode
    if (strcasecmp(tok, "lgdt") == 0) return MNEM_LGDT;
    if (strcasecmp(tok, "lidt") == 0) return MNEM_LIDT;
    if (strcasecmp(tok, "sgdt") == 0) return MNEM_SGDT;
    if (strcasecmp(tok, "sidt") == 0) return MNEM_SIDT;
    if (strcasecmp(tok, "ltr") == 0) return MNEM_LTR;
    if (strcasecmp(tok, "str") == 0) return MNEM_STR;
    if (strcasecmp(tok, "lldt") == 0) return MNEM_LLDT;
    if (strcasecmp(tok, "sldt") == 0) return MNEM_SLDT;
    if (strcasecmp(tok, "lar") == 0) return MNEM_LAR;
    if (strcasecmp(tok, "lsl") == 0) return MNEM_LSL;
    if (strcasecmp(tok, "verr") == 0) return MNEM_VERR;
    if (strcasecmp(tok, "verw") == 0) return MNEM_VERW;
    if (strcasecmp(tok, "clts") == 0) return MNEM_CLTS;
    if (strcasecmp(tok, "lmsw") == 0) return MNEM_LMSW;
    if (strcasecmp(tok, "smsw") == 0) return MNEM_SMSW;
    if (strcasecmp(tok, "invlpg") == 0) return MNEM_INVLPG;
    if (strcasecmp(tok, "invd") == 0) return MNEM_INVD;
    if (strcasecmp(tok, "wbinvd") == 0) return MNEM_WBINVD;
    // Double-precision shifts
    if (strcasecmp(tok, "shld") == 0) return MNEM_SHLD;
    if (strcasecmp(tok, "shrd") == 0) return MNEM_SHRD;
    // Memory fences
    if (strcasecmp(tok, "mfence") == 0) return MNEM_MFENCE;
    if (strcasecmp(tok, "lfence") == 0) return MNEM_LFENCE;
    if (strcasecmp(tok, "sfence") == 0) return MNEM_SFENCE;
    // System instructions
    if (strcasecmp(tok, "ud2") == 0) return MNEM_UD2;
    if (strcasecmp(tok, "iret") == 0) return MNEM_IRET;
    if (strcasecmp(tok, "iretd") == 0) return MNEM_IRETD;
    if (strcasecmp(tok, "iretq") == 0) return MNEM_IRETQ;
    if (strcasecmp(tok, "jcxz") == 0) return MNEM_JCXZ;
    if (strcasecmp(tok, "jecxz") == 0) return MNEM_JECXZ;
    if (strcasecmp(tok, "jrcxz") == 0) return MNEM_JRCXZ;
    if (strcasecmp(tok, "retf") == 0) return MNEM_RETF;
    if (strcasecmp(tok, "sysenter") == 0) return MNEM_SYSENTER;
    if (strcasecmp(tok, "sysexit") == 0) return MNEM_SYSEXIT;
    if (strcasecmp(tok, "sysret") == 0) return MNEM_SYSRET;
    // Cache control
    if (strcasecmp(tok, "prefetchnta") == 0) return MNEM_PREFETCHNTA;
    if (strcasecmp(tok, "prefetcht0") == 0) return MNEM_PREFETCHT0;
    if (strcasecmp(tok, "prefetcht1") == 0) return MNEM_PREFETCHT1;
    if (strcasecmp(tok, "prefetcht2") == 0) return MNEM_PREFETCHT2;
    if (strcasecmp(tok, "clflush") == 0) return MNEM_CLFLUSH;
    if (strcasecmp(tok, "clflushopt") == 0) return MNEM_CLFLUSHOPT;
    // Random number generation
    if (strcasecmp(tok, "rdrand") == 0) return MNEM_RDRAND;
    if (strcasecmp(tok, "rdseed") == 0) return MNEM_RDSEED;
    // Segment register loads
    if (strcasecmp(tok, "lds") == 0) return MNEM_LDS;
    if (strcasecmp(tok, "les") == 0) return MNEM_LES;
    if (strcasecmp(tok, "lfs") == 0) return MNEM_LFS;
    if (strcasecmp(tok, "lgs") == 0) return MNEM_LGS;
    if (strcasecmp(tok, "lss") == 0) return MNEM_LSS;
    // BCD arithmetic
    if (strcasecmp(tok, "aaa") == 0) return MNEM_AAA;
    if (strcasecmp(tok, "aad") == 0) return MNEM_AAD;
    if (strcasecmp(tok, "aam") == 0) return MNEM_AAM;
    if (strcasecmp(tok, "aas") == 0) return MNEM_AAS;
    if (strcasecmp(tok, "daa") == 0) return MNEM_DAA;
    if (strcasecmp(tok, "das") == 0) return MNEM_DAS;
    // Legacy instructions
    if (strcasecmp(tok, "bound") == 0) return MNEM_BOUND;
    if (strcasecmp(tok, "arpl") == 0) return MNEM_ARPL;
    if (strcasecmp(tok, "into") == 0) return MNEM_INTO;
    if (strcasecmp(tok, "salc") == 0) return MNEM_SALC;
    // Extended state save/restore
    if (strcasecmp(tok, "xsave") == 0) return MNEM_XSAVE;
    if (strcasecmp(tok, "xsave64") == 0) return MNEM_XSAVE64;
    if (strcasecmp(tok, "xrstor") == 0) return MNEM_XRSTOR;
    if (strcasecmp(tok, "xrstor64") == 0) return MNEM_XRSTOR64;
    if (strcasecmp(tok, "xsaveopt") == 0) return MNEM_XSAVEOPT;
    if (strcasecmp(tok, "xsaveopt64") == 0) return MNEM_XSAVEOPT64;
    if (strcasecmp(tok, "xsavec") == 0) return MNEM_XSAVEC;
    if (strcasecmp(tok, "xsavec64") == 0) return MNEM_XSAVEC64;
    if (strcasecmp(tok, "xsaves") == 0) return MNEM_XSAVES;
    if (strcasecmp(tok, "xsaves64") == 0) return MNEM_XSAVES64;
    if (strcasecmp(tok, "xrstors") == 0) return MNEM_XRSTORS;
    if (strcasecmp(tok, "xrstors64") == 0) return MNEM_XRSTORS64;
    // Extended control registers
    if (strcasecmp(tok, "xgetbv") == 0) return MNEM_XGETBV;
    if (strcasecmp(tok, "xsetbv") == 0) return MNEM_XSETBV;
    // CPU monitoring
    if (strcasecmp(tok, "monitor") == 0) return MNEM_MONITOR;
    if (strcasecmp(tok, "mwait") == 0) return MNEM_MWAIT;
    // x87 FPU instructions
    if (strcasecmp(tok, "fld") == 0) return MNEM_FLD;
    if (strcasecmp(tok, "fst") == 0) return MNEM_FST;
    if (strcasecmp(tok, "fstp") == 0) return MNEM_FSTP;
    if (strcasecmp(tok, "fild") == 0) return MNEM_FILD;
    if (strcasecmp(tok, "fist") == 0) return MNEM_FIST;
    if (strcasecmp(tok, "fistp") == 0) return MNEM_FISTP;
    if (strcasecmp(tok, "fbld") == 0) return MNEM_FBLD;
    if (strcasecmp(tok, "fbstp") == 0) return MNEM_FBSTP;
    if (strcasecmp(tok, "fxch") == 0) return MNEM_FXCH;
    if (strcasecmp(tok, "fadd") == 0) return MNEM_FADD;
    if (strcasecmp(tok, "faddp") == 0) return MNEM_FADDP;
    if (strcasecmp(tok, "fiadd") == 0) return MNEM_FIADD;
    if (strcasecmp(tok, "fsub") == 0) return MNEM_FSUB;
    if (strcasecmp(tok, "fsubp") == 0) return MNEM_FSUBP;
    if (strcasecmp(tok, "fisub") == 0) return MNEM_FISUB;
    if (strcasecmp(tok, "fsubr") == 0) return MNEM_FSUBR;
    if (strcasecmp(tok, "fsubrp") == 0) return MNEM_FSUBRP;
    if (strcasecmp(tok, "fisubr") == 0) return MNEM_FISUBR;
    if (strcasecmp(tok, "fmul") == 0) return MNEM_FMUL;
    if (strcasecmp(tok, "fmulp") == 0) return MNEM_FMULP;
    if (strcasecmp(tok, "fimul") == 0) return MNEM_FIMUL;
    if (strcasecmp(tok, "fdiv") == 0) return MNEM_FDIV;
    if (strcasecmp(tok, "fdivp") == 0) return MNEM_FDIVP;
    if (strcasecmp(tok, "fidiv") == 0) return MNEM_FIDIV;
    if (strcasecmp(tok, "fdivr") == 0) return MNEM_FDIVR;
    if (strcasecmp(tok, "fdivrp") == 0) return MNEM_FDIVRP;
    if (strcasecmp(tok, "fidivr") == 0) return MNEM_FIDIVR;
    if (strcasecmp(tok, "fsqrt") == 0) return MNEM_FSQRT;
    if (strcasecmp(tok, "fscale") == 0) return MNEM_FSCALE;
    if (strcasecmp(tok, "fprem") == 0) return MNEM_FPREM;
    if (strcasecmp(tok, "fprem1") == 0) return MNEM_FPREM1;
    if (strcasecmp(tok, "frndint") == 0) return MNEM_FRNDINT;
    if (strcasecmp(tok, "fxtract") == 0) return MNEM_FXTRACT;
    if (strcasecmp(tok, "fabs") == 0) return MNEM_FABS;
    if (strcasecmp(tok, "fchs") == 0) return MNEM_FCHS;
    if (strcasecmp(tok, "fcom") == 0) return MNEM_FCOM;
    if (strcasecmp(tok, "fcomp") == 0) return MNEM_FCOMP;
    if (strcasecmp(tok, "fcompp") == 0) return MNEM_FCOMPP;
    if (strcasecmp(tok, "fucom") == 0) return MNEM_FUCOM;
    if (strcasecmp(tok, "fucomp") == 0) return MNEM_FUCOMP;
    if (strcasecmp(tok, "fucompp") == 0) return MNEM_FUCOMPP;
    if (strcasecmp(tok, "ficom") == 0) return MNEM_FICOM;
    if (strcasecmp(tok, "ficomp") == 0) return MNEM_FICOMP;
    if (strcasecmp(tok, "fcomi") == 0) return MNEM_FCOMI;
    if (strcasecmp(tok, "fcomip") == 0) return MNEM_FCOMIP;
    if (strcasecmp(tok, "fucomi") == 0) return MNEM_FUCOMI;
    if (strcasecmp(tok, "fucomip") == 0) return MNEM_FUCOMIP;
    if (strcasecmp(tok, "ftst") == 0) return MNEM_FTST;
    if (strcasecmp(tok, "fxam") == 0) return MNEM_FXAM;
    if (strcasecmp(tok, "fsin") == 0) return MNEM_FSIN;
    if (strcasecmp(tok, "fcos") == 0) return MNEM_FCOS;
    if (strcasecmp(tok, "fsincos") == 0) return MNEM_FSINCOS;
    if (strcasecmp(tok, "fptan") == 0) return MNEM_FPTAN;
    if (strcasecmp(tok, "fpatan") == 0) return MNEM_FPATAN;
    if (strcasecmp(tok, "f2xm1") == 0) return MNEM_F2XM1;
    if (strcasecmp(tok, "fyl2x") == 0) return MNEM_FYL2X;
    if (strcasecmp(tok, "fyl2xp1") == 0) return MNEM_FYL2XP1;
    if (strcasecmp(tok, "fld1") == 0) return MNEM_FLD1;
    if (strcasecmp(tok, "fldl2t") == 0) return MNEM_FLDL2T;
    if (strcasecmp(tok, "fldl2e") == 0) return MNEM_FLDL2E;
    if (strcasecmp(tok, "fldpi") == 0) return MNEM_FLDPI;
    if (strcasecmp(tok, "fldlg2") == 0) return MNEM_FLDLG2;
    if (strcasecmp(tok, "fldln2") == 0) return MNEM_FLDLN2;
    if (strcasecmp(tok, "fldz") == 0) return MNEM_FLDZ;
    if (strcasecmp(tok, "finit") == 0) return MNEM_FINIT;
    if (strcasecmp(tok, "fninit") == 0) return MNEM_FNINIT;
    if (strcasecmp(tok, "fclex") == 0) return MNEM_FCLEX;
    if (strcasecmp(tok, "fnclex") == 0) return MNEM_FNCLEX;
    if (strcasecmp(tok, "fstcw") == 0) return MNEM_FSTCW;
    if (strcasecmp(tok, "fnstcw") == 0) return MNEM_FNSTCW;
    if (strcasecmp(tok, "fldcw") == 0) return MNEM_FLDCW;
    if (strcasecmp(tok, "fstenv") == 0) return MNEM_FSTENV;
    if (strcasecmp(tok, "fnstenv") == 0) return MNEM_FNSTENV;
    if (strcasecmp(tok, "fldenv") == 0) return MNEM_FLDENV;
    if (strcasecmp(tok, "fsave") == 0) return MNEM_FSAVE;
    if (strcasecmp(tok, "fnsave") == 0) return MNEM_FNSAVE;
    if (strcasecmp(tok, "frstor") == 0) return MNEM_FRSTOR;
    if (strcasecmp(tok, "fstsw") == 0) return MNEM_FSTSW;
    if (strcasecmp(tok, "fnstsw") == 0) return MNEM_FNSTSW;
    if (strcasecmp(tok, "fincstp") == 0) return MNEM_FINCSTP;
    if (strcasecmp(tok, "fdecstp") == 0) return MNEM_FDECSTP;
    if (strcasecmp(tok, "ffree") == 0) return MNEM_FFREE;
    if (strcasecmp(tok, "ffreep") == 0) return MNEM_FFREEP;
    if (strcasecmp(tok, "fnop") == 0) return MNEM_FNOP;
    if (strcasecmp(tok, "fwait") == 0) return MNEM_FWAIT;
    // MMX instructions (some shared with SSE2)
    if (strcasecmp(tok, "emms") == 0) return MNEM_EMMS;
    if (strcasecmp(tok, "movd") == 0) return MNEM_MOVD;
    if (strcasecmp(tok, "movq") == 0) return MNEM_MOVQ;
    if (strcasecmp(tok, "packsswb") == 0) return MNEM_PACKSSWB;
    if (strcasecmp(tok, "packssdw") == 0) return MNEM_PACKSSDW;
    if (strcasecmp(tok, "packuswb") == 0) return MNEM_PACKUSWB;
    if (strcasecmp(tok, "paddb") == 0) return MNEM_PADDB;
    if (strcasecmp(tok, "paddw") == 0) return MNEM_PADDW;
    if (strcasecmp(tok, "paddsb") == 0) return MNEM_PADDSB;
    if (strcasecmp(tok, "paddsw") == 0) return MNEM_PADDSW;
    if (strcasecmp(tok, "paddusb") == 0) return MNEM_PADDUSB;
    if (strcasecmp(tok, "paddusw") == 0) return MNEM_PADDUSW;
    if (strcasecmp(tok, "pandn") == 0) return MNEM_PANDN;
    if (strcasecmp(tok, "pcmpeqb") == 0) return MNEM_PCMPEQB;
    if (strcasecmp(tok, "pcmpeqw") == 0) return MNEM_PCMPEQW;
    if (strcasecmp(tok, "pcmpgtb") == 0) return MNEM_PCMPGTB;
    if (strcasecmp(tok, "pcmpgtw") == 0) return MNEM_PCMPGTW;
    if (strcasecmp(tok, "pmaddwd") == 0) return MNEM_PMADDWD;
    if (strcasecmp(tok, "pmulhw") == 0) return MNEM_PMULHW;
    if (strcasecmp(tok, "pmullw") == 0) return MNEM_PMULLW;
    if (strcasecmp(tok, "pslld") == 0) return MNEM_PSLLD;
    if (strcasecmp(tok, "psllw") == 0) return MNEM_PSLLW;
    if (strcasecmp(tok, "psrad") == 0) return MNEM_PSRAD;
    if (strcasecmp(tok, "psraw") == 0) return MNEM_PSRAW;
    if (strcasecmp(tok, "psrld") == 0) return MNEM_PSRLD;
    if (strcasecmp(tok, "psrlw") == 0) return MNEM_PSRLW;
    if (strcasecmp(tok, "psubb") == 0) return MNEM_PSUBB;
    if (strcasecmp(tok, "psubw") == 0) return MNEM_PSUBW;
    if (strcasecmp(tok, "psubsb") == 0) return MNEM_PSUBSB;
    if (strcasecmp(tok, "psubsw") == 0) return MNEM_PSUBSW;
    if (strcasecmp(tok, "psubusb") == 0) return MNEM_PSUBUSB;
    if (strcasecmp(tok, "psubusw") == 0) return MNEM_PSUBUSW;
    if (strcasecmp(tok, "punpckhbw") == 0) return MNEM_PUNPCKHBW;
    if (strcasecmp(tok, "punpckhwd") == 0) return MNEM_PUNPCKHWD;
    if (strcasecmp(tok, "punpckhdq") == 0) return MNEM_PUNPCKHDQ;
    if (strcasecmp(tok, "punpcklbw") == 0) return MNEM_PUNPCKLBW;
    if (strcasecmp(tok, "punpcklwd") == 0) return MNEM_PUNPCKLWD;
    if (strcasecmp(tok, "punpckldq") == 0) return MNEM_PUNPCKLDQ;
    if (strcasecmp(tok, "pmulhuw") == 0) return MNEM_PMULHUW;
    if (strcasecmp(tok, "pavgb") == 0) return MNEM_PAVGB;
    if (strcasecmp(tok, "pavgw") == 0) return MNEM_PAVGW;
    if (strcasecmp(tok, "pmaxsw") == 0) return MNEM_PMAXSW;
    if (strcasecmp(tok, "pmaxub") == 0) return MNEM_PMAXUB;
    if (strcasecmp(tok, "pminsw") == 0) return MNEM_PMINSW;
    if (strcasecmp(tok, "pminub") == 0) return MNEM_PMINUB;
    if (strcasecmp(tok, "pmovmskb") == 0) return MNEM_PMOVMSKB;
    if (strcasecmp(tok, "psadbw") == 0) return MNEM_PSADBW;
    if (strcasecmp(tok, "pextrw") == 0) return MNEM_PEXTRW;
    if (strcasecmp(tok, "pinsrw") == 0) return MNEM_PINSRW;
    if (strcasecmp(tok, "maskmovq") == 0) return MNEM_MASKMOVQ;
    if (strcasecmp(tok, "movntq") == 0) return MNEM_MOVNTQ;
    // Prefix
    if (strcasecmp(tok, "lock") == 0) return MNEM_LOCK;
    return MNEM_INVALID;
}

static bool parse_number(const char *tok, uint64_t *out) {
    if (!tok || !*tok) return false;
    char *end = NULL;
    int base = 10;
    if (starts_with(tok, "0x") || starts_with(tok, "0X")) base = 16;
    errno = 0;
    uint64_t v = strtoull(tok, &end, base);
    if (errno != 0 || end == tok || *trim_leading(end) != '\0') return false;
    *out = v;
    return true;
}

static bool parse_float(const char *tok, uint32_t *out) {
    if (!tok || !*tok) return false;
    char *end = NULL;
    errno = 0;
    float f = strtof(tok, &end);
    if (errno != 0 || end == tok || *trim_leading(end) != '\0') return false;
    // Convert float to its bit representation
    uint32_t bits;
    memcpy(&bits, &f, sizeof(float));
    *out = bits;
    return true;
}

static bool parse_double(const char *tok, uint64_t *out) {
    if (!tok || !*tok) return false;
    char *end = NULL;
    errno = 0;
    double d = strtod(tok, &end);
    if (errno != 0 || end == tok || *trim_leading(end) != '\0') return false;
    // Convert double to its bit representation
    uint64_t bits;
    memcpy(&bits, &d, sizeof(double));
    *out = bits;
    return true;
}

static uint64_t align_up(uint64_t v, size_t a) {
    if (a == 0) return v;
    return (v + (uint64_t)(a - 1)) & ~((uint64_t)a - 1);
}

static const char *skip_token(const char *s) {
    while (*s && !isspace((unsigned char)*s) && *s != ',') {
        s++;
    }
    return s;
}

static char *token_dup(const char *start, const char *end) {
    size_t n = (size_t)(end - start);
    char *p = malloc(n + 1);
    if (!p) {
        fprintf(stderr, "fatal: out of memory\n");
        exit(EXIT_FAILURE);
    }
    memcpy(p, start, n);
    p[n] = '\0';
    return p;
}

static bool parse_mem_term(const char *tok, int sign, reg_kind *base, reg_kind *index, uint8_t *scale, int64_t *disp, const char **sym, bool *rip_rel, asm_unit *unit) {
    // handle reg*scale or reg
    char *mul = strchr(tok, '*');
    if (mul) {
        char *lhs = token_dup(tok, mul);
        char *rhs = token_dup(mul + 1, tok + strlen(tok));
        reg_kind r = parse_reg(lhs);
        uint64_t sc = 0;
        bool ok = parse_number(rhs, &sc);
        free(lhs);
        free(rhs);
        if (r != REG_INVALID && ok && (sc == 1 || sc == 2 || sc == 4 || sc == 8)) {
            if (*index != REG_INVALID) return false;
            *index = r;
            *scale = (uint8_t)sc;
            return true;
        }
        return false;
    }

    reg_kind r = parse_reg(tok);
    if (r != REG_INVALID) {
        if (sign == -1) return false; // cannot negate register terms
        if (r == REG_RIP) {
            *rip_rel = true;
            *base = REG_RIP;
            return true;
        }
        if (*base == REG_INVALID) {
            *base = r;
            return true;
        }
        if (*index == REG_INVALID) {
            *index = r;
            *scale = 1;
            return true;
        }
        return false;
    }
    uint64_t num = 0;
    if (parse_number(tok, &num)) {
        int64_t v = (int64_t)num;
        *disp += sign == -1 ? -v : v;
        return true;
    }
    
    // Check if token is an absolute symbol (like struct field offset)
    if (unit) {
        const symbol *found_sym = find_symbol(unit, tok);
        if (found_sym && found_sym->is_defined && found_sym->section == SEC_ABS) {
            // It's an absolute symbol - use its value as displacement
            int64_t v = (int64_t)found_sym->value;
            *disp += sign == -1 ? -v : v;
            return true;
        }
    }
    
    // symbol
    if (*sym) return false;
    if (sign == -1) return false; // negative symbol not supported
    *sym = str_dup(tok);
    return true;
}

static bool parse_mem_operand(const char *expr, mem_ref *out, asm_unit *unit) {
    mem_ref m = { .base = REG_INVALID, .index = REG_INVALID, .scale = 1, .disp = 0, .sym = NULL, .rip_relative = false, .seg_override = REG_INVALID };
    
    // Check for segment override prefix (e.g., "es:" at the start)
    const char *p = expr;
    while (isspace((unsigned char)*p)) p++;
    
    // Look for segment:rest pattern
    const char *colon = strchr(p, ':');
    if (colon) {
        // Extract potential segment register name
        char seg_name[8];
        size_t seg_len = colon - p;
        if (seg_len < sizeof(seg_name)) {
            // Trim whitespace before colon
            while (seg_len > 0 && isspace((unsigned char)p[seg_len - 1])) seg_len--;
            memcpy(seg_name, p, seg_len);
            seg_name[seg_len] = '\0';
            
            reg_kind seg = parse_reg(seg_name);
            if (seg >= REG_ES && seg <= REG_GS) {
                m.seg_override = seg;
                // Skip past the segment prefix for further parsing
                expr = colon + 1;
            }
        }
    }
    p = expr;
    while (*p) {
        while (isspace((unsigned char)*p)) p++;
        if (*p == '\0') break;
        const char *term_start = p;
        int sign = 1;
        if (*p == '+') { sign = 1; p++; term_start = p; }
        else if (*p == '-') { sign = -1; p++; term_start = p; }
        while (isspace((unsigned char)*p)) p++;
        term_start = p;
        const char *term_end = p;
        while (*term_end && *term_end != '+' && *term_end != '-' ) term_end++;
        // Trim trailing whitespace from term
        while (term_end > term_start && isspace((unsigned char)*(term_end - 1))) term_end--;
        char *tok = token_dup(term_start, term_end);
        bool ok = parse_mem_term(tok, sign, &m.base, &m.index, &m.scale, &m.disp, &m.sym, &m.rip_relative, unit);
        free(tok);
        if (!ok) return false;
        // Skip past any whitespace after the term
        while (*term_end && isspace((unsigned char)*term_end)) term_end++;
        p = term_end;
    }
    *out = m;
    return true;
}

static bool parse_escape_char(const char **p, char *out) {
    char c = *(*p)++;
    switch (c) {
        case '\\': *out = '\\'; return true;
        case '\"': *out = '"'; return true;
        case 'n': *out = '\n'; return true;
        case 't': *out = '\t'; return true;
        case 'r': *out = '\r'; return true;
        case '0': *out = '\0'; return true;
        default: *out = c; return true;
    }
}

static bool is_local_label(const char *name) {
    return name && name[0] == '.';
}

static char *make_full_local_label(const char *global_label, const char *local_name) {
    if (!global_label || !local_name || local_name[0] != '.') {
        return str_dup(local_name);
    }
    // Create "global_label.local" format
    size_t glen = strlen(global_label);
    size_t llen = strlen(local_name);
    char *full = malloc(glen + llen + 1);
    if (!full) {
        fprintf(stderr, "fatal: out of memory\n");
        exit(EXIT_FAILURE);
    }
    memcpy(full, global_label, glen);
    memcpy(full + glen, local_name, llen + 1);
    return full;
}

static const char *resolve_label_name(asm_unit *unit, const char *name) {
    if (is_local_label(name) && unit->current_global_label) {
        return make_full_local_label(unit->current_global_label, name);
    }
    return str_dup(name);
}

static void add_symbol(asm_unit *unit, const char *name, section_kind sec, uint64_t value, bool defined, bool make_global, bool make_extern) {
    for (size_t i = 0; i < unit->symbols.len; ++i) {
        if (strcmp(unit->symbols.data[i].name, name) == 0) {
            if (defined && unit->symbols.data[i].is_defined) {
                fprintf(stderr, "error: duplicate symbol: %s\n", name);
            }
            if (defined) {
                unit->symbols.data[i].section = sec;
                unit->symbols.data[i].value = value;
                unit->symbols.data[i].is_defined = true;
            }
            if (make_global) unit->symbols.data[i].is_global = true;
            if (make_extern) unit->symbols.data[i].is_extern = true;
            return;
        }
    }
    symbol sym = { .name = str_dup(name), .section = sec, .value = value, .is_defined = defined, .is_global = make_global, .is_extern = make_extern };
    VEC_PUSH(unit->symbols, sym);
}

static operand parse_operand_token(const char *tok, asm_unit *unit) {
    operand op = { .kind = OP_IMM, .v.imm = 0 };
    
    // Strip size qualifiers (byte/word/dword/qword/ptr) before parsing
    const char *size_qualifiers[] = {"byte", "word", "dword", "qword", "tword", "oword", "yword", "zword"};
    const char *actual_tok = tok;
    for (size_t i = 0; i < sizeof(size_qualifiers) / sizeof(size_qualifiers[0]); i++) {
        size_t qual_len = strlen(size_qualifiers[i]);
        if (strncasecmp(tok, size_qualifiers[i], qual_len) == 0) {
            const char *p = tok + qual_len;
            // Skip whitespace after size qualifier
            while (*p && isspace((unsigned char)*p)) p++;
            // Also skip optional "ptr" keyword
            if (strncasecmp(p, "ptr", 3) == 0) {
                p += 3;
                while (*p && isspace((unsigned char)*p)) p++;
            }
            actual_tok = p;
            break;
        }
    }
    
    size_t len = strlen(actual_tok);
    if (len >= 2 && actual_tok[0] == '[' && actual_tok[len - 1] == ']') {
        char *inner = token_dup(actual_tok + 1, actual_tok + len - 1);
        mem_ref m;
        if (!parse_mem_operand(inner, &m, unit)) {
            free(inner);
            op.kind = OP_INVALID;
            return op;
        }
        // Resolve local label in memory operand symbol
        if (m.sym && is_local_label(m.sym)) {
            const char *resolved = resolve_label_name(unit, m.sym);
            free((void*)m.sym);
            m.sym = resolved;
        }
        free(inner);
        op.kind = OP_MEM;
        op.v.mem = m;
        return op;
    }
    uint64_t num = 0;
    reg_kind r = parse_reg(actual_tok);
    if (r != REG_INVALID) {
        op.kind = OP_REG;
        op.v.reg = r;
        return op;
    }
    if (parse_number(actual_tok, &num)) {
        op.kind = OP_IMM;
        op.v.imm = num;
        return op;
    }
    
    // Check for $ or $$ symbols (position markers)
    if (strcmp(actual_tok, "$") == 0 || strcmp(actual_tok, "$$") == 0) {
        expr_node *expr = parse_expression(actual_tok);
        if (expr) {
            op.kind = OP_EXPR;
            op.v.expr = expr;
            return op;
        }
    }
    
    // Try parsing as floating-point literal (for dd/dq directives)
    // Check if it contains a decimal point
    if (strchr(actual_tok, '.')) {
        uint32_t float_bits;
        uint64_t double_bits;
        // Try as float first (for dd)
        if (parse_float(actual_tok, &float_bits)) {
            op.kind = OP_IMM;
            op.v.imm = float_bits;
            return op;
        }
        // Try as double (for dq)
        if (parse_double(actual_tok, &double_bits)) {
            op.kind = OP_IMM;
            op.v.imm = double_bits;
            return op;
        }
    }
    
    // Try parsing as expression
    // Check if it looks like an expression (contains operators)
    bool has_expr_chars = false;
    for (const char *p = actual_tok; *p; p++) {
        if (strchr("+-*/%<>&|^~()", *p)) {
            has_expr_chars = true;
            break;
        }
    }
    
    if (has_expr_chars) {
        expr_node *expr = parse_expression(actual_tok);
        if (expr) {
            // Resolve local labels in expression
            // For now, we'll need to walk the tree and resolve symbols
            // This is a simplified version - we resolve at evaluation time
            op.kind = OP_EXPR;
            op.v.expr = expr;
            return op;
        }
    }
    
    // Fall back to symbol - resolve local labels
    const char *resolved_name = resolve_label_name(unit, actual_tok);
    op.kind = OP_SYMBOL;
    op.v.sym = resolved_name;
    return op;
}

static data_width parse_width_kw(const char *tok) {
    if (strcasecmp(tok, "db") == 0) return DATA_DB;
    if (strcasecmp(tok, "dw") == 0) return DATA_DW;
    if (strcasecmp(tok, "dd") == 0) return DATA_DD;
    if (strcasecmp(tok, "dq") == 0) return DATA_DQ;
    return DATA_DB;
}

static size_t width_bytes(data_width w) {
    switch (w) {
        case DATA_DB: return 1;
        case DATA_DW: return 2;
        case DATA_DD: return 4;
        case DATA_DQ: return 8;
    }
    return 1;
}

static rasm_status parse_source(const char *src, asm_unit *unit, FILE *log) {
    unit->current_section = SEC_TEXT;
    const char *cursor = src;
    size_t line_no = 1;

    while (*cursor) {
        const char *nl = strchr(cursor, '\n');
        size_t line_len = nl ? (size_t)(nl - cursor) : strlen(cursor);
        char *line_buf = malloc(line_len + 1);
        if (!line_buf) return RASM_ERR_IO;
        memcpy(line_buf, cursor, line_len);
        line_buf[line_len] = '\0';

        // strip comment
        char *comment = strchr(line_buf, ';');
        if (comment) *comment = '\0';
        char *p = line_buf;
        while (*p && isspace((unsigned char)*p)) p++;
        if (*p == '\0') {
            free(line_buf);
            if (!nl) break;
            cursor = nl + 1;
            line_no++;
            continue;
        }

        // handle labels (may be multiple leading labels)
        while (true) {
            // Find colon, but skip over strings and brackets
            char *colon = NULL;
            char *scan = p;
            bool in_string = false;
            char quote_char = '\0';
            int bracket_depth = 0;
            while (*scan && !colon) {
                if (!in_string && (*scan == '"' || *scan == '\'')) {
                    in_string = true;
                    quote_char = *scan;
                } else if (in_string && *scan == quote_char && (scan == p || *(scan - 1) != '\\')) {
                    in_string = false;
                } else if (!in_string && *scan == '[') {
                    bracket_depth++;
                } else if (!in_string && *scan == ']') {
                    bracket_depth--;
                } else if (!in_string && bracket_depth == 0 && *scan == ':') {
                    colon = scan;
                    break;
                }
                scan++;
            }
            
            if (colon) {
                *colon = '\0';
                char *name_end = colon - 1;
                while (name_end >= p && isspace((unsigned char)*name_end)) {
                    *name_end-- = '\0';
                }
                if (*p == '\0') {
                    if (log) fprintf(log, "parse error line %zu: empty label name\n", line_no);
                    free(line_buf);
                    return RASM_ERR_INVALID_ARGUMENT;
                }
                
                // Track global labels for local label scoping
                if (!is_local_label(p)) {
                    unit->current_global_label = str_dup(p);
                }
                
                statement st = { .kind = STMT_LABEL, .section = unit->current_section };
                st.v.label.line = line_no;
                // Resolve local labels to full name
                const char *full_name = resolve_label_name(unit, p);
                st.v.label.name = full_name;
                VEC_PUSH(unit->stmts, st);
                p = colon + 1;
                while (*p && isspace((unsigned char)*p)) p++;
                if (*p == '\0') {
                    break;
                }
                continue;
            }
            break;
        }

        if (*p == '\0') {
            free(line_buf);
            if (!nl) break;
            cursor = nl + 1;
            line_no++;
            continue;
        }

        // parse directive or instruction
        const char *tok_start = p;
        const char *tok_end = skip_token(tok_start);
        char *head = token_dup(tok_start, tok_end);
        p = (char *)tok_end;
        while (*p && isspace((unsigned char)*p)) p++;

        if (head[0] == '.') {
            const char *name = head + 1;
            if (strcasecmp(name, "text") == 0) {
                unit->current_section = SEC_TEXT;
            } else if (strcasecmp(name, "data") == 0) {
                unit->current_section = SEC_DATA;
            } else if (strcasecmp(name, "bss") == 0) {
                unit->current_section = SEC_BSS;
            } else if (strcasecmp(name, "align") == 0 || strcasecmp(name, "balign") == 0) {
                uint64_t a = 0;
                if (!parse_number(p, &a)) {
                    if (log) fprintf(log, "parse error line %zu: expected numeric alignment after %s\n", line_no, head);
                    free(head);
                    free(line_buf);
                    return RASM_ERR_INVALID_ARGUMENT;
                }
                statement st = { .kind = STMT_ALIGN, .section = unit->current_section };
                st.v.align.align = (size_t)a;
                st.v.align.line = line_no;
                VEC_PUSH(unit->stmts, st);
            } else if (strcasecmp(name, "global") == 0 || strcasecmp(name, "globl") == 0) {
                char *q = p;
                while (*q) {
                    while (*q && (isspace((unsigned char)*q) || *q == ',')) q++;
                    if (*q == '\0') break;
                    const char *ns = q;
                    const char *ne = skip_token(ns);
                    char *sym = token_dup(ns, ne);
                    add_symbol(unit, sym, unit->current_section, 0, false, true, false);
                    free(sym);
                    q = (char *)ne;
                }
            } else if (strcasecmp(name, "extern") == 0) {
                char *q = p;
                while (*q) {
                    while (*q && (isspace((unsigned char)*q) || *q == ',')) q++;
                    if (*q == '\0') break;
                    const char *ns = q;
                    const char *ne = skip_token(ns);
                    char *sym = token_dup(ns, ne);
                    add_symbol(unit, sym, unit->current_section, 0, false, false, true);
                    free(sym);
                    q = (char *)ne;
                }
            } else if (strcasecmp(name, "section") == 0 && *p == '.') {
                // fallback for "section .text"
                const char *next_start = p + 1;
                const char *next_end = skip_token(next_start);
                char *sect = token_dup(next_start, next_end);
                if (strcasecmp(sect, "text") == 0) unit->current_section = SEC_TEXT;
                else if (strcasecmp(sect, "data") == 0) unit->current_section = SEC_DATA;
                else if (strcasecmp(sect, "bss") == 0) unit->current_section = SEC_BSS;
                free(sect);
            } else {
                if (log) fprintf(log, "parse error line %zu: unknown directive %s\n", line_no, head);
                free(head);
                free(line_buf);
                return RASM_ERR_INVALID_ARGUMENT;
            }
            free(head);
            free(line_buf);
            if (!nl) break;
            cursor = nl + 1;
            line_no++;
            continue;
        } else if (strcasecmp(head, "section") == 0) {
            if (*p == '.') p++;
            const char *next_start = p;
            const char *next_end = skip_token(next_start);
            char *sect = token_dup(next_start, next_end);
            if (strcasecmp(sect, "text") == 0) unit->current_section = SEC_TEXT;
            else if (strcasecmp(sect, "data") == 0) unit->current_section = SEC_DATA;
            else if (strcasecmp(sect, "bss") == 0) unit->current_section = SEC_BSS;
            else {
                if (log) fprintf(log, "parse error line %zu: unknown section %s\n", line_no, sect);
                free(sect);
                free(head);
                free(line_buf);
                return RASM_ERR_INVALID_ARGUMENT;
            }
            free(sect);
            free(head);
            free(line_buf);
            if (!nl) break;
            cursor = nl + 1;
            line_no++;
            continue;
        } else if (strcasecmp(head, "align") == 0 || strcasecmp(head, "balign") == 0) {
            uint64_t a = 0;
            if (!parse_number(p, &a)) {
                if (log) fprintf(log, "parse error line %zu: expected numeric alignment after %s\n", line_no, head);
                free(head);
                free(line_buf);
                return RASM_ERR_INVALID_ARGUMENT;
            }
            statement st = { .kind = STMT_ALIGN, .section = unit->current_section };
            st.v.align.align = (size_t)a;
            st.v.align.line = line_no;
            VEC_PUSH(unit->stmts, st);
            free(head);
            free(line_buf);
            if (!nl) break;
            cursor = nl + 1;
            line_no++;
            continue;
        } else if (strcasecmp(head, "global") == 0 || strcasecmp(head, "globl") == 0) {
            char *q = p;
            while (*q) {
                while (*q && (isspace((unsigned char)*q) || *q == ',')) q++;
                if (*q == '\0') break;
                const char *ns = q;
                const char *ne = skip_token(ns);
                char *sym = token_dup(ns, ne);
                add_symbol(unit, sym, unit->current_section, 0, false, true, false);
                free(sym);
                q = (char *)ne;
            }
            free(head);
            free(line_buf);
            if (!nl) break;
            cursor = nl + 1;
            line_no++;
            continue;
        } else if (strcasecmp(head, "extern") == 0) {
            char *q = p;
            while (*q) {
                while (*q && (isspace((unsigned char)*q) || *q == ',')) q++;
                if (*q == '\0') break;
                const char *ns = q;
                const char *ne = skip_token(ns);
                char *sym = token_dup(ns, ne);
                add_symbol(unit, sym, unit->current_section, 0, false, false, true);
                free(sym);
                q = (char *)ne;
            }
            free(head);
            free(line_buf);
            if (!nl) break;
            cursor = nl + 1;
            line_no++;
            continue;
        } else if (strcasecmp(head, "org") == 0) {
            // org directive - set origin address
            uint64_t addr = 0;
            if (!parse_number(p, &addr)) {
                if (log) fprintf(log, "parse error line %zu: expected numeric address after org\n", line_no);
                free(head);
                free(line_buf);
                return RASM_ERR_INVALID_ARGUMENT;
            }
            unit->origin = addr;
            free(head);
            free(line_buf);
            if (!nl) break;
            cursor = nl + 1;
            line_no++;
            continue;
        } else if (strcasecmp(head, "bits") == 0) {
            // bits directive - switch between 16/32/64-bit mode
            uint64_t bits = 0;
            if (!parse_number(p, &bits)) {
                if (log) fprintf(log, "parse error line %zu: expected numeric value after bits\n", line_no);
                free(head);
                free(line_buf);
                return RASM_ERR_INVALID_ARGUMENT;
            }
            if (bits == 16) {
                unit->arch = ARCH_X86_16;
            } else if (bits == 32) {
                unit->arch = ARCH_X86_32;
            } else if (bits == 64) {
                unit->arch = ARCH_X86_64;
            } else {
                if (log) fprintf(log, "parse error line %zu: bits must be 16, 32, or 64\n", line_no);
                free(head);
                free(line_buf);
                return RASM_ERR_INVALID_ARGUMENT;
            }
            free(head);
            free(line_buf);
            if (!nl) break;
            cursor = nl + 1;
            line_no++;
            continue;
        } else if (strcasecmp(head, "struc") == 0) {
            // struc directive - define a structure
            const char *struc_start = p;
            const char *struc_end = skip_token(struc_start);
            if (struc_start == struc_end) {
                if (log) fprintf(log, "parse error line %zu: expected struct name after struc\n", line_no);
                free(head);
                free(line_buf);
                return RASM_ERR_INVALID_ARGUMENT;
            }
            char *struc_name = token_dup(struc_start, struc_end);
            
            // Parse struct body until endstruc
            struct_field *fields = NULL;
            size_t field_count = 0;
            size_t field_cap = 0;
            size_t offset = 0;
            
            free(head);
            free(line_buf);
            if (!nl) {
                if (log) fprintf(log, "parse error line %zu: unexpected end after struc\n", line_no);
                free(struc_name);
                return RASM_ERR_INVALID_ARGUMENT;
            }
            cursor = nl + 1;
            line_no++;
            
            // Parse fields
            while (true) {
                // Get next line
                if (*cursor == '\0') {
                    if (log) fprintf(log, "parse error line %zu: struc %s not closed with endstruc\n", line_no, struc_name);
                    free(struc_name);
                    free(fields);
                    return RASM_ERR_INVALID_ARGUMENT;
                }
                
                nl = strchr(cursor, '\n');
                line_buf = nl ? strndup(cursor, nl - cursor) : strdup(cursor);
                if (!line_buf) {
                    fprintf(stderr, "fatal: out of memory\n");
                    exit(EXIT_FAILURE);
                }
                
                char *lp = line_buf;
                // Trim and check for comment
                while (*lp && isspace((unsigned char)*lp)) lp++;
                if (*lp == '\0' || *lp == ';') {
                    free(line_buf);
                    if (!nl) {
                        if (log) fprintf(log, "parse error line %zu: struc %s not closed with endstruc\n", line_no, struc_name);
                        free(struc_name);
                        free(fields);
                        return RASM_ERR_INVALID_ARGUMENT;
                    }
                    cursor = nl + 1;
                    line_no++;
                    continue;
                }
                
                // Parse first token
                const char *tok_start = lp;
                const char *tok_end = skip_token(tok_start);
                head = token_dup(tok_start, tok_end);
                lp = (char *)tok_end;
                while (*lp && isspace((unsigned char)*lp)) lp++;
                
                // Check for endstruc
                if (strcasecmp(head, "endstruc") == 0) {
                    free(head);
                    free(line_buf);
                    break;
                }
                
                // Field must start with '.' or be a label with ':'
                if (head[0] == '.') {
                    // It's a field name like .field:
                    char *field_name = str_dup(head);
                    // Remove trailing ':' if present
                    size_t len = strlen(field_name);
                    if (len > 0 && field_name[len - 1] == ':') {
                        field_name[len - 1] = '\0';
                    }
                    
                    // Expect resb/resw/resd/resq
                    tok_start = lp;
                    tok_end = skip_token(tok_start);
                    if (tok_start == tok_end) {
                        if (log) fprintf(log, "parse error line %zu: expected resb/resw/resd/resq after field name\n", line_no);
                        free(field_name);
                        free(head);
                        free(line_buf);
                        free(struc_name);
                        free(fields);
                        return RASM_ERR_INVALID_ARGUMENT;
                    }
                    
                    char *res_tok = token_dup(tok_start, tok_end);
                    lp = (char *)tok_end;
                    while (*lp && isspace((unsigned char)*lp)) lp++;
                    
                    // Parse count
                    uint64_t count = 1;
                    if (*lp != '\0' && *lp != ';') {
                        if (!parse_number(lp, &count)) {
                            count = 1;
                        }
                    }
                    
                    size_t field_size = 0;
                    if (strcasecmp(res_tok, "resb") == 0) field_size = 1 * count;
                    else if (strcasecmp(res_tok, "resw") == 0) field_size = 2 * count;
                    else if (strcasecmp(res_tok, "resd") == 0) field_size = 4 * count;
                    else if (strcasecmp(res_tok, "resq") == 0) field_size = 8 * count;
                    else {
                        if (log) fprintf(log, "parse error line %zu: expected resb/resw/resd/resq, got %s\n", line_no, res_tok);
                        free(field_name);
                        free(res_tok);
                        free(head);
                        free(line_buf);
                        free(struc_name);
                        free(fields);
                        return RASM_ERR_INVALID_ARGUMENT;
                    }
                    free(res_tok);
                    
                    // Add field
                    if (field_count >= field_cap) {
                        field_cap = field_cap == 0 ? 4 : field_cap * 2;
                        fields = realloc(fields, field_cap * sizeof(struct_field));
                        if (!fields) {
                            fprintf(stderr, "fatal: out of memory\n");
                            exit(EXIT_FAILURE);
                        }
                    }
                    
                    fields[field_count].name = field_name;
                    fields[field_count].offset = offset;
                    fields[field_count].size = field_size;
                    field_count++;
                    
                    // Define symbol for struct.field as absolute constant
                    char full_name[512];
                    snprintf(full_name, sizeof(full_name), "%s%s", struc_name, field_name);
                    add_symbol(unit, full_name, SEC_ABS, offset, true, false, false);
                    
                    offset += field_size;
                }
                
                free(head);
                free(line_buf);
                if (!nl) {
                    if (log) fprintf(log, "parse error line %zu: struc %s not closed with endstruc\n", line_no, struc_name);
                    free(struc_name);
                    free(fields);
                    return RASM_ERR_INVALID_ARGUMENT;
                }
                cursor = nl + 1;
                line_no++;
            }
            
            // Save struct definition
            struct_def new_struct;
            new_struct.name = struc_name;
            new_struct.fields = fields;
            new_struct.field_count = field_count;
            new_struct.total_size = offset;
            VEC_STRUCT_PUSH(unit->structs, new_struct);
            
            // Define symbol for struct size (struct_size) as absolute constant
            char size_name[512];
            snprintf(size_name, sizeof(size_name), "%s_size", struc_name);
            add_symbol(unit, size_name, SEC_ABS, offset, true, false, false);
            
            if (!nl) break;
            cursor = nl + 1;
            line_no++;
            continue;
        }

        // times directive: times <count> <directive> <args>
        size_t times_count = 1;
        expr_node *times_expr = NULL;
        if (strcasecmp(head, "times") == 0) {
            // get the count token
            const char *count_start = p;
            const char *count_end = skip_token(count_start);
            char *count_tok = token_dup(count_start, count_end);
            operand count_op = parse_operand_token(count_tok, unit);
            
            int64_t count_val = 0;
            if (count_op.kind == OP_IMM) {
                count_val = count_op.v.imm;
                if (count_val <= 0) {
                    if (log) fprintf(log, "parse error line %zu: times count must be positive\n", line_no);
                    free(count_tok);
                    free(head);
                    free(line_buf);
                    return RASM_ERR_INVALID_ARGUMENT;
                }
                times_count = (size_t)count_val;
            } else if (count_op.kind == OP_EXPR) {
                // Store expression for later evaluation
                times_expr = count_op.v.expr;
            } else {
                if (log) fprintf(log, "parse error line %zu: expected numeric count after times\n", line_no);
                free(count_tok);
                free(head);
                free(line_buf);
                return RASM_ERR_INVALID_ARGUMENT;
            }
            
            free(count_tok);
            // skip to next token after the count
            p = (char *)count_end;
            while (*p && isspace((unsigned char)*p)) p++;
            // get the next directive
            free(head);
            const char *next_start = p;
            const char *next_end = skip_token(next_start);
            head = token_dup(next_start, next_end);
            p = (char *)next_end;
            while (*p && isspace((unsigned char)*p)) p++;
        }

        // data directives (db/dw/dd/dq/resb/resw/resd/resq)
        bool is_reserve = false;
        data_width dw = DATA_DB;
        if (strcasecmp(head, "db") == 0 || strcasecmp(head, "dw") == 0 ||
            strcasecmp(head, "dd") == 0 || strcasecmp(head, "dq") == 0) {
            dw = parse_width_kw(head);
        } else if (strcasecmp(head, "resb") == 0 || strcasecmp(head, "resw") == 0 ||
                   strcasecmp(head, "resd") == 0 || strcasecmp(head, "resq") == 0) {
            is_reserve = true;
            if (tolower((unsigned char)head[3]) == 'b') dw = DATA_DB;
            else if (tolower((unsigned char)head[3]) == 'w') dw = DATA_DW;
            else if (tolower((unsigned char)head[3]) == 'd') dw = DATA_DD;
            else if (tolower((unsigned char)head[3]) == 'q') dw = DATA_DQ;
        }

        if (is_reserve) {
            // Try to parse as operand to support both numbers and symbols
            const char *count_start = p;
            const char *count_end = skip_token(count_start);
            char *count_tok = token_dup(count_start, count_end);
            operand count_op = parse_operand_token(count_tok, unit);
            
            uint64_t count = 0;
            if (count_op.kind == OP_IMM) {
                count = (uint64_t)count_op.v.imm;
            } else if (count_op.kind == OP_SYMBOL) {
                // Look up the symbol and get its value
                const symbol *sym = find_symbol(unit, count_op.v.sym);
                if (sym && sym->is_defined && sym->section == SEC_ABS) {
                    count = (uint64_t)sym->value;
                    free((void*)count_op.v.sym);
                } else {
                    if (log) fprintf(log, "parse error line %zu: expected numeric count after %s (symbol %s not yet defined or not absolute)\n", 
                                     line_no, head, count_op.v.sym);
                    free((void*)count_op.v.sym);
                    free(count_tok);
                    free(head);
                    free(line_buf);
                    return RASM_ERR_INVALID_ARGUMENT;
                }
            } else if (count_op.kind == OP_EXPR) {
                // For now, we can't resolve expressions here
                // But we should at least not error if it's a symbol
                // Try to resolve the symbol if it exists
                const char *unresolved = NULL;
                int64_t val = 0;
                if (eval_expression(count_op.v.expr, unit, &val, &unresolved)) {
                    count = (uint64_t)val;
                    expr_free(count_op.v.expr);
                } else {
                    // Can't resolve yet - error for now
                    if (log) fprintf(log, "parse error line %zu: expected numeric count after %s (symbol %s not yet defined)\n", 
                                     line_no, head, unresolved ? unresolved : "unknown");
                    free(count_tok);
                    free(head);
                    free(line_buf);
                    expr_free(count_op.v.expr);
                    return RASM_ERR_INVALID_ARGUMENT;
                }
            } else {
                if (log) fprintf(log, "parse error line %zu: expected numeric count after %s\n", line_no, head);
                free(count_tok);
                free(head);
                free(line_buf);
                return RASM_ERR_INVALID_ARGUMENT;
            }
            free(count_tok);
            
            statement st = { .kind = STMT_RESERVE, .section = unit->current_section };
            st.v.res.count = (size_t)count * times_count;
            st.v.res.width = dw;
            st.v.res.line = line_no;
            VEC_PUSH(unit->stmts, st);
            free(head);
            free(line_buf);
            if (!nl) break;
            cursor = nl + 1;
            line_no++;
            continue;
        }

        if (strcasecmp(head, "db") == 0 || strcasecmp(head, "dw") == 0 ||
            strcasecmp(head, "dd") == 0 || strcasecmp(head, "dq") == 0) {
            // If we have a times expression (containing $ or $$), create a STMT_TIMES
            if (times_expr) {
                // Parse the single value
                char *q = p;
                while (*q && isspace((unsigned char)*q)) q++;
                if (*q == '\0') {
                    if (log) fprintf(log, "parse error line %zu: expected value after %s\n", line_no, head);
                    expr_free(times_expr);
                    free(head);
                    free(line_buf);
                    return RASM_ERR_INVALID_ARGUMENT;
                }
                const char *val_start = q;
                const char *val_end = skip_token(val_start);
                char *tok = token_dup(val_start, val_end);
                operand op = parse_operand_token(tok, unit);
                if (op.kind == OP_INVALID) {
                    if (log) fprintf(log, "parse error line %zu: invalid operand\n", line_no);
                    free(tok);
                    expr_free(times_expr);
                    free(head);
                    free(line_buf);
                    return RASM_ERR_INVALID_ARGUMENT;
                }
                statement st = { .kind = STMT_TIMES, .section = unit->current_section };
                st.v.times.kind = TIMES_DATA;
                st.v.times.count_expr = times_expr;
                st.v.times.u.data.width = dw;
                st.v.times.u.data.value = op;
                st.v.times.line = line_no;
                VEC_PUSH(unit->stmts, st);
                free(tok);
                free(head);
                free(line_buf);
                if (!nl) break;
                cursor = nl + 1;
                line_no++;
                continue;
            }
            
            // comma separated values
            for (size_t times_idx = 0; times_idx < times_count; times_idx++) {
                char *q = p;
                while (*q) {
                    while (*q && isspace((unsigned char)*q)) q++;
                    if (*q == '\0') break;
                    if (*q == '"' || *q == '\'') {
                        if (dw != DATA_DB) {
                            if (log) fprintf(log, "parse error line %zu: string literal only valid with db\n", line_no);
                            free(head);
                            free(line_buf);
                            return RASM_ERR_INVALID_ARGUMENT;
                        }
                        char quote_char = *q;
                        q++; // skip opening quote
                        while (*q && *q != quote_char) {
                            char ch = *q++;
                            if (ch == '\\') {
                                if (*q == '\0') {
                                    if (log) fprintf(log, "parse error line %zu: unterminated escape in string\n", line_no);
                                    free(head);
                                    free(line_buf);
                                    return RASM_ERR_INVALID_ARGUMENT;
                                }
                                (void)parse_escape_char((const char **)&q, &ch);
                            }
                            operand op = { .kind = OP_IMM, .v.imm = (uint8_t)ch };
                            statement st = { .kind = STMT_DATA, .section = unit->current_section };
                            st.v.data.width = dw;
                            st.v.data.value = op;
                            st.v.data.line = line_no;
                            VEC_PUSH(unit->stmts, st);
                        }
                        if (*q != quote_char) {
                            if (log) fprintf(log, "parse error line %zu: unterminated string literal\n", line_no);
                            free(head);
                            free(line_buf);
                            return RASM_ERR_INVALID_ARGUMENT;
                        }
                        q++; // closing quote
                    } else {
                        const char *val_start = q;
                        const char *val_end = skip_token(val_start);
                        char *tok = token_dup(val_start, val_end);
                        operand op = parse_operand_token(tok, unit);
                        if (op.kind == OP_INVALID) {
                            if (log) fprintf(log, "parse error line %zu: invalid operand\n", line_no);
                            free(tok);
                            free(head);
                            free(line_buf);
                            return RASM_ERR_INVALID_ARGUMENT;
                        }
                        statement st = { .kind = STMT_DATA, .section = unit->current_section };
                        st.v.data.width = dw;
                        st.v.data.value = op;
                        st.v.data.line = line_no;
                        VEC_PUSH(unit->stmts, st);
                        free(tok);
                        q = (char *)val_end;
                    }
                    while (*q && isspace((unsigned char)*q)) q++;
                    if (*q == ',') q++;
                }
            }
            free(head);
            free(line_buf);
            if (!nl) break;
            cursor = nl + 1;
            line_no++;
            continue;
        }

        // Instruction
        mnemonic mnem = parse_mnemonic(head);
        if (mnem == MNEM_INVALID) {
            if (log) fprintf(log, "parse error line %zu: unknown mnemonic %s\n", line_no, head);
            free(head);
            free(line_buf);
            return RASM_ERR_INVALID_ARGUMENT;
        }
        
        // Handle instruction prefixes - parse the actual instruction from the same line
        instr_prefix prefix = PREFIX_NONE;
        if (mnem == MNEM_LOCK || mnem == MNEM_REP || mnem == MNEM_REPZ || mnem == MNEM_REPE || mnem == MNEM_REPNE || mnem == MNEM_REPNZ) {
            // Determine prefix byte
            if (mnem == MNEM_LOCK) {
                prefix = PREFIX_LOCK;
            } else if (mnem == MNEM_REP || mnem == MNEM_REPZ || mnem == MNEM_REPE) {
                prefix = PREFIX_REP; // REPE, REPZ, and REP all use prefix F3
            } else if (mnem == MNEM_REPNE || mnem == MNEM_REPNZ) {
                prefix = PREFIX_REPNE; // REPNE and REPNZ use prefix F2
            }
            
            // Parse the actual mnemonic following the prefix
            free(head);
            const char *instr_start = p;
            const char *instr_end = skip_token(instr_start);
            if (instr_start == instr_end) {
                if (log) fprintf(log, "parse error line %zu: expected instruction after prefix\n", line_no);
                free(line_buf);
                return RASM_ERR_INVALID_ARGUMENT;
            }
            head = token_dup(instr_start, instr_end);
            mnem = parse_mnemonic(head);
            if (mnem == MNEM_INVALID) {
                if (log) fprintf(log, "parse error line %zu: unknown mnemonic %s\n", line_no, head);
                free(head);
                free(line_buf);
                return RASM_ERR_INVALID_ARGUMENT;
            }
            p = (char *)instr_end;
            while (*p && isspace((unsigned char)*p)) p++;
        }
        
        instr_stmt inst = { .mnem = mnem, .op_count = 0, .prefix = prefix, .line = line_no };
        if (*p) {
            while (*p) {
                while (*p && (isspace((unsigned char)*p) || *p == ',')) p++;
                if (*p == '\0') break;
                const char *os = p;
                // Collect operand up to next comma (or end), preserving spaces for expressions
                const char *oe = os;
                int bracket_depth = 0;
                while (*oe && (*oe != ',' || bracket_depth > 0)) {
                    if (*oe == '[') bracket_depth++;
                    else if (*oe == ']') bracket_depth--;
                    oe++;
                }
                // Trim trailing whitespace from operand
                while (oe > os && isspace((unsigned char)*(oe - 1))) oe--;
                
                char *tok = token_dup(os, oe);
                operand opv = parse_operand_token(tok, unit);
                if (opv.kind == OP_INVALID) {
                    if (log) fprintf(log, "parse error line %zu: invalid operand\n", line_no);
                    free(tok);
                    free(head);
                    free(line_buf);
                    return RASM_ERR_INVALID_ARGUMENT;
                }
                inst.ops[inst.op_count++] = opv;
                free(tok);
                p = (char *)oe;
                if (inst.op_count >= 4) break;
            }
        }
        
        // If times_expr is set, create STMT_TIMES instead of repeating
        if (times_expr) {
            statement st = { .kind = STMT_TIMES, .section = unit->current_section };
            st.v.times.kind = TIMES_INSTR;
            st.v.times.count_expr = times_expr;
            st.v.times.u.instr = inst;
            st.v.times.line = line_no;
            VEC_PUSH(unit->stmts, st);
        } else {
            // Repeat the instruction times_count times
            for (size_t tc = 0; tc < times_count; tc++) {
                statement st = { .kind = STMT_INSTR, .section = unit->current_section };
                st.v.instr = inst;
                VEC_PUSH(unit->stmts, st);
            }
        }

        free(head);
        free(line_buf);
        if (!nl) break;
        cursor = nl + 1;
        line_no++;
    }

    return RASM_OK;
}

// Register helpers
static bool is_gpr(reg_kind r);
static bool is_gpr64(reg_kind r);
static bool is_gpr32(reg_kind r);
static bool is_gpr16(reg_kind r);
static bool is_gpr8(reg_kind r);
static bool is_gpr8_high(reg_kind r);
static bool is_xmm(reg_kind r);
static bool is_ymm(reg_kind r);
static uint8_t reg_code(reg_kind r);
static uint8_t gpr_low3(reg_kind r);
static bool gpr_is_high(reg_kind r);
static bool vec_is_high(reg_kind r);
// static bool mem_needs_rex(const mem_ref *m); // unused

static bool is_reg64(const operand *op) { return op->kind == OP_REG && is_gpr64(op->v.reg); }
static bool is_reg32(const operand *op) { return op->kind == OP_REG && is_gpr32(op->v.reg); }
static bool is_reg16(const operand *op) { return op->kind == OP_REG && is_gpr16(op->v.reg); }
static bool is_reg8(const operand *op) { return op->kind == OP_REG && (is_gpr8(op->v.reg) || is_gpr8_high(op->v.reg)); }
static bool is_memop(const operand *op) { return op->kind == OP_MEM; }
static bool is_imm(const operand *op) { return op->kind == OP_IMM || op->kind == OP_SYMBOL || op->kind == OP_EXPR; }
static bool is_xmmop(const operand *op) { return op->kind == OP_REG && is_xmm(op->v.reg); }
static bool is_ymmop(const operand *op) { return op->kind == OP_REG && is_ymm(op->v.reg); }
static bool is_vec_op(const operand *op) { return is_xmmop(op) || is_ymmop(op); }
static bool is_imm8(const operand *op) { return op->kind == OP_IMM && op->v.imm <= 0xFF; }
static bool is_simm8(const operand *op) { return op->kind == OP_IMM && (int64_t)op->v.imm >= -128 && (int64_t)op->v.imm <= 127; }

#if 0
// Unused helper - may be useful for future features
static bool operand_needs_rex(const operand *op) {
    if (op->kind == OP_REG) return gpr_is_high(op->v.reg) || vec_is_high(op->v.reg);
    if (op->kind == OP_MEM) return mem_needs_rex(&op->v.mem);
    return false;
}
#endif

static int cond_code_from_mnemonic(mnemonic m) {
    switch (m) {
        case MNEM_JO: case MNEM_CMOVO: case MNEM_SETO: return 0x0;
        case MNEM_JNO: case MNEM_CMOVNO: case MNEM_SETNO: return 0x1;
        case MNEM_JB: case MNEM_CMOVB: case MNEM_SETB: return 0x2;
        case MNEM_JAE: case MNEM_CMOVAE: case MNEM_SETAE: return 0x3;
        case MNEM_JE: case MNEM_CMOVE: case MNEM_SETE: return 0x4;
        case MNEM_JNE: case MNEM_CMOVNE: case MNEM_SETNE: return 0x5;
        case MNEM_JBE: case MNEM_CMOVBE: case MNEM_SETBE: return 0x6;
        case MNEM_JA: case MNEM_CMOVA: case MNEM_SETA: return 0x7;
        case MNEM_JS: case MNEM_CMOVS: case MNEM_SETS: return 0x8;
        case MNEM_JNS: case MNEM_CMOVNS: case MNEM_SETNS: return 0x9;
        case MNEM_JP: case MNEM_CMOVP: case MNEM_SETP: return 0xA;
        case MNEM_JNP: case MNEM_CMOVNP: case MNEM_SETNP: return 0xB;
        case MNEM_JL: case MNEM_CMOVL: case MNEM_SETL: return 0xC;
        case MNEM_JGE: case MNEM_CMOVGE: case MNEM_SETGE: return 0xD;
        case MNEM_JLE: case MNEM_CMOVLE: case MNEM_SETLE: return 0xE;
        case MNEM_JG: case MNEM_CMOVG: case MNEM_SETG: return 0xF;
        default: return -1;
    }
}

// Symbol lookup helper
static const symbol *find_symbol(const asm_unit *unit, const char *name) {
    for (size_t i = 0; i < unit->symbols.len; ++i) {
        if (strcmp(unit->symbols.data[i].name, name) == 0) {
            return &unit->symbols.data[i];
        }
    }
    return NULL;
}

// Immediate validation helper
static bool validate_immediate(int64_t value, int size_bits) {
    switch (size_bits) {
        case 8:
            return (value >= -128 && value <= 255);
        case 16:
            return (value >= -32768 && value <= 65535);
        case 32:
            return (value >= -2147483648LL && value <= 4294967295LL);
        case 64:
            return true; // 64-bit can hold any int64_t
        default:
            return false;
    }
}

// Get register size in bits
static int get_reg_size_bits(const operand *op) {
    if (op->kind != OP_REG) return 0;
    if (is_gpr64(op->v.reg)) return 64;
    if (is_gpr32(op->v.reg)) return 32;
    if (is_gpr16(op->v.reg)) return 16;
    if (is_gpr8(op->v.reg)) return 8;
    if (is_xmm(op->v.reg)) return 128;
    if (is_ymm(op->v.reg)) return 256;
    return 0;
}

// Validate register sizes match for binary operations
static bool validate_reg_sizes(const operand *op1, const operand *op2, FILE *log, size_t line) {
    if (op1->kind != OP_REG || op2->kind != OP_REG) return true; // Only validate reg-to-reg
    
    int size1 = get_reg_size_bits(op1);
    int size2 = get_reg_size_bits(op2);
    
    if (size1 != size2 && size1 > 0 && size2 > 0) {
        if (log) {
            fprintf(log, "encode error line %zu: register size mismatch (%d-bit vs %d-bit)\n", 
                    line, size1, size2);
        }
        return false;
    }
    return true;
}


#if 0
// Unused helper - may be useful for future features
static size_t branch_size(const instr_stmt *in, const asm_unit *unit, uint64_t here_off) {
    bool is_jcc = cond_code_from_mnemonic(in->mnem) >= 0;
    bool is_jmp = in->mnem == MNEM_JMP;
    if (!is_jcc && !is_jmp) return 0;
    if (in->op_count != 1) return 0;
    
    // Try short branch if target is a symbol
    if (in->ops[0].kind == OP_SYMBOL) {
        const symbol *sym = find_symbol(unit, in->ops[0].v.sym);
        if (sym && sym->is_defined && sym->section == SEC_TEXT) {
            int64_t target = (int64_t)sym->value;
            int64_t current = (int64_t)(here_off + (is_jcc ? 2 : 2)); // after short branch
            int64_t disp = target - current;
            
            // Short branch: -128 to +127
            if (disp >= -128 && disp <= 127) {
                return 2; // 1 byte opcode + 1 byte displacement
            }
        }
    }
    
    // Fall back to near branch
    return is_jcc ? 6 : 5; // 0x0F + opcode + 4-byte disp, or opcode + 4-byte disp
}
#endif

#if 0
// Unused helper - may be useful for future features
static size_t modrm_size_for_operand(const operand *op) {
    if (op->kind == OP_REG) return 1; // modrm only
    if (op->kind != OP_MEM) return 0;
    const mem_ref *m = &op->v.mem;
    bool use_sib = false;
    size_t disp = 0;
    reg_kind base = m->base;
    if (base == REG_INVALID && m->index != REG_INVALID) base = REG_RBP; // force base to allow SIB
    if (base == REG_RSP || base == REG_R12 || m->index != REG_INVALID || base == REG_INVALID) use_sib = true;
    bool has_disp = m->disp != 0;
    bool need_disp32 = m->rip_relative || m->sym != NULL || base == REG_RBP || base == REG_R13 || base == REG_INVALID || m->disp < -128 || m->disp > 127;
    if (need_disp32) disp = 4;
    else if (has_disp) disp = 1;
    return 1 + (use_sib ? 1 : 0) + disp;
}
#endif

#if 0
// Unused helper - may be useful for future instruction size calculation features
static size_t enc_instr_size(const instr_stmt *in, const asm_unit *unit, uint64_t here_off) {
    switch (in->mnem) {
        case MNEM_MOV:
            if (in->op_count == 2 && is_reg64(&in->ops[0]) && is_imm(&in->ops[1])) {
                return 1 + 1 + 8; // rex + opcode + imm64
            }
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg64(&in->ops[0])) && is_reg64(&in->ops[1])) {
                return 1 + 1 + 1 + modrm_size_for_operand(&in->ops[0]); // rex + opcode + modrm/sib/disp
            }
            if (in->op_count == 2 && is_reg64(&in->ops[0]) && (is_memop(&in->ops[1]) || is_reg64(&in->ops[1]))) {
                return 1 + 1 + 1 + modrm_size_for_operand(&in->ops[1]);
            }
            if (in->op_count == 2 && is_memop(&in->ops[0]) && is_imm(&in->ops[1])) {
                return 1 + 1 + 1 + modrm_size_for_operand(&in->ops[0]) + 4;
            }
            return 0;
        case MNEM_ADD:
        case MNEM_SUB:
        case MNEM_CMP:
        case MNEM_XOR:
        case MNEM_AND:
        case MNEM_OR: {
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg64(&in->ops[0])) && is_reg64(&in->ops[1])) {
                return 1 + 1 + modrm_size_for_operand(&in->ops[0]) + 1; // rex + opcode + modrm
            }
            if (in->op_count == 1 && (is_memop(&in->ops[0]) || is_reg64(&in->ops[0]))) {
                size_t rex = 1; // REX.W always emitted
                return rex + 1 + modrm_size_for_operand(&in->ops[0]);
            }
                return 1 + 1 + modrm_size_for_operand(&in->ops[1]) + 1;
            }
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg64(&in->ops[0])) && is_imm(&in->ops[1])) {
                size_t imm_sz = (in->ops[1].kind == OP_IMM && is_simm8(&in->ops[1])) ? 1 : 4;
                return 1 + 1 + modrm_size_for_operand(&in->ops[0]) + imm_sz + 1;
            }
            size_t rex = 1; // REX.W always emitted
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg64(&in->ops[0])) && is_imm8(&in->ops[1])) return rex + 1 + modrm_size_for_operand(&in->ops[0]) + 1;
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg64(&in->ops[0])) && in->ops[1].kind == OP_REG && in->ops[1].v.reg == REG_RCX) return rex + 1 + modrm_size_for_operand(&in->ops[0]);
            if (in->op_count == 1 && (is_memop(&in->ops[0]) || is_reg64(&in->ops[0]))) return rex + 1 + modrm_size_for_operand(&in->ops[0]); // implicit 1
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg64(&in->ops[0])) && is_reg64(&in->ops[1])) {
                return 1 + 1 + modrm_size_for_operand(&in->ops[0]) + 1;
            }
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg64(&in->ops[0])) && is_imm(&in->ops[1])) {
                return 1 + 1 + modrm_size_for_operand(&in->ops[0]) + 4 + 1;
            }
            return 0;
        case MNEM_LEA:
            if (in->op_count == 2 && is_reg64(&in->ops[0]) && is_memop(&in->ops[1])) {
                return 1 + 1 + modrm_size_for_operand(&in->ops[1]) + 1;
            }
            return 0;
        case MNEM_PUSH:
            if (in->op_count == 1 && is_reg64(&in->ops[0])) return 1 + (in->ops[0].v.reg >= 8 ? 1 : 0);
            if (in->op_count == 1 && is_memop(&in->ops[0])) return 1 + 1 + modrm_size_for_operand(&in->ops[0]);
            if (in->op_count == 1 && is_imm(&in->ops[0])) {
                if (in->ops[0].kind == OP_IMM && is_simm8(&in->ops[0])) return 1 + 1;
                return 1 + 4;
            }
            return 0;
        case MNEM_POP:
            if (in->op_count == 1 && is_reg64(&in->ops[0])) return 1 + (in->ops[0].v.reg >= 8 ? 1 : 0);
            if (in->op_count == 1 && is_memop(&in->ops[0])) return 1 + 1 + modrm_size_for_operand(&in->ops[0]);
            return 0;
        case MNEM_JMP:
        case MNEM_CALL: {
            if (in->op_count == 1 && (is_memop(&in->ops[0]) || is_reg64(&in->ops[0]))) return 1 + 1 + modrm_size_for_operand(&in->ops[0]);
            if (in->mnem == MNEM_CALL) return 1 + 4;
            size_t sz = branch_size(in, unit, here_off);
            return sz;
        }
        case MNEM_JE: case MNEM_JNE: case MNEM_JA: case MNEM_JAE: case MNEM_JB: case MNEM_JBE: case MNEM_JG: case MNEM_JGE: case MNEM_JL: case MNEM_JLE: case MNEM_JO: case MNEM_JNO: case MNEM_JS: case MNEM_JNS: case MNEM_JP: case MNEM_JNP: {
            size_t sz = branch_size(in, unit, here_off);
            return sz;
        }
        case MNEM_SETE: case MNEM_SETNE: case MNEM_SETA: case MNEM_SETAE: case MNEM_SETB: case MNEM_SETBE: case MNEM_SETG: case MNEM_SETGE: case MNEM_SETL: case MNEM_SETLE: case MNEM_SETO: case MNEM_SETNO: case MNEM_SETS: case MNEM_SETNS: case MNEM_SETP: case MNEM_SETNP: {
            if (in->op_count == 1 && (is_memop(&in->ops[0]) || is_reg64(&in->ops[0]))) {
                size_t rex = operand_needs_rex(&in->ops[0]) ? 1 : 0;
                return 2 + rex + modrm_size_for_operand(&in->ops[0]);
            }
            return 0;
        }
        case MNEM_MOVZX:
        case MNEM_MOVSX: {
            if (in->op_count == 2 && is_reg64(&in->ops[0]) && (is_reg64(&in->ops[1]) || is_memop(&in->ops[1]))) {
                size_t rex = (operand_needs_rex(&in->ops[0]) || operand_needs_rex(&in->ops[1])) ? 1 : 0;
                return 2 + rex + modrm_size_for_operand(&in->ops[1]);
            }
            return 0;
        }
        case MNEM_MOVSXD:
            if (in->op_count == 2 && is_reg64(&in->ops[0]) && (is_reg64(&in->ops[1]) || is_memop(&in->ops[1]))) {
                size_t rex = 1; // REX.W is required for movsxd
                return 1 + rex + modrm_size_for_operand(&in->ops[1]);
            }
            return 0;
        case MNEM_CMOVE: case MNEM_CMOVNE: case MNEM_CMOVA: case MNEM_CMOVAE: case MNEM_CMOVB: case MNEM_CMOVBE: case MNEM_CMOVG: case MNEM_CMOVGE: case MNEM_CMOVL: case MNEM_CMOVLE: case MNEM_CMOVO: case MNEM_CMOVNO: case MNEM_CMOVS: case MNEM_CMOVNS: case MNEM_CMOVP: case MNEM_CMOVNP:
            if (in->op_count == 2 && is_reg64(&in->ops[0]) && (is_memop(&in->ops[1]) || is_reg64(&in->ops[1]))) return 1 + 2 + modrm_size_for_operand(&in->ops[1]) + 1;
            return 0;
        case MNEM_MUL:
        case MNEM_IMUL:
        case MNEM_DIV:
        case MNEM_IDIV:
            if (in->op_count == 1 && (is_memop(&in->ops[0]) || is_reg64(&in->ops[0]))) return 1 + 1 + modrm_size_for_operand(&in->ops[0]) + 1;
            return 0;
        case MNEM_CQO:
            return 1 + 1;
        case MNEM_SYSCALL:
            return 2;
        case MNEM_RET:
        case MNEM_NOP:
            return 1;
        case MNEM_INC:
        case MNEM_DEC:
        case MNEM_NEG:
        case MNEM_NOT: {
            if (in->op_count == 1 && (is_memop(&in->ops[0]) || is_reg64(&in->ops[0]))) return 1 + modrm_size_for_operand(&in->ops[0]) + 1;
            return 0;
        }
        case MNEM_SHL:
        case MNEM_SAL:
        case MNEM_SHR:
        case MNEM_SAR: {
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg64(&in->ops[0])) && is_imm8(&in->ops[1])) return 1 + modrm_size_for_operand(&in->ops[0]) + 1 + 1;
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg64(&in->ops[0])) && in->ops[1].kind == OP_REG && in->ops[1].v.reg == REG_RCX) return 1 + modrm_size_for_operand(&in->ops[0]) + 1;
            if (in->op_count == 1 && (is_memop(&in->ops[0]) || is_reg64(&in->ops[0]))) return 1 + modrm_size_for_operand(&in->ops[0]) + 1; // implicit 1
            return 0;
        }
        case MNEM_MOVAPS:
        case MNEM_MOVUPS:
        case MNEM_MOVDQA:
        case MNEM_MOVDQU: {
            if (in->op_count != 2) return 0;
            size_t prefix_len = (in->mnem == MNEM_MOVDQA || in->mnem == MNEM_MOVDQU) ? 1 : 0;
            size_t rex = (operand_needs_rex(&in->ops[0]) || operand_needs_rex(&in->ops[1])) ? 1 : 0;
            size_t opcode_len = 2; // 0F xx
            const operand *rm = NULL;
            if (is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1]))) rm = &in->ops[1];
            else if (is_memop(&in->ops[0]) && is_xmmop(&in->ops[1])) rm = &in->ops[0];
            else return 0;
            return prefix_len + rex + opcode_len + modrm_size_for_operand(rm);
        }
        case MNEM_ADDPS:
        case MNEM_ADDPD:
        case MNEM_SUBPS:
        case MNEM_SUBPD:
        case MNEM_MULPS:
        case MNEM_MULPD:
        case MNEM_XORPS:
        case MNEM_XORPD: {
            if (in->op_count != 2 || !is_xmmop(&in->ops[0]) || !(is_xmmop(&in->ops[1]) || is_memop(&in->ops[1]))) return 0;
            size_t prefix_len = (in->mnem == MNEM_ADDPD || in->mnem == MNEM_SUBPD || in->mnem == MNEM_MULPD || in->mnem == MNEM_XORPD) ? 1 : 0;
            size_t rex = (operand_needs_rex(&in->ops[0]) || operand_needs_rex(&in->ops[1])) ? 1 : 0;
            return prefix_len + rex + 2 + modrm_size_for_operand(&in->ops[1]);
        }
        case MNEM_VMOVAPS:
        case MNEM_VMOVUPS:
        case MNEM_VMOVDQA:
        case MNEM_VMOVDQU: {
            if (in->op_count != 2) return 0;
            const operand *rm = NULL;
            if (is_vec_op(&in->ops[0]) && (is_vec_op(&in->ops[1]) || is_memop(&in->ops[1]))) rm = &in->ops[1];
            else if (is_memop(&in->ops[0]) && is_vec_op(&in->ops[1])) rm = &in->ops[0];
            else return 0;
            return 3 + 1 + modrm_size_for_operand(rm); // VEX3 + opcode + modrm/sib/disp
        }
        case MNEM_VADDPS:
        case MNEM_VADDPD:
        case MNEM_VSUBPS:
        case MNEM_VSUBPD:
        case MNEM_VMULPS:
        case MNEM_VMULPD:
        case MNEM_VXORPS:
        case MNEM_VXORPD: {
            if (in->op_count == 3 && is_vec_op(&in->ops[0]) && is_vec_op(&in->ops[1]) && (is_vec_op(&in->ops[2]) || is_memop(&in->ops[2]))) {
                if ((is_xmmop(&in->ops[0]) != is_xmmop(&in->ops[1])) || (is_ymmop(&in->ops[0]) != is_ymmop(&in->ops[1]))) return 0;
                if (is_vec_op(&in->ops[2])) {
                    if ((is_xmmop(&in->ops[0]) != is_xmmop(&in->ops[2])) || (is_ymmop(&in->ops[0]) != is_ymmop(&in->ops[2]))) return 0;
                }
                return 3 + 1 + modrm_size_for_operand(&in->ops[2]); // VEX3 + opcode + modrm/sib/disp
            }
            return 0;
        }
        case MNEM_VPTEST: {
            if (in->op_count == 2 && is_vec_op(&in->ops[0]) && (is_vec_op(&in->ops[1]) || is_memop(&in->ops[1]))) {
                if (is_vec_op(&in->ops[1]) && ((is_xmmop(&in->ops[0]) != is_xmmop(&in->ops[1])) || (is_ymmop(&in->ops[0]) != is_ymmop(&in->ops[1])))) return 0;
                return 3 + 1 + modrm_size_for_operand(&in->ops[1]);
            }
            return 0;
        }
        case MNEM_VROUNDPS:
        case MNEM_VROUNDPD:
        case MNEM_VPERMILPS:
        case MNEM_VPERMILPD: {
            if (in->op_count == 3 && is_vec_op(&in->ops[0]) && (is_vec_op(&in->ops[1]) || is_memop(&in->ops[1])) && is_imm8(&in->ops[2])) {
                if (is_vec_op(&in->ops[1]) && ((is_xmmop(&in->ops[0]) != is_xmmop(&in->ops[1])) || (is_ymmop(&in->ops[0]) != is_ymmop(&in->ops[1])))) return 0;
                return 3 + 1 + modrm_size_for_operand(&in->ops[1]) + 1; // VEX3 + opcode + modrm/sib/disp + imm8
            }
            return 0;
        }
        // AVX Conversions (2-operand) - can have different src/dst sizes
        case MNEM_VCVTPS2PD:
        case MNEM_VCVTPD2PS:
        case MNEM_VCVTPS2DQ:
        case MNEM_VCVTPD2DQ:
        case MNEM_VCVTDQ2PS:
        case MNEM_VCVTDQ2PD: {
            if (in->op_count == 2 && is_vec_op(&in->ops[0]) && (is_vec_op(&in->ops[1]) || is_memop(&in->ops[1]))) {
                // Conversions can change size, so don't check size matching
                return 3 + 1 + modrm_size_for_operand(&in->ops[1]);
            }
            return 0;
        }
        // Horizontal operations (SSE3)
        case MNEM_HADDPS:
        case MNEM_HADDPD:
        case MNEM_HSUBPS:
        case MNEM_HSUBPD: {
            if (in->op_count == 2 && is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1]))) {
                size_t prefix_len = (in->mnem == MNEM_HADDPD || in->mnem == MNEM_HSUBPD) ? 1 : 1; // 0xF2 or 0x66
                size_t rex = (operand_needs_rex(&in->ops[0]) || operand_needs_rex(&in->ops[1])) ? 1 : 0;
                return prefix_len + rex + 2 + modrm_size_for_operand(&in->ops[1]);
            }
            return 0;
        }
        // AVX Horizontal operations (3-operand)
        case MNEM_VHADDPS:
        case MNEM_VHADDPD:
        case MNEM_VHSUBPS:
        case MNEM_VHSUBPD: {
            if (in->op_count == 3 && is_vec_op(&in->ops[0]) && is_vec_op(&in->ops[1]) && (is_vec_op(&in->ops[2]) || is_memop(&in->ops[2]))) {
                if ((is_xmmop(&in->ops[0]) != is_xmmop(&in->ops[1])) || (is_ymmop(&in->ops[0]) != is_ymmop(&in->ops[1]))) return 0;
                if (is_vec_op(&in->ops[2])) {
                    if ((is_xmmop(&in->ops[0]) != is_xmmop(&in->ops[2])) || (is_ymmop(&in->ops[0]) != is_ymmop(&in->ops[2]))) return 0;
                }
                return 3 + 1 + modrm_size_for_operand(&in->ops[2]);
            }
            return 0;
        }
        // SSE4.1 blend operations (3-operand + imm8)
        case MNEM_BLENDPS:
        case MNEM_BLENDPD: {
            if (in->op_count == 3 && is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1])) && is_immop(&in->ops[2])) {
                size_t prefix_len = 1; // 0x66
                size_t rex = (operand_needs_rex(&in->ops[0]) || operand_needs_rex(&in->ops[1])) ? 1 : 0;
                return prefix_len + rex + 3 + modrm_size_for_operand(&in->ops[1]) + 1; // +1 for imm8
            }
            return 0;
        }
        // AVX blend operations (4-operand + imm8)
        case MNEM_VBLENDPS:
        case MNEM_VBLENDPD: {
            if (in->op_count == 4 && is_vec_op(&in->ops[0]) && is_vec_op(&in->ops[1]) && (is_vec_op(&in->ops[2]) || is_memop(&in->ops[2])) && is_immop(&in->ops[3])) {
                if ((is_xmmop(&in->ops[0]) != is_xmmop(&in->ops[1])) || (is_ymmop(&in->ops[0]) != is_ymmop(&in->ops[1]))) return 0;
                if (is_vec_op(&in->ops[2])) {
                    if ((is_xmmop(&in->ops[0]) != is_xmmop(&in->ops[2])) || (is_ymmop(&in->ops[0]) != is_ymmop(&in->ops[2]))) return 0;
                }
                return 3 + 1 + modrm_size_for_operand(&in->ops[2]) + 1; // +1 for imm8
            }
            return 0;
        }
        // SSE4.1 insertps (3-operand + imm8)
        case MNEM_INSERTPS: {
            if (in->op_count == 3 && is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1])) && is_immop(&in->ops[2])) {
                size_t prefix_len = 1; // 0x66
                size_t rex = (operand_needs_rex(&in->ops[0]) || operand_needs_rex(&in->ops[1])) ? 1 : 0;
                return prefix_len + rex + 3 + modrm_size_for_operand(&in->ops[1]) + 1; // +1 for imm8
            }
            return 0;
        }
        // SSE4.1 extractps (3-operand)
        case MNEM_EXTRACTPS: {
            if (in->op_count == 3 && (is_regop(&in->ops[0]) || is_memop(&in->ops[0])) && is_xmmop(&in->ops[1]) && is_immop(&in->ops[2])) {
                size_t prefix_len = 1; // 0x66
                size_t rex = (operand_needs_rex(&in->ops[0]) || operand_needs_rex(&in->ops[1])) ? 1 : 0;
                return prefix_len + rex + 3 + modrm_size_for_operand(&in->ops[0]) + 1; // +1 for imm8
            }
            return 0;
        }
        // SSE4.1 pblendw, roundss, roundsd, dpps, dppd
        case MNEM_PBLENDW:
        case MNEM_ROUNDSS:
        case MNEM_ROUNDSD:
        case MNEM_DPPS:
        case MNEM_DPPD: {
            if (in->op_count == 3 && is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1])) && is_immop(&in->ops[2])) {
                size_t prefix_len = 1; // 0x66
                size_t rex = (operand_needs_rex(&in->ops[0]) || operand_needs_rex(&in->ops[1])) ? 1 : 0;
                return prefix_len + rex + 3 + modrm_size_for_operand(&in->ops[1]) + 1; // +1 for imm8
            }
            return 0;
        }
        // FMA3 instructions (3-operand VEX)
        case MNEM_VFMADD132PS:
        case MNEM_VFMADD132PD:
        case MNEM_VFMADD213PS:
        case MNEM_VFMADD213PD:
        case MNEM_VFMADD231PS:
        case MNEM_VFMADD231PD:
        case MNEM_VFMSUB132PS:
        case MNEM_VFMSUB132PD:
        case MNEM_VFMSUB213PS:
        case MNEM_VFMSUB213PD:
        case MNEM_VFMSUB231PS:
        case MNEM_VFMSUB231PD:
        case MNEM_VFNMADD132PS:
        case MNEM_VFNMADD132PD:
        case MNEM_VFNMADD213PS:
        case MNEM_VFNMADD213PD:
        case MNEM_VFNMADD231PS:
        case MNEM_VFNMADD231PD:
        case MNEM_VFNMSUB132PS:
        case MNEM_VFNMSUB132PD:
        case MNEM_VFNMSUB213PS:
        case MNEM_VFNMSUB213PD:
        case MNEM_VFNMSUB231PS:
        case MNEM_VFNMSUB231PD: {
            if (in->op_count == 3 && is_vec_op(&in->ops[0]) && is_vec_op(&in->ops[1]) && (is_vec_op(&in->ops[2]) || is_memop(&in->ops[2]))) {
                if ((is_xmmop(&in->ops[0]) != is_xmmop(&in->ops[1])) || (is_ymmop(&in->ops[0]) != is_ymmop(&in->ops[1]))) return 0;
                if (is_vec_op(&in->ops[2])) {
                    if ((is_xmmop(&in->ops[0]) != is_xmmop(&in->ops[2])) || (is_ymmop(&in->ops[0]) != is_ymmop(&in->ops[2]))) return 0;
                }
                return 3 + 1 + modrm_size_for_operand(&in->ops[2]); // VEX + opcode + modrm
            }
            return 0;
        }
        // AVX2 vperm2i128 (4-operand + imm8)
        case MNEM_VPERM2I128: {
            if (in->op_count == 4 && is_ymmop(&in->ops[0]) && is_ymmop(&in->ops[1]) && (is_ymmop(&in->ops[2]) || is_memop(&in->ops[2])) && is_immop(&in->ops[3])) {
                return 3 + 1 + modrm_size_for_operand(&in->ops[2]) + 1; // VEX + opcode + modrm + imm8
            }
            return 0;
        }
        // AVX2 vpermd (3-operand)
        case MNEM_VPERMD: {
            if (in->op_count == 3 && is_ymmop(&in->ops[0]) && is_ymmop(&in->ops[1]) && (is_ymmop(&in->ops[2]) || is_memop(&in->ops[2]))) {
                return 3 + 1 + modrm_size_for_operand(&in->ops[2]); // VEX + opcode + modrm
            }
            return 0;
        }
        // AVX2 vpermq (3-operand + imm8)
        case MNEM_VPERMQ: {
            if (in->op_count == 3 && is_ymmop(&in->ops[0]) && (is_ymmop(&in->ops[1]) || is_memop(&in->ops[1])) && is_immop(&in->ops[2])) {
                return 3 + 1 + modrm_size_for_operand(&in->ops[1]) + 1; // VEX + opcode + modrm + imm8
            }
            return 0;
        }
        // AVX2 vgather* instructions (3-operand)
        case MNEM_VGATHERDPS:
        case MNEM_VGATHERDPD:
        case MNEM_VGATHERQPS:
        case MNEM_VGATHERQPD: {
            if (in->op_count == 3 && is_vec_op(&in->ops[0]) && is_memop(&in->ops[1]) && is_vec_op(&in->ops[2])) {
                return 3 + 1 + modrm_size_for_operand(&in->ops[1]); // VEX + opcode + modrm
            }
            return 0;
        }
        // AVX2 vpmaskmov* instructions (3-operand)
        case MNEM_VPMASKMOVD:
        case MNEM_VPMASKMOVQ: {
            if (in->op_count == 3) {
                // Two forms: load and store
                return 3 + 1 + modrm_size_for_operand(&in->ops[1]); // VEX + opcode + modrm
            }
            return 0;
        }
        // Loop instructions (always 2 bytes: opcode + rel8)
        case MNEM_LOOP:
        case MNEM_LOOPE:
        case MNEM_LOOPNE:
            if (in->op_count == 1) return 2;
            return 0;
        // Table lookup translation
        case MNEM_XLAT:
            return 1; // D7
        // String I/O
        case MNEM_INSB:
        case MNEM_INSW:
        case MNEM_INSD:
        case MNEM_OUTSB:
        case MNEM_OUTSW:
        case MNEM_OUTSD:
            return 1; // 6C/6D/6E/6F
        // Port I/O
        case MNEM_IN:
        case MNEM_OUT:
            if (in->op_count == 2) {
                // IN/OUT with immediate port uses 2 bytes (opcode + imm8)
                if (is_imm(&in->ops[1])) return 2;
                // IN/OUT with DX port uses 1 byte (opcode only)
                return 1;
            }
            return 0;
        // MOVBE - Move with byte swap
        case MNEM_MOVBE:
            if (in->op_count == 2) {
                size_t rex = (operand_needs_rex(&in->ops[0]) || operand_needs_rex(&in->ops[1])) ? 1 : 0;
                const operand *mem_op = is_memop(&in->ops[0]) ? &in->ops[0] : &in->ops[1];
                return rex + 3 + modrm_size_for_operand(mem_op); // REX? + 0F 38 F0/F1 + ModRM
            }
            return 0;
        default:
            return 0;
    }
}
#endif

static rasm_status encode_instr(const instr_stmt *in, asm_unit *unit);

static rasm_status first_pass_sizes(asm_unit *unit, FILE *log) {
    uint64_t offsets[3] = {0, 0, 0};
    for (size_t i = 0; i < unit->stmts.len; ++i) {
        statement *st = &unit->stmts.data[i];
        switch (st->kind) {
            case STMT_LABEL:
                add_symbol(unit, st->v.label.name, st->section, offsets[st->section], true, false, false);
                break;
            case STMT_INSTR: {
                // Validate register sizes for two-operand instructions (except CRC32 which allows mixed sizes)
                if (st->v.instr.op_count == 2 && st->v.instr.mnem != MNEM_CRC32) {
                    if (!validate_reg_sizes(&st->v.instr.ops[0], &st->v.instr.ops[1], log, st->v.instr.line)) {
                        return RASM_ERR_INVALID_ARGUMENT;
                    }
                }
                
                // compute exact size by encoding into a scratch buffer
                asm_unit scratch = *unit;
                scratch.text = (vec_uint8_t){0};
                scratch.text_relocs = (vec_relocation){0};
                vec_reserve_raw((void**)&scratch.text.data, &scratch.text.cap, sizeof(uint8_t), offsets[st->section]);
                scratch.text.len = offsets[st->section];
                scratch.current_section = st->section;
                size_t start_len = scratch.text.len;
                rasm_status szst = encode_instr(&st->v.instr, &scratch);
                if (szst != RASM_OK) {
                    if (log) fprintf(log, "encode error line %zu: unsupported instruction\n", st->v.instr.line);
                    free(scratch.text.data);
                    free(scratch.text_relocs.data);
                    return RASM_ERR_INVALID_ARGUMENT;
                }
                size_t sz = scratch.text.len - start_len;
                free(scratch.text.data);
                free(scratch.text_relocs.data);
                offsets[st->section] += sz;
                break;
            }
            case STMT_DATA:
                offsets[st->section] += width_bytes(st->v.data.width);
                break;
            case STMT_RESERVE:
                offsets[st->section] += st->v.res.count * width_bytes(st->v.res.width);
                break;
            case STMT_ALIGN:
                offsets[st->section] = align_up(offsets[st->section], st->v.align.align);
                break;
            case STMT_TIMES: {
                // Evaluate the times expression with current position
                const char *unresolved = NULL;
                int64_t count_val = 0;
                if (!eval_expression(st->v.times.count_expr, unit, &count_val, &unresolved)) {
                    if (log) {
                        fprintf(log, "error line %zu: cannot evaluate times count expression", st->v.times.line);
                        if (unresolved) fprintf(log, " (unresolved symbol: %s)", unresolved);
                        fprintf(log, "\n");
                    }
                    return RASM_ERR_INVALID_ARGUMENT;
                }
                if (count_val <= 0) {
                    if (log) fprintf(log, "error line %zu: times count must be positive (got %lld)\n", st->v.times.line, (long long)count_val);
                    return RASM_ERR_INVALID_ARGUMENT;
                }
                
                if (st->v.times.kind == TIMES_DATA) {
                    offsets[st->section] += (size_t)count_val * width_bytes(st->v.times.u.data.width);
                } else { // TIMES_INSTR
                    // Encode the instruction once to get its size
                    asm_unit scratch = *unit;
                    scratch.text = (vec_uint8_t){0};
                    scratch.text_relocs = (vec_relocation){0};
                    vec_reserve_raw((void**)&scratch.text.data, &scratch.text.cap, sizeof(uint8_t), offsets[st->section]);
                    scratch.text.len = offsets[st->section];
                    scratch.current_section = st->section;
                    size_t start_len = scratch.text.len;
                    rasm_status szst = encode_instr(&st->v.times.u.instr, &scratch);
                    if (szst != RASM_OK) {
                        if (log) fprintf(log, "encode error line %zu: unsupported instruction\n", st->v.times.line);
                        free(scratch.text.data);
                        free(scratch.text_relocs.data);
                        return RASM_ERR_INVALID_ARGUMENT;
                    }
                    size_t instr_sz = scratch.text.len - start_len;
                    free(scratch.text.data);
                    free(scratch.text_relocs.data);
                    offsets[st->section] += (size_t)count_val * instr_sz;
                }
                break;
            }
        }
    }
    unit->bss_size = offsets[SEC_BSS];
    unit->text.len = 0;
    unit->data.len = 0;
    vec_reserve_raw((void**)&unit->text.data, &unit->text.cap, sizeof(uint8_t), offsets[SEC_TEXT]);
    vec_reserve_raw((void**)&unit->data.data, &unit->data.cap, sizeof(uint8_t), offsets[SEC_DATA]);
    return RASM_OK;
}

static void emit_u8(VEC(uint8_t) *buf, uint8_t v) {
    VEC_PUSH(*buf, v);
}

static void emit_u16(VEC(uint8_t) *buf, uint16_t v) {
    emit_u8(buf, (uint8_t)(v & 0xFF));
    emit_u8(buf, (uint8_t)((v >> 8) & 0xFF));
}

static void emit_u32(VEC(uint8_t) *buf, uint32_t v) {
    emit_u8(buf, (uint8_t)(v & 0xFF));
    emit_u8(buf, (uint8_t)((v >> 8) & 0xFF));
    emit_u8(buf, (uint8_t)((v >> 16) & 0xFF));
    emit_u8(buf, (uint8_t)((v >> 24) & 0xFF));
}

static void emit_u64(VEC(uint8_t) *buf, uint64_t v) {
    emit_u32(buf, (uint32_t)(v & 0xFFFFFFFFu));
    emit_u32(buf, (uint32_t)((v >> 32) & 0xFFFFFFFFu));
}

static bool is_gpr64(reg_kind r) { return r >= REG_RAX && r <= REG_R15; }
static bool is_gpr32(reg_kind r) { return r >= REG_EAX && r <= REG_R15D; }
static bool is_gpr16(reg_kind r) { return r >= REG_AX && r <= REG_R15W; }
static bool is_gpr8(reg_kind r) { return r >= REG_AL && r <= REG_R15B; }
static bool is_gpr8_high(reg_kind r) { return r >= REG_AH && r <= REG_BH; }
static bool is_gpr(reg_kind r) { return is_gpr64(r) || is_gpr32(r) || is_gpr16(r) || is_gpr8(r) || is_gpr8_high(r); }
static bool is_xmm(reg_kind r) { return r >= REG_XMM0 && r <= REG_XMM31; }
static bool is_ymm(reg_kind r) { return r >= REG_YMM0 && r <= REG_YMM31; }
static bool is_zmm(reg_kind r) { return r >= REG_ZMM0 && r <= REG_ZMM31; }
static bool is_opmask(reg_kind r) { return r >= REG_K0 && r <= REG_K7; }
static bool is_segreg(reg_kind r) { return r >= REG_ES && r <= REG_GS; }
static bool is_creg(reg_kind r) { return r >= REG_CR0 && r <= REG_CR8; }
static bool is_dreg(reg_kind r) { return r >= REG_DR0 && r <= REG_DR7; }
static bool is_st(reg_kind r) { return r >= REG_ST0 && r <= REG_ST7; }
static bool is_mmx(reg_kind r) { return r >= REG_MM0 && r <= REG_MM7; }

static uint8_t reg_code(reg_kind r) {
    if (is_gpr64(r)) return (uint8_t)r;
    if (is_gpr32(r)) return (uint8_t)(r - REG_EAX);
    if (is_gpr16(r)) return (uint8_t)(r - REG_AX);
    if (is_gpr8(r)) return (uint8_t)(r - REG_AL);
    if (is_gpr8_high(r)) return (uint8_t)(4 + (r - REG_AH)); // ah->4, ch->5, dh->6, bh->7
    if (is_xmm(r)) return (uint8_t)(r - REG_XMM0);
    if (is_ymm(r)) return (uint8_t)(r - REG_YMM0);
    if (is_zmm(r)) return (uint8_t)(r - REG_ZMM0);
    if (is_opmask(r)) return (uint8_t)(r - REG_K0);
    if (is_segreg(r)) return (uint8_t)(r - REG_ES); // ES=0, CS=1, SS=2, DS=3, FS=4, GS=5
    if (is_creg(r)) return (r == REG_CR8) ? 8 : (uint8_t)(r - REG_CR0); // CR0-4, CR8
    if (is_dreg(r)) return (uint8_t)(r - REG_DR0); // DR0-7
    if (is_st(r)) return (uint8_t)(r - REG_ST0); // ST0-7
    if (is_mmx(r)) return (uint8_t)(r - REG_MM0); // MM0-7
    return 0;
}

static uint8_t gpr_low3(reg_kind r) { return reg_code(r) & 7; }
static bool gpr_is_high(reg_kind r) { 
    if (is_gpr8_high(r)) return false; // ah/ch/dh/bh don't use REX
    return is_gpr(r) && reg_code(r) >= 8; 
}
static bool vec_is_high(reg_kind r) { return (is_xmm(r) || is_ymm(r)) && reg_code(r) >= 8; }

// Check if register is valid for target architecture
static bool reg_valid_for_arch(reg_kind r, target_arch arch) {
    uint8_t code = reg_code(r);
    
    // r8-r15 and their variants only exist in 64-bit mode
    if (code >= 8 && arch != ARCH_X86_64) {
        return false;
    }
    
    // 64-bit registers only valid in 64-bit mode
    if (is_gpr64(r) && arch != ARCH_X86_64) {
        return false;
    }
    
    // spl, bpl, sil, dil require 64-bit mode (REX prefix)
    if ((r == REG_SPL || r == REG_BPL || r == REG_SIL || r == REG_DIL) && arch != ARCH_X86_64) {
        return false;
    }
    
    return true;
}

static void emit_rex(VEC(uint8_t) *buf, bool w, bool r, bool x, bool b, target_arch arch) {
    // REX prefix only exists in 64-bit mode
    if (arch != ARCH_X86_64) return;
    
    uint8_t rex = 0x40;
    if (w) rex |= 0x08;
    if (r) rex |= 0x04;
    if (x) rex |= 0x02;
    if (b) rex |= 0x01;
    emit_u8(buf, rex);
}

#if 0
// Unused helper - may be useful for future features
static bool mem_needs_rex(const mem_ref *m) {
    if (m->base != REG_INVALID && gpr_is_high(m->base)) return true;
    if (m->index != REG_INVALID && gpr_is_high(m->index)) return true;
    return false;
}
#endif

// Check if a memory operand uses 16-bit addressing registers
static void emit_segment_override(vec_uint8_t *code, reg_kind seg) {
    if (seg == REG_INVALID) return;
    switch (seg) {
        case REG_ES: emit_u8(code, 0x26); break;
        case REG_CS: emit_u8(code, 0x2E); break;
        case REG_SS: emit_u8(code, 0x36); break;
        case REG_DS: emit_u8(code, 0x3E); break;
        case REG_FS: emit_u8(code, 0x64); break;
        case REG_GS: emit_u8(code, 0x65); break;
        default: break;
    }
}

static bool is_16bit_address(const mem_ref *m) {
    // 16-bit addressing uses BX, BP, SI, DI as base/index
    if (m->base != REG_INVALID) {
        if (m->base == REG_BX || m->base == REG_BP || m->base == REG_SI || m->base == REG_DI) {
            return true;
        }
    }
    if (m->index != REG_INVALID) {
        if (m->index == REG_BX || m->index == REG_BP || m->index == REG_SI || m->index == REG_DI) {
            return true;
        }
    }
    // If no base/index, it's a direct address (compatible with 16-bit)
    if (m->base == REG_INVALID && m->index == REG_INVALID) {
        return true;
    }
    return false;
}

// Encode ModR/M for 16-bit addressing mode (no SIB byte)
// 16-bit addressing combinations:
// [BX+SI]=000, [BX+DI]=001, [BP+SI]=010, [BP+DI]=011
// [SI]=100, [DI]=101, [BP]=110 (with disp), [BX]=111
// [disp16] = mod=00, r/m=110
static rasm_status emit_op_modrm_16bit(const uint8_t *prefixes, size_t prefix_len, const uint8_t *opcodes, size_t opcode_len, const operand *rmop, uint8_t reg_field, asm_unit *unit, reloc_kind reloc_for_sym) {
    if (rmop->kind != OP_MEM) return RASM_ERR_INVALID_ARGUMENT;
    
    const mem_ref *m = &rmop->v.mem;
    
    // Emit segment override prefix first if present
    emit_segment_override(&unit->text, m->seg_override);
    reg_kind base = m->base;
    reg_kind index = m->index;
    int64_t disp = m->disp;
    
    uint8_t mod_bits = 0;
    uint8_t rm_bits = 0;
    bool need_disp = false;
    size_t disp_size = 0;
    
    // Direct address [disp16] - no base or index
    if (base == REG_INVALID && index == REG_INVALID) {
        mod_bits = 0x00;
        rm_bits = 0x06;
        need_disp = true;
        disp_size = 2;
    }
    // [BX+SI] = 000
    else if (base == REG_BX && index == REG_SI) {
        rm_bits = 0x00;
    }
    // [BX+DI] = 001
    else if (base == REG_BX && index == REG_DI) {
        rm_bits = 0x01;
    }
    // [BP+SI] = 010
    else if (base == REG_BP && index == REG_SI) {
        rm_bits = 0x02;
    }
    // [BP+DI] = 011
    else if (base == REG_BP && index == REG_DI) {
        rm_bits = 0x03;
    }
    // [SI] = 100
    else if (base == REG_SI && index == REG_INVALID) {
        rm_bits = 0x04;
    }
    // [DI] = 101
    else if (base == REG_DI && index == REG_INVALID) {
        rm_bits = 0x05;
    }
    // [BP] = 110 (always needs displacement)
    else if (base == REG_BP && index == REG_INVALID) {
        rm_bits = 0x06;
        if (disp == 0) {
            // BP requires at least disp8
            need_disp = true;
            disp_size = 1;
            mod_bits = 0x40;
        }
    }
    // [BX] = 111
    else if (base == REG_BX && index == REG_INVALID) {
        rm_bits = 0x07;
    }
    else {
        // Invalid 16-bit addressing combination
        return RASM_ERR_INVALID_ARGUMENT;
    }
    
    // Determine displacement size if not already set
    if (!need_disp && disp != 0) {
        if (disp >= -128 && disp <= 127) {
            mod_bits = 0x40; // disp8
            disp_size = 1;
            need_disp = true;
        } else {
            mod_bits = 0x80; // disp16
            disp_size = 2;
            need_disp = true;
        }
    }
    
    // For symbolic references, always use disp16
    if (m->sym != NULL) {
        mod_bits = 0x80;
        disp_size = 2;
        need_disp = true;
    }
    
    // Emit prefixes and opcode
    for (size_t i = 0; i < prefix_len; ++i) emit_u8(&unit->text, prefixes[i]);
    for (size_t i = 0; i < opcode_len; ++i) emit_u8(&unit->text, opcodes[i]);
    
    // Emit ModR/M byte
    uint8_t modrm = mod_bits | ((reg_field & 0x07) << 3) | rm_bits;
    emit_u8(&unit->text, modrm);
    
    // Emit displacement
    if (need_disp) {
        if (m->sym != NULL) {
            // Add relocation for symbol
            relocation r;
            r.offset = unit->text.len;
            r.kind = reloc_for_sym;
            r.symbol = str_dup(m->sym);
            r.addend = disp;
            VEC_PUSH(unit->text_relocs, r);
            emit_u16(&unit->text, 0); // Placeholder
        } else {
            if (disp_size == 1) {
                emit_u8(&unit->text, (uint8_t)disp);
            } else {
                emit_u16(&unit->text, (uint16_t)disp);
            }
        }
    }
    
    return RASM_OK;
}

static rasm_status emit_op_modrm_legacy(const uint8_t *prefixes, size_t prefix_len, const uint8_t *opcodes, size_t opcode_len, const operand *rmop, uint8_t reg_field, bool rex_w, asm_unit *unit, reloc_kind reloc_for_sym) {
    if (rmop->kind != OP_MEM && rmop->kind != OP_REG) return RASM_ERR_INVALID_ARGUMENT;
    
    // Check if this is 16-bit addressing mode (uses BX/BP/SI/DI)
    if (unit->arch == ARCH_X86_16 && rmop->kind == OP_MEM && is_16bit_address(&rmop->v.mem)) {
        // Use native 16-bit addressing (no address-size prefix)
        return emit_op_modrm_16bit(prefixes, prefix_len, opcodes, opcode_len, rmop, reg_field, unit, reloc_for_sym);
    }
    
    // In 16-bit mode with 32-bit registers, need address-size prefix for 32-bit addressing
    // In 32-bit mode, we use default 32-bit addressing
    // In 64-bit mode, we use default 64-bit addressing (or REX prefix handles it)
    bool need_addr_prefix = false;
    if (unit->arch == ARCH_X86_16 && rmop->kind == OP_MEM && !is_16bit_address(&rmop->v.mem)) {
        // 16-bit mode using 32-bit registers needs 0x67 prefix
        need_addr_prefix = true;
    }
    
    // Emit segment override prefix first if present (before REX and other prefixes)
    if (rmop->kind == OP_MEM) {
        emit_segment_override(&unit->text, rmop->v.mem.seg_override);
    }
    
    bool rex_r = (reg_field & 0x08) != 0;
    uint8_t reg_bits = reg_field & 0x07;

    uint8_t rm_bits = 0;
    uint8_t sib = 0;
    uint8_t mod_bits = 0;
    bool use_sib = false;
    bool rex_b = false;
    bool rex_x = false;
    bool need_disp32 = false;
    reg_kind mem_base = REG_INVALID;

    if (rmop->kind == OP_REG) {
        reg_kind r = rmop->v.reg;
        uint8_t code = reg_code(r);
        rex_b = vec_is_high(r) || gpr_is_high(r);
        mod_bits = 0xC0;
        rm_bits = code & 0x07;
    } else {
        const mem_ref *m = &rmop->v.mem;
        reg_kind base = m->base;
        mem_base = base;
        reg_kind index = m->index;
        uint8_t scale = m->scale ? m->scale : 1;
        if (base == REG_INVALID && index != REG_INVALID) base = REG_RBP; // force disp32 with SIB
        if (base == REG_RSP || base == REG_R12 || index != REG_INVALID || base == REG_INVALID) use_sib = true;

        need_disp32 = m->rip_relative || m->sym != NULL || base == REG_RBP || base == REG_R13 || base == REG_INVALID || m->disp < -128 || m->disp > 127;
        if (base == REG_INVALID && !m->rip_relative) {
            // absolute disp32 address with no base/index
            use_sib = true;
            mod_bits = 0x00;
            need_disp32 = true;
        } else if (!need_disp32 && !use_sib && base != REG_RIP) {
            mod_bits = 0x00;
        } else if (!m->rip_relative && m->sym == NULL && m->disp >= -128 && m->disp <= 127 && base != REG_RIP) {
            mod_bits = 0x40; // disp8
            need_disp32 = false;
        } else {
            mod_bits = 0x80; // disp32
            need_disp32 = true;
        }

        if (m->rip_relative || base == REG_RIP) {
            use_sib = false;
            rm_bits = 0x05;
            rex_b = false;
            mod_bits = 0x00;
            need_disp32 = true;
        } else if (use_sib) {
            rm_bits = 0x04;
            uint8_t sib_base = 0;
            if (base == REG_INVALID) {
                sib_base = 0x05;
                need_disp32 = true;
            } else {
                sib_base = gpr_low3(base);
                rex_b = gpr_is_high(base);
            }
            uint8_t sib_index = 0x04; // none
            if (index != REG_INVALID) {
                sib_index = gpr_low3(index);
                rex_x = gpr_is_high(index);
            }
            uint8_t sib_scale = 0;
            switch (scale) {
                case 1: sib_scale = 0; break;
                case 2: sib_scale = 1; break;
                case 4: sib_scale = 2; break;
                case 8: sib_scale = 3; break;
                default: return RASM_ERR_INVALID_ARGUMENT;
            }
            sib = (sib_scale << 6) | (sib_index << 3) | sib_base;
        } else {
            rm_bits = gpr_low3(base);
            rex_b = gpr_is_high(base);
            if (base == REG_RBP || base == REG_R13) {
                mod_bits = 0x40; // disp8=0
                need_disp32 = false;
            }
        }
    }

    bool need_rex = rex_w || rex_r || rex_x || rex_b;
    if (need_addr_prefix) emit_u8(&unit->text, 0x67); // Address-size override
    for (size_t i = 0; i < prefix_len; ++i) emit_u8(&unit->text, prefixes[i]);
    if (need_rex) emit_rex(&unit->text, rex_w, rex_r, rex_x, rex_b, unit->arch);
    for (size_t i = 0; i < opcode_len; ++i) emit_u8(&unit->text, opcodes[i]);
    emit_u8(&unit->text, mod_bits | (reg_bits << 3) | rm_bits);
    if (use_sib) emit_u8(&unit->text, sib);

    if (rmop->kind == OP_MEM) {
        const mem_ref *m = &rmop->v.mem;
        uint64_t disp_off = unit->text.len;
        if (mod_bits == 0x40) {
            emit_u8(&unit->text, (uint8_t)m->disp);
        } else if (need_disp32 || mod_bits == 0x80 || m->rip_relative || m->sym != NULL) {
            emit_u32(&unit->text, 0);
            if (m->sym != NULL) {
                reloc_kind kind = reloc_for_sym;
                int64_t addend = m->disp;
                if (m->rip_relative || mem_base == REG_RIP) {
                    kind = RELOC_PC32;
                    addend = m->disp - 4;
                } else if (kind == RELOC_NONE || kind == RELOC_PC32) {
                    kind = RELOC_ABS32;
                }
                relocation r = { .kind = kind, .symbol = m->sym, .offset = disp_off, .addend = addend };
                VEC_PUSH(unit->text_relocs, r);
            } else {
                uint8_t *p = &unit->text.data[unit->text.len - 4];
                int32_t d = (int32_t)m->disp;
                p[0] = (uint8_t)(d & 0xFF);
                p[1] = (uint8_t)((d >> 8) & 0xFF);
                p[2] = (uint8_t)((d >> 16) & 0xFF);
                p[3] = (uint8_t)((d >> 24) & 0xFF);
            }
        }
    }
    return RASM_OK;
}

static rasm_status emit_vex_modrm(const uint8_t *opcodes, size_t opcode_len, const operand *rmop, uint8_t reg_field, reg_kind vvvv_reg, bool vex_w, bool vex_l, uint8_t vex_pp, uint8_t vex_mmmmm, asm_unit *unit, reloc_kind reloc_for_sym) {
    if (rmop->kind != OP_MEM && rmop->kind != OP_REG) return RASM_ERR_INVALID_ARGUMENT;
    bool rex_r = reg_field >= 8;
    uint8_t reg_bits = reg_field & 0x07;

    uint8_t rm_bits = 0;
    uint8_t sib = 0;
    uint8_t mod_bits = 0;
    bool use_sib = false;
    bool rex_b = false;
    bool rex_x = false;
    bool need_disp32 = false;
    reg_kind mem_base = REG_INVALID;

    if (rmop->kind == OP_REG) {
        reg_kind r = rmop->v.reg;
        uint8_t code = reg_code(r);
        rex_b = vec_is_high(r) || gpr_is_high(r);
        mod_bits = 0xC0;
        rm_bits = code & 0x07;
    } else {
        const mem_ref *m = &rmop->v.mem;
        reg_kind base = m->base;
        mem_base = base;
        reg_kind index = m->index;
        uint8_t scale = m->scale ? m->scale : 1;
        if (base == REG_INVALID && index != REG_INVALID) base = REG_RBP;
        if (base == REG_RSP || base == REG_R12 || index != REG_INVALID || base == REG_INVALID) use_sib = true;

        need_disp32 = m->rip_relative || m->sym != NULL || base == REG_RBP || base == REG_R13 || base == REG_INVALID || m->disp < -128 || m->disp > 127;
        if (base == REG_INVALID && !m->rip_relative) {
            use_sib = true;
            mod_bits = 0x00;
            need_disp32 = true;
        } else if (!need_disp32 && !use_sib && base != REG_RIP) {
            mod_bits = 0x00;
        } else if (!m->rip_relative && m->sym == NULL && m->disp >= -128 && m->disp <= 127 && base != REG_RIP) {
            mod_bits = 0x40;
            need_disp32 = false;
        } else {
            mod_bits = 0x80;
            need_disp32 = true;
        }

        if (m->rip_relative || base == REG_RIP) {
            use_sib = false;
            rm_bits = 0x05;
            rex_b = false;
            mod_bits = 0x00;
            need_disp32 = true;
        } else if (use_sib) {
            rm_bits = 0x04;
            uint8_t sib_base = 0;
            if (base == REG_INVALID) {
                sib_base = 0x05;
                need_disp32 = true;
            } else {
                sib_base = gpr_low3(base);
                rex_b = gpr_is_high(base);
            }
            uint8_t sib_index = 0x04;
            if (index != REG_INVALID) {
                sib_index = gpr_low3(index);
                rex_x = gpr_is_high(index);
            }
            uint8_t sib_scale = 0;
            switch (scale) {
                case 1: sib_scale = 0; break;
                case 2: sib_scale = 1; break;
                case 4: sib_scale = 2; break;
                case 8: sib_scale = 3; break;
                default: return RASM_ERR_INVALID_ARGUMENT;
            }
            sib = (sib_scale << 6) | (sib_index << 3) | sib_base;
        } else {
            rm_bits = gpr_low3(base);
            rex_b = gpr_is_high(base);
            if (base == REG_RBP || base == REG_R13) {
                mod_bits = 0x40;
                need_disp32 = false;
            }
        }
    }

    uint8_t vvvv_code = 0x00; // default 0 for instructions that ignore vvvv
    if (is_gpr(vvvv_reg) || is_xmm(vvvv_reg) || is_ymm(vvvv_reg)) vvvv_code = reg_code(vvvv_reg) & 0x0F;

    emit_u8(&unit->text, 0xC4);
    uint8_t b2 = ((rex_r ? 0 : 1) << 7) | ((rex_x ? 0 : 1) << 6) | ((rex_b ? 0 : 1) << 5) | (vex_mmmmm & 0x1F);
    emit_u8(&unit->text, b2);
    uint8_t b3 = (vex_w ? 0x80 : 0) | ((uint8_t)(~vvvv_code & 0x0F) << 3) | (vex_l ? 0x04 : 0) | (vex_pp & 0x03);
    emit_u8(&unit->text, b3);
    for (size_t i = 0; i < opcode_len; ++i) emit_u8(&unit->text, opcodes[i]);
    emit_u8(&unit->text, mod_bits | (reg_bits << 3) | rm_bits);
    if (use_sib) emit_u8(&unit->text, sib);

    if (rmop->kind == OP_MEM) {
        const mem_ref *m = &rmop->v.mem;
        uint64_t disp_off = unit->text.len;
        if (mod_bits == 0x40) {
            emit_u8(&unit->text, (uint8_t)m->disp);
        } else if (need_disp32 || mod_bits == 0x80 || m->rip_relative || m->sym != NULL) {
            emit_u32(&unit->text, 0);
            if (m->sym != NULL) {
                reloc_kind kind = reloc_for_sym;
                int64_t addend = m->disp;
                if (m->rip_relative || mem_base == REG_RIP) {
                    kind = RELOC_PC32;
                    addend = m->disp - 4;
                } else if (kind == RELOC_NONE || kind == RELOC_PC32) {
                    kind = RELOC_ABS32;
                }
                relocation r = { .kind = kind, .symbol = m->sym, .offset = disp_off, .addend = addend };
                VEC_PUSH(unit->text_relocs, r);
            } else {
                uint8_t *p = &unit->text.data[unit->text.len - 4];
                int32_t d = (int32_t)m->disp;
                p[0] = (uint8_t)(d & 0xFF);
                p[1] = (uint8_t)((d >> 8) & 0xFF);
                p[2] = (uint8_t)((d >> 16) & 0xFF);
                p[3] = (uint8_t)((d >> 24) & 0xFF);
            }
        }
    }
    return RASM_OK;
}

// Helper to get immediate value from operand (handles expressions)
static bool get_operand_imm(const operand *op, const asm_unit *unit, int64_t *result) {
    if (op->kind == OP_IMM) {
        *result = (int64_t)op->v.imm;
        return true;
    }
    if (op->kind == OP_EXPR) {
        const char *unresolved = NULL;
        return eval_expression(op->v.expr, unit, result, &unresolved);
    }
    if (op->kind == OP_SYMBOL) {
        // Try to resolve symbol - especially important for absolute symbols (like struct fields)
        const symbol *sym = find_symbol(unit, op->v.sym);
        if (sym && sym->is_defined) {
            // For absolute symbols (like struct field offsets), use the value directly
            if (sym->section == SEC_ABS) {
                *result = (int64_t)sym->value;
                return true;
            }
            // For section-relative symbols, we can't resolve to an immediate
            // (would need a relocation)
            return false;
        }
        return false;
    }
    return false;
}

// EVEX encoding helper for AVX-512 instructions
// EVEX prefix format: [62h] [P0] [P1] [P2]
// P0: R'RXB'mmm - Register extensions + opcode map
// P1: Wvvvv1pp - Operand size + vvvv register + mandatory prefix
// P2: zL'Lbv'aaa - Zeroing + vector length + broadcast + mask register
static rasm_status emit_evex_modrm(const uint8_t *opcodes, size_t opcode_len, const operand *rmop, uint8_t reg_field, reg_kind vvvv_reg, reg_kind mask_reg, bool evex_w, uint8_t evex_ll, uint8_t evex_pp, uint8_t evex_mmmmm, bool evex_z, bool evex_b, asm_unit *unit, reloc_kind reloc_for_sym) {
    if (rmop->kind != OP_MEM && rmop->kind != OP_REG) return RASM_ERR_INVALID_ARGUMENT;
    
    // Compute register extensions
    bool rex_r_prime = reg_field >= 16;  // R' bit for registers 16-31
    bool rex_r = (reg_field & 0x08) != 0;  // R bit for registers 8-15
    uint8_t reg_bits = reg_field & 0x07;
    
    uint8_t rm_bits = 0;
    uint8_t sib = 0;
    uint8_t mod_bits = 0;
    bool use_sib = false;
    bool rex_b = false;
    bool rex_b_prime = false;
    bool rex_x = false;
    bool need_disp32 = false;
    reg_kind mem_base = REG_INVALID;
    
    if (rmop->kind == OP_REG) {
        reg_kind r = rmop->v.reg;
        uint8_t code = reg_code(r);
        rex_b_prime = code >= 16;
        rex_b = (code & 0x08) != 0;
        mod_bits = 0xC0;
        rm_bits = code & 0x07;
    } else {
        const mem_ref *m = &rmop->v.mem;
        reg_kind base = m->base;
        mem_base = base;
        reg_kind index = m->index;
        uint8_t scale = m->scale ? m->scale : 1;
        if (base == REG_INVALID && index != REG_INVALID) base = REG_RBP;
        if (base == REG_RSP || base == REG_R12 || index != REG_INVALID || base == REG_INVALID) use_sib = true;
        
        need_disp32 = m->rip_relative || m->sym != NULL || base == REG_RBP || base == REG_R13 || base == REG_INVALID || m->disp < -128 || m->disp > 127;
        if (base == REG_INVALID && !m->rip_relative) {
            use_sib = true;
            mod_bits = 0x00;
            need_disp32 = true;
        } else if (!need_disp32 && !use_sib && base != REG_RIP) {
            mod_bits = 0x00;
        } else if (!m->rip_relative && m->sym == NULL && m->disp >= -128 && m->disp <= 127 && base != REG_RIP) {
            mod_bits = 0x40;
            need_disp32 = false;
        } else {
            mod_bits = 0x80;
            need_disp32 = true;
        }
        
        if (m->rip_relative || base == REG_RIP) {
            use_sib = false;
            rm_bits = 0x05;
            rex_b = false;
            rex_b_prime = false;
            mod_bits = 0x00;
            need_disp32 = true;
        } else if (use_sib) {
            rm_bits = 0x04;
            uint8_t sib_base = 0;
            if (base == REG_INVALID) {
                sib_base = 0x05;
                need_disp32 = true;
            } else {
                uint8_t base_code = reg_code(base);
                sib_base = base_code & 0x07;
                rex_b_prime = base_code >= 16;
                rex_b = (base_code & 0x08) != 0;
            }
            uint8_t sib_index = 0x04;
            if (index != REG_INVALID) {
                uint8_t idx_code = reg_code(index);
                sib_index = idx_code & 0x07;
                rex_x = (idx_code & 0x08) != 0;
            }
            uint8_t sib_scale = 0;
            switch (scale) {
                case 1: sib_scale = 0; break;
                case 2: sib_scale = 1; break;
                case 4: sib_scale = 2; break;
                case 8: sib_scale = 3; break;
                default: return RASM_ERR_INVALID_ARGUMENT;
            }
            sib = (sib_scale << 6) | (sib_index << 3) | sib_base;
        } else {
            uint8_t base_code = reg_code(base);
            rm_bits = base_code & 0x07;
            rex_b_prime = base_code >= 16;
            rex_b = (base_code & 0x08) != 0;
            if (base == REG_RBP || base == REG_R13) {
                mod_bits = 0x40;
                need_disp32 = false;
            }
        }
    }
    
    // Compute vvvv field (inverted)
    uint8_t vvvv_code = 0x00;
    bool rex_v_prime = false;
    if (is_gpr(vvvv_reg) || is_xmm(vvvv_reg) || is_ymm(vvvv_reg) || is_zmm(vvvv_reg)) {
        uint8_t v_code = reg_code(vvvv_reg);
        rex_v_prime = v_code >= 16;
        vvvv_code = v_code & 0x0F;
    }
    
    // Compute mask register field (aaa)
    uint8_t aaa = 0;
    if (is_opmask(mask_reg)) {
        aaa = reg_code(mask_reg) & 0x07;
    }
    
    // Emit EVEX prefix: 62h [P0] [P1] [P2]
    emit_u8(&unit->text, 0x62);
    
    // P0: R'RXB'mmm
    // Note: rex_b is computed but not used in EVEX encoding (only rex_b_prime is used)
    (void)rex_b;
    uint8_t p0 = ((rex_r_prime ? 0 : 1) << 7) | ((rex_r ? 0 : 1) << 6) | ((rex_x ? 0 : 1) << 5) | ((rex_b_prime ? 0 : 1) << 4) | (evex_mmmmm & 0x0F);
    emit_u8(&unit->text, p0);
    
    // P1: Wvvvv1pp
    uint8_t p1 = (evex_w ? 0x80 : 0) | ((uint8_t)(~vvvv_code & 0x0F) << 3) | 0x04 | (evex_pp & 0x03);
    emit_u8(&unit->text, p1);
    
    // P2: zL'Lbv'aaa
    uint8_t p2 = (evex_z ? 0x80 : 0) | ((evex_ll & 0x03) << 5) | (evex_b ? 0x10 : 0) | ((rex_v_prime ? 0 : 1) << 3) | (aaa & 0x07);
    emit_u8(&unit->text, p2);
    
    // Emit opcode bytes
    for (size_t i = 0; i < opcode_len; ++i) emit_u8(&unit->text, opcodes[i]);
    
    // Emit ModR/M byte
    emit_u8(&unit->text, mod_bits | (reg_bits << 3) | rm_bits);
    
    // Emit SIB byte if needed
    if (use_sib) emit_u8(&unit->text, sib);
    
    // Emit displacement if needed
    if (rmop->kind == OP_MEM) {
        const mem_ref *m = &rmop->v.mem;
        uint64_t disp_off = unit->text.len;
        if (mod_bits == 0x40) {
            emit_u8(&unit->text, (uint8_t)m->disp);
        } else if (need_disp32 || mod_bits == 0x80 || m->rip_relative || m->sym != NULL) {
            emit_u32(&unit->text, 0);
            if (m->sym != NULL) {
                reloc_kind kind = reloc_for_sym;
                int64_t addend = m->disp;
                if (m->rip_relative || mem_base == REG_RIP) {
                    kind = RELOC_PC32;
                    addend = m->disp - 4;
                } else if (kind == RELOC_NONE || kind == RELOC_PC32) {
                    kind = RELOC_ABS32;
                }
                relocation r = { .kind = kind, .symbol = m->sym, .offset = disp_off, .addend = addend };
                VEC_PUSH(unit->text_relocs, r);
            } else {
                uint8_t *p = &unit->text.data[unit->text.len - 4];
                int32_t d = (int32_t)m->disp;
                p[0] = (uint8_t)(d & 0xFF);
                p[1] = (uint8_t)((d >> 8) & 0xFF);
                p[2] = (uint8_t)((d >> 16) & 0xFF);
                p[3] = (uint8_t)((d >> 24) & 0xFF);
            }
        }
    }
    return RASM_OK;
}

#if 0
// Helper to check if operand is an immediate (or evaluable expression)
static bool is_imm_or_expr(const operand *op) {
    return op->kind == OP_IMM || op->kind == OP_EXPR;
}
#endif

static rasm_status encode_instr(const instr_stmt *in, asm_unit *unit) {
    // Emit instruction prefix if present
    if (in->prefix != PREFIX_NONE) {
        emit_u8(&unit->text, (uint8_t)in->prefix);
    }
    
    // Validate all operand registers for target architecture
    for (size_t i = 0; i < in->op_count; ++i) {
        if (in->ops[i].kind == OP_REG) {
            if (!reg_valid_for_arch(in->ops[i].v.reg, unit->arch)) {
                return RASM_ERR_INVALID_ARGUMENT;
            }
        } else if (in->ops[i].kind == OP_MEM) {
            const mem_ref *m = &in->ops[i].v.mem;
            if (m->base != REG_INVALID && !reg_valid_for_arch(m->base, unit->arch)) {
                return RASM_ERR_INVALID_ARGUMENT;
            }
            if (m->index != REG_INVALID && !reg_valid_for_arch(m->index, unit->arch)) {
                return RASM_ERR_INVALID_ARGUMENT;
            }
        }
    }
    
    switch (in->mnem) {
        case MNEM_MOV: {
            // MOV reg, imm variants
            if (in->op_count == 2 && is_reg64(&in->ops[0]) && is_imm(&in->ops[1])) {
                reg_kind dst = in->ops[0].v.reg;
                bool rex_b = gpr_is_high(dst);
                emit_rex(&unit->text, true, false, false, rex_b, unit->arch);
                emit_u8(&unit->text, (uint8_t)(0xB8 + gpr_low3(dst)));
                
                int64_t val;
                if (get_operand_imm(&in->ops[1], unit, &val)) {
                    // Resolved to immediate value (including absolute symbols)
                    emit_u64(&unit->text, (uint64_t)val);
                } else {
                    // Unresolved symbol or section-relative symbol - needs relocation
                    emit_u64(&unit->text, 0);
                    if (in->ops[1].kind == OP_SYMBOL) {
                        relocation r = { .kind = RELOC_ABS64, .symbol = in->ops[1].v.sym, .offset = unit->text.len - 8, .addend = 0 };
                        VEC_PUSH(unit->text_relocs, r);
                    } else {
                        // Expression with unresolved symbols
                        return RASM_ERR_INVALID_ARGUMENT;
                    }
                }
                return RASM_OK;
            }
            if (in->op_count == 2 && is_reg32(&in->ops[0]) && is_imm(&in->ops[1])) {
                // In 16-bit mode, 32-bit operands need operand-size prefix
                if (unit->arch == ARCH_X86_16) emit_u8(&unit->text, 0x66);
                
                reg_kind dst = in->ops[0].v.reg;
                bool rex_b = gpr_is_high(dst);
                if (rex_b) emit_rex(&unit->text, false, false, false, true, unit->arch);
                emit_u8(&unit->text, (uint8_t)(0xB8 + gpr_low3(dst)));
                int64_t val;
                if (get_operand_imm(&in->ops[1], unit, &val)) {
                    emit_u32(&unit->text, (uint32_t)val);
                } else {
                    // Unresolved symbol - emit placeholder and add relocation
                    emit_u32(&unit->text, 0);
                    if (in->ops[1].kind == OP_SYMBOL) {
                        relocation r = { .kind = RELOC_ABS32, .symbol = in->ops[1].v.sym, .offset = unit->text.len - 4, .addend = 0 };
                        VEC_PUSH(unit->text_relocs, r);
                    } else {
                        return RASM_ERR_INVALID_ARGUMENT;
                    }
                }
                return RASM_OK;
            }
            if (in->op_count == 2 && is_reg16(&in->ops[0]) && is_imm(&in->ops[1])) {
                // In 32/64-bit mode, 16-bit operands need operand-size prefix
                // In 16-bit mode, 16-bit is default, no prefix needed
                if (unit->arch != ARCH_X86_16) emit_u8(&unit->text, 0x66);
                reg_kind dst = in->ops[0].v.reg;
                bool rex_b = gpr_is_high(dst);
                if (rex_b) emit_rex(&unit->text, false, false, false, true, unit->arch);
                emit_u8(&unit->text, (uint8_t)(0xB8 + gpr_low3(dst)));
                int64_t val;
                if (get_operand_imm(&in->ops[1], unit, &val)) {
                    // Validate 16-bit immediate range
                    if (!validate_immediate(val, 16)) {
                        return RASM_ERR_INVALID_ARGUMENT;
                    }
                    emit_u16(&unit->text, (uint16_t)val);
                } else {
                    // Unresolved symbol - emit placeholder and add relocation
                    emit_u16(&unit->text, 0);
                    if (in->ops[1].kind == OP_SYMBOL) {
                        // Use 16-bit absolute relocation for 16-bit mode
                        relocation r = { .kind = RELOC_ABS32, .symbol = in->ops[1].v.sym, .offset = unit->text.len - 2, .addend = 0 };
                        VEC_PUSH(unit->text_relocs, r);
                    } else {
                        return RASM_ERR_INVALID_ARGUMENT;
                    }
                }
                return RASM_OK;
            }
            if (in->op_count == 2 && is_reg8(&in->ops[0]) && is_imm(&in->ops[1])) {
                reg_kind dst = in->ops[0].v.reg;
                bool rex_needed = gpr_is_high(dst) || (is_gpr8(dst) && reg_code(dst) >= 4 && reg_code(dst) <= 7); // spl/bpl/sil/dil need REX
                if (rex_needed) emit_rex(&unit->text, false, false, false, gpr_is_high(dst), unit->arch);
                // For 8-bit registers including AH/CH/DH/BH, use the full register code
                emit_u8(&unit->text, (uint8_t)(0xB0 + (reg_code(dst) & 0x0F)));
                int64_t val;
                if (get_operand_imm(&in->ops[1], unit, &val)) {
                    // Validate 8-bit immediate range
                    if (!validate_immediate(val, 8)) {
                        return RASM_ERR_INVALID_ARGUMENT;
                    }
                    emit_u8(&unit->text, (uint8_t)val);
                } else {
                    return RASM_ERR_INVALID_ARGUMENT;
                }
                return RASM_OK;
            }
            // MOV reg, reg/mem variants (64-bit)
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg64(&in->ops[0])) && is_reg64(&in->ops[1])) {
                uint8_t opc[] = {0x89};
                uint8_t reg_field = reg_code(in->ops[1].v.reg);
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], reg_field, true, unit, RELOC_PC32);
            }
            if (in->op_count == 2 && is_reg64(&in->ops[0]) && (is_memop(&in->ops[1]) || is_reg64(&in->ops[1]))) {
                uint8_t opc[] = {0x8B};
                uint8_t reg_field = reg_code(in->ops[0].v.reg);
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[1], reg_field, true, unit, RELOC_PC32);
            }
            // MOV reg, reg/mem variants (32-bit)
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg32(&in->ops[0])) && is_reg32(&in->ops[1])) {
                uint8_t pfx[1];
                size_t pfx_len = 0;
                if (unit->arch == ARCH_X86_16) pfx[pfx_len++] = 0x66; // 32-bit operand in 16-bit mode
                uint8_t opc[] = {0x89};
                uint8_t reg_field = reg_code(in->ops[1].v.reg);
                return emit_op_modrm_legacy(pfx, pfx_len, opc, 1, &in->ops[0], reg_field, false, unit, RELOC_PC32);
            }
            if (in->op_count == 2 && is_reg32(&in->ops[0]) && (is_memop(&in->ops[1]) || is_reg32(&in->ops[1]))) {
                uint8_t pfx[1];
                size_t pfx_len = 0;
                if (unit->arch == ARCH_X86_16) pfx[pfx_len++] = 0x66; // 32-bit operand in 16-bit mode
                uint8_t opc[] = {0x8B};
                uint8_t reg_field = reg_code(in->ops[0].v.reg);
                return emit_op_modrm_legacy(pfx, pfx_len, opc, 1, &in->ops[1], reg_field, false, unit, RELOC_PC32);
            }
            // MOV reg, reg/mem variants (16-bit)
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg16(&in->ops[0])) && is_reg16(&in->ops[1])) {
                uint8_t pfx[1];
                size_t pfx_len = 0;
                if (unit->arch != ARCH_X86_16) pfx[pfx_len++] = 0x66; // 16-bit operand in 32/64-bit mode
                uint8_t opc[] = {0x89};
                uint8_t reg_field = reg_code(in->ops[1].v.reg);
                return emit_op_modrm_legacy(pfx, pfx_len, opc, 1, &in->ops[0], reg_field, false, unit, RELOC_PC32);
            }
            if (in->op_count == 2 && is_reg16(&in->ops[0]) && (is_memop(&in->ops[1]) || is_reg16(&in->ops[1]))) {
                uint8_t pfx[1];
                size_t pfx_len = 0;
                if (unit->arch != ARCH_X86_16) pfx[pfx_len++] = 0x66; // 16-bit operand in 32/64-bit mode
                uint8_t opc[] = {0x8B};
                uint8_t reg_field = reg_code(in->ops[0].v.reg);
                return emit_op_modrm_legacy(pfx, pfx_len, opc, 1, &in->ops[1], reg_field, false, unit, RELOC_PC32);
            }
            // MOV reg, reg/mem variants (8-bit)
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg8(&in->ops[0])) && is_reg8(&in->ops[1])) {
                uint8_t opc[] = {0x88};
                uint8_t reg_field = reg_code(in->ops[1].v.reg);
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], reg_field, false, unit, RELOC_PC32);
            }
            if (in->op_count == 2 && is_reg8(&in->ops[0]) && (is_memop(&in->ops[1]) || is_reg8(&in->ops[1]))) {
                uint8_t opc[] = {0x8A};
                uint8_t reg_field = reg_code(in->ops[0].v.reg);
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[1], reg_field, false, unit, RELOC_PC32);
            }
            // MOV mem, imm variants
            if (in->op_count == 2 && is_memop(&in->ops[0]) && is_imm(&in->ops[1])) {
                uint8_t opc[] = {0xC7};
                rasm_status st = emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 0, true, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                if (in->ops[1].kind == OP_IMM) emit_u32(&unit->text, (uint32_t)in->ops[1].v.imm);
                else {
                    emit_u32(&unit->text, 0);
                    relocation r = { .kind = RELOC_ABS32, .symbol = in->ops[1].v.sym, .offset = unit->text.len - 4, .addend = 0 };
                    VEC_PUSH(unit->text_relocs, r);
                }
                return RASM_OK;
            }
            // MOV segreg, r/m16
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_segreg(in->ops[0].v.reg) && (is_reg16(&in->ops[1]) || is_memop(&in->ops[1]))) {
                uint8_t opc[] = {0x8E};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            // MOV r/m16, segreg
            if (in->op_count == 2 && (is_reg16(&in->ops[0]) || is_memop(&in->ops[0])) && in->ops[1].kind == OP_REG && is_segreg(in->ops[1].v.reg)) {
                uint8_t opc[] = {0x8C};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], reg_code(in->ops[1].v.reg), false, unit, RELOC_PC32);
            }
            // MOV reg32/64, CR0-4/CR8 or MOV CR0-4/CR8, reg32/64
            // In 16/32-bit modes use 32-bit registers, in 64-bit mode use 64-bit registers
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && in->ops[1].kind == OP_REG) {
                if ((is_reg32(&in->ops[0]) || is_reg64(&in->ops[0])) && is_creg(in->ops[1].v.reg)) {
                    // MOV r32/r64, CRx (0F 20 /r)
                    // In 16/32-bit mode, operand size is 32-bit
                    // In 64-bit mode, operand size is 64-bit (REX.W not needed, it's implicit)
                    if (is_reg32(&in->ops[0]) && unit->arch != ARCH_X86_16) {
                        emit_u8(&unit->text, 0x66);  // 32-bit override in 64-bit mode
                    }
                    emit_u8(&unit->text, 0x0F);
                    emit_u8(&unit->text, 0x20);
                    uint8_t modrm = 0xC0 | (reg_code(in->ops[1].v.reg) << 3) | (reg_code(in->ops[0].v.reg) & 0x07);
                    emit_u8(&unit->text, modrm);
                    return RASM_OK;
                } else if (is_creg(in->ops[0].v.reg) && (is_reg32(&in->ops[1]) || is_reg64(&in->ops[1]))) {
                    // MOV CRx, r32/r64 (0F 22 /r)
                    if (is_reg32(&in->ops[1]) && unit->arch != ARCH_X86_16) {
                        emit_u8(&unit->text, 0x66);  // 32-bit override in 64-bit mode
                    }
                    emit_u8(&unit->text, 0x0F);
                    emit_u8(&unit->text, 0x22);
                    uint8_t modrm = 0xC0 | (reg_code(in->ops[0].v.reg) << 3) | (reg_code(in->ops[1].v.reg) & 0x07);
                    emit_u8(&unit->text, modrm);
                    return RASM_OK;
                } else if ((is_reg32(&in->ops[0]) || is_reg64(&in->ops[0])) && is_dreg(in->ops[1].v.reg)) {
                    // MOV r32/r64, DRx (0F 21 /r)
                    if (is_reg32(&in->ops[0]) && unit->arch != ARCH_X86_16) {
                        emit_u8(&unit->text, 0x66);  // 32-bit override in 64-bit mode
                    }
                    emit_u8(&unit->text, 0x0F);
                    emit_u8(&unit->text, 0x21);
                    uint8_t modrm = 0xC0 | (reg_code(in->ops[1].v.reg) << 3) | (reg_code(in->ops[0].v.reg) & 0x07);
                    emit_u8(&unit->text, modrm);
                    return RASM_OK;
                } else if (is_dreg(in->ops[0].v.reg) && (is_reg32(&in->ops[1]) || is_reg64(&in->ops[1]))) {
                    // MOV DRx, r32/r64 (0F 23 /r)
                    if (is_reg32(&in->ops[1]) && unit->arch != ARCH_X86_16) {
                        emit_u8(&unit->text, 0x66);  // 32-bit override in 64-bit mode
                    }
                    emit_u8(&unit->text, 0x0F);
                    emit_u8(&unit->text, 0x23);
                    uint8_t modrm = 0xC0 | (reg_code(in->ops[0].v.reg) << 3) | (reg_code(in->ops[1].v.reg) & 0x07);
                    emit_u8(&unit->text, modrm);
                    return RASM_OK;
                }
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_ADD:
        case MNEM_SUB:
        case MNEM_CMP:
        case MNEM_XOR:
        case MNEM_AND:
        case MNEM_OR:
        case MNEM_ADC:
        case MNEM_SBB: {
            uint8_t op_rm_r_64 = 0, op_r_rm_64 = 0;
            uint8_t op_rm_r_8 = 0, op_r_rm_8 = 0;
            uint8_t imm_ext = 0;
            switch (in->mnem) {
                case MNEM_ADD: op_rm_r_64 = 0x01; op_r_rm_64 = 0x03; op_rm_r_8 = 0x00; op_r_rm_8 = 0x02; imm_ext = 0x00; break;
                case MNEM_SUB: op_rm_r_64 = 0x29; op_r_rm_64 = 0x2B; op_rm_r_8 = 0x28; op_r_rm_8 = 0x2A; imm_ext = 0x05; break;
                case MNEM_CMP: op_rm_r_64 = 0x39; op_r_rm_64 = 0x3B; op_rm_r_8 = 0x38; op_r_rm_8 = 0x3A; imm_ext = 0x07; break;
                case MNEM_XOR: op_rm_r_64 = 0x31; op_r_rm_64 = 0x33; op_rm_r_8 = 0x30; op_r_rm_8 = 0x32; imm_ext = 0x06; break;
                case MNEM_AND: op_rm_r_64 = 0x21; op_r_rm_64 = 0x23; op_rm_r_8 = 0x20; op_r_rm_8 = 0x22; imm_ext = 0x04; break;
                case MNEM_OR:  op_rm_r_64 = 0x09; op_r_rm_64 = 0x0B; op_rm_r_8 = 0x08; op_r_rm_8 = 0x0A; imm_ext = 0x01; break;
                case MNEM_ADC: op_rm_r_64 = 0x11; op_r_rm_64 = 0x13; op_rm_r_8 = 0x10; op_r_rm_8 = 0x12; imm_ext = 0x02; break;
                case MNEM_SBB: op_rm_r_64 = 0x19; op_r_rm_64 = 0x1B; op_rm_r_8 = 0x18; op_r_rm_8 = 0x1A; imm_ext = 0x03; break;
                default: break;
            }

            // 64-bit reg/mem, reg
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg64(&in->ops[0])) && is_reg64(&in->ops[1])) {
                uint8_t opc[] = {op_rm_r_64};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], reg_code(in->ops[1].v.reg), true, unit, RELOC_PC32);
            }
            // 64-bit reg, reg/mem
            if (in->op_count == 2 && is_reg64(&in->ops[0]) && (is_memop(&in->ops[1]) || is_reg64(&in->ops[1]))) {
                uint8_t opc[] = {op_r_rm_64};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), true, unit, RELOC_PC32);
            }
            // 32-bit reg/mem, reg
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg32(&in->ops[0])) && is_reg32(&in->ops[1])) {
                uint8_t pfx[1];
                size_t pfx_len = 0;
                if (unit->arch == ARCH_X86_16) pfx[pfx_len++] = 0x66;
                uint8_t opc[] = {op_rm_r_64};
                return emit_op_modrm_legacy(pfx, pfx_len, opc, 1, &in->ops[0], reg_code(in->ops[1].v.reg), false, unit, RELOC_PC32);
            }
            // 32-bit reg, reg/mem
            if (in->op_count == 2 && is_reg32(&in->ops[0]) && (is_memop(&in->ops[1]) || is_reg32(&in->ops[1]))) {
                uint8_t pfx[1];
                size_t pfx_len = 0;
                if (unit->arch == ARCH_X86_16) pfx[pfx_len++] = 0x66;
                uint8_t opc[] = {op_r_rm_64};
                return emit_op_modrm_legacy(pfx, pfx_len, opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            // 16-bit reg/mem, reg
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg16(&in->ops[0])) && is_reg16(&in->ops[1])) {
                uint8_t pfx[1];
                size_t pfx_len = 0;
                if (unit->arch != ARCH_X86_16) pfx[pfx_len++] = 0x66;
                uint8_t opc[] = {op_rm_r_64};
                return emit_op_modrm_legacy(pfx, pfx_len, opc, 1, &in->ops[0], reg_code(in->ops[1].v.reg), false, unit, RELOC_PC32);
            }
            // 16-bit reg, reg/mem
            if (in->op_count == 2 && is_reg16(&in->ops[0]) && (is_memop(&in->ops[1]) || is_reg16(&in->ops[1]))) {
                uint8_t pfx[1];
                size_t pfx_len = 0;
                if (unit->arch != ARCH_X86_16) pfx[pfx_len++] = 0x66;
                uint8_t opc[] = {op_r_rm_64};
                return emit_op_modrm_legacy(pfx, pfx_len, opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            // 8-bit reg/mem, reg
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg8(&in->ops[0])) && is_reg8(&in->ops[1])) {
                uint8_t opc[] = {op_rm_r_8};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], reg_code(in->ops[1].v.reg), false, unit, RELOC_PC32);
            }
            // 8-bit reg, reg/mem
            if (in->op_count == 2 && is_reg8(&in->ops[0]) && (is_memop(&in->ops[1]) || is_reg8(&in->ops[1]))) {
                uint8_t opc[] = {op_r_rm_8};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            // 64-bit reg/mem, imm
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg64(&in->ops[0])) && is_imm(&in->ops[1])) {
                bool use_imm8 = in->ops[1].kind == OP_IMM && is_simm8(&in->ops[1]);
                // Validate immediate range
                if (in->ops[1].kind == OP_IMM) {
                    if (use_imm8 && !validate_immediate(in->ops[1].v.imm, 8)) {
                        return RASM_ERR_INVALID_ARGUMENT;
                    }
                    if (!use_imm8 && !validate_immediate(in->ops[1].v.imm, 32)) {
                        return RASM_ERR_INVALID_ARGUMENT;
                    }
                }
                uint8_t opc[] = { (uint8_t)(use_imm8 ? 0x83 : 0x81) };
                rasm_status st = emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], imm_ext, true, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                if (use_imm8 && in->ops[1].kind == OP_IMM) {
                    emit_u8(&unit->text, (uint8_t)in->ops[1].v.imm);
                } else {
                    if (in->ops[1].kind == OP_IMM) emit_u32(&unit->text, (uint32_t)in->ops[1].v.imm);
                    else {
                        emit_u32(&unit->text, 0);
                        relocation r = { .kind = RELOC_ABS32, .symbol = in->ops[1].v.sym, .offset = unit->text.len - 4, .addend = 0 };
                        VEC_PUSH(unit->text_relocs, r);
                    }
                }
                return RASM_OK;
            }
            // 32-bit reg/mem, imm
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg32(&in->ops[0])) && is_imm(&in->ops[1])) {
                bool use_imm8 = in->ops[1].kind == OP_IMM && is_simm8(&in->ops[1]);
                // Validate immediate range
                if (in->ops[1].kind == OP_IMM) {
                    if (use_imm8 && !validate_immediate(in->ops[1].v.imm, 8)) {
                        return RASM_ERR_INVALID_ARGUMENT;
                    }
                    if (!use_imm8 && !validate_immediate(in->ops[1].v.imm, 32)) {
                        return RASM_ERR_INVALID_ARGUMENT;
                    }
                }
                uint8_t pfx[1];
                size_t pfx_len = 0;
                if (unit->arch == ARCH_X86_16) pfx[pfx_len++] = 0x66;
                uint8_t opc[] = { (uint8_t)(use_imm8 ? 0x83 : 0x81) };
                rasm_status st = emit_op_modrm_legacy(pfx, pfx_len, opc, 1, &in->ops[0], imm_ext, false, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                if (use_imm8) {
                    emit_u8(&unit->text, (uint8_t)in->ops[1].v.imm);
                } else {
                    emit_u32(&unit->text, (uint32_t)in->ops[1].v.imm);
                }
                return RASM_OK;
            }
            // 16-bit reg/mem, imm
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg16(&in->ops[0])) && is_imm(&in->ops[1])) {
                bool use_imm8 = in->ops[1].kind == OP_IMM && is_simm8(&in->ops[1]);
                // Validate immediate range
                if (in->ops[1].kind == OP_IMM) {
                    if (use_imm8 && !validate_immediate(in->ops[1].v.imm, 8)) {
                        return RASM_ERR_INVALID_ARGUMENT;
                    }
                    if (!use_imm8 && !validate_immediate(in->ops[1].v.imm, 16)) {
                        return RASM_ERR_INVALID_ARGUMENT;
                    }
                }
                uint8_t pfx[1];
                size_t pfx_len = 0;
                if (unit->arch != ARCH_X86_16) pfx[pfx_len++] = 0x66;
                uint8_t opc[] = { (uint8_t)(use_imm8 ? 0x83 : 0x81) };
                rasm_status st = emit_op_modrm_legacy(pfx, pfx_len, opc, 1, &in->ops[0], imm_ext, false, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                if (use_imm8) {
                    emit_u8(&unit->text, (uint8_t)in->ops[1].v.imm);
                } else {
                    emit_u16(&unit->text, (uint16_t)in->ops[1].v.imm);
                }
                return RASM_OK;
            }
            // 8-bit reg/mem, imm
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg8(&in->ops[0])) && is_imm(&in->ops[1])) {
                uint8_t opc[] = {0x80};
                rasm_status st = emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], imm_ext, false, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                emit_u8(&unit->text, (uint8_t)in->ops[1].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_TEST: {
            // 64-bit reg/mem, reg
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg64(&in->ops[0])) && is_reg64(&in->ops[1])) {
                uint8_t opc[] = {0x85};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], reg_code(in->ops[1].v.reg), true, unit, RELOC_PC32);
            }
            // 32-bit reg/mem, reg
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg32(&in->ops[0])) && is_reg32(&in->ops[1])) {
                uint8_t pfx[1];
                size_t pfx_len = 0;
                if (unit->arch == ARCH_X86_16) pfx[pfx_len++] = 0x66;
                uint8_t opc[] = {0x85};
                return emit_op_modrm_legacy(pfx, pfx_len, opc, 1, &in->ops[0], reg_code(in->ops[1].v.reg), false, unit, RELOC_PC32);
            }
            // 16-bit reg/mem, reg
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg16(&in->ops[0])) && is_reg16(&in->ops[1])) {
                uint8_t pfx[1];
                size_t pfx_len = 0;
                if (unit->arch != ARCH_X86_16) pfx[pfx_len++] = 0x66;
                uint8_t opc[] = {0x85};
                return emit_op_modrm_legacy(pfx, pfx_len, opc, 1, &in->ops[0], reg_code(in->ops[1].v.reg), false, unit, RELOC_PC32);
            }
            // 8-bit reg/mem, reg
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg8(&in->ops[0])) && is_reg8(&in->ops[1])) {
                uint8_t opc[] = {0x84};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], reg_code(in->ops[1].v.reg), false, unit, RELOC_PC32);
            }
            // 64-bit reg/mem, imm
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg64(&in->ops[0])) && is_imm(&in->ops[1])) {
                uint8_t opc[] = {0xF7};
                rasm_status st = emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 0, true, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                if (in->ops[1].kind == OP_IMM) emit_u32(&unit->text, (uint32_t)in->ops[1].v.imm);
                else {
                    emit_u32(&unit->text, 0);
                    relocation r = { .kind = RELOC_ABS32, .symbol = in->ops[1].v.sym, .offset = unit->text.len - 4, .addend = 0 };
                    VEC_PUSH(unit->text_relocs, r);
                }
                return RASM_OK;
            }
            // 32-bit reg/mem, imm
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg32(&in->ops[0])) && is_imm(&in->ops[1])) {
                uint8_t pfx[1];
                size_t pfx_len = 0;
                if (unit->arch == ARCH_X86_16) pfx[pfx_len++] = 0x66;
                uint8_t opc[] = {0xF7};
                rasm_status st = emit_op_modrm_legacy(pfx, pfx_len, opc, 1, &in->ops[0], 0, false, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                emit_u32(&unit->text, (uint32_t)in->ops[1].v.imm);
                return RASM_OK;
            }
            // 16-bit reg/mem, imm
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg16(&in->ops[0])) && is_imm(&in->ops[1])) {
                uint8_t pfx[1];
                size_t pfx_len = 0;
                if (unit->arch != ARCH_X86_16) pfx[pfx_len++] = 0x66;
                uint8_t opc[] = {0xF7};
                rasm_status st = emit_op_modrm_legacy(pfx, pfx_len, opc, 1, &in->ops[0], 0, false, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                emit_u16(&unit->text, (uint16_t)in->ops[1].v.imm);
                return RASM_OK;
            }
            // 8-bit reg/mem, imm
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg8(&in->ops[0])) && is_imm(&in->ops[1])) {
                uint8_t opc[] = {0xF6};
                rasm_status st = emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 0, false, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                emit_u8(&unit->text, (uint8_t)in->ops[1].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_LEA: {
            if (in->op_count == 2 && is_reg64(&in->ops[0]) && is_memop(&in->ops[1])) {
                uint8_t opc[] = {0x8D};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), true, unit, RELOC_PC32);
            }
            if (in->op_count == 2 && is_reg32(&in->ops[0]) && is_memop(&in->ops[1])) {
                uint8_t pfx[1];
                size_t pfx_len = 0;
                if (unit->arch == ARCH_X86_16) pfx[pfx_len++] = 0x66; // 32-bit operand in 16-bit mode
                uint8_t opc[] = {0x8D};
                return emit_op_modrm_legacy(pfx, pfx_len, opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            if (in->op_count == 2 && is_reg16(&in->ops[0]) && is_memop(&in->ops[1])) {
                uint8_t pfx[1];
                size_t pfx_len = 0;
                if (unit->arch != ARCH_X86_16) pfx[pfx_len++] = 0x66; // 16-bit operand in 32/64-bit mode
                uint8_t opc[] = {0x8D};
                return emit_op_modrm_legacy(pfx, pfx_len, opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_PUSH: {
            // 64-bit register
            if (in->op_count == 1 && is_reg64(&in->ops[0])) {
                reg_kind r = in->ops[0].v.reg;
                bool rex_b = gpr_is_high(r);
                if (rex_b) emit_rex(&unit->text, false, false, false, true, unit->arch);
                emit_u8(&unit->text, (uint8_t)(0x50 + gpr_low3(r)));
                return RASM_OK;
            }
            // 32-bit register
            if (in->op_count == 1 && is_reg32(&in->ops[0])) {
                uint8_t pfx[1];
                size_t pfx_len = 0;
                if (unit->arch == ARCH_X86_16) pfx[pfx_len++] = 0x66; // 32-bit operand in 16-bit mode
                for (size_t i = 0; i < pfx_len; ++i) emit_u8(&unit->text, pfx[i]);
                emit_u8(&unit->text, (uint8_t)(0x50 + reg_code(in->ops[0].v.reg)));
                return RASM_OK;
            }
            // 16-bit register
            if (in->op_count == 1 && is_reg16(&in->ops[0])) {
                uint8_t pfx[1];
                size_t pfx_len = 0;
                if (unit->arch != ARCH_X86_16) pfx[pfx_len++] = 0x66; // 16-bit operand in 32/64-bit mode
                for (size_t i = 0; i < pfx_len; ++i) emit_u8(&unit->text, pfx[i]);
                emit_u8(&unit->text, (uint8_t)(0x50 + reg_code(in->ops[0].v.reg)));
                return RASM_OK;
            }
            // Segment register
            if (in->op_count == 1 && is_segreg(in->ops[0].v.reg)) {
                uint8_t seg_code = reg_code(in->ops[0].v.reg);
                // ES=0x06, CS=0x0E, SS=0x16, DS=0x1E, FS=0xA0 0x0F, GS=0xA8 0x0F
                if (seg_code <= 3) { // ES, CS, SS, DS
                    emit_u8(&unit->text, (uint8_t)(0x06 + seg_code * 8));
                } else if (seg_code == 4) { // FS
                    emit_u8(&unit->text, 0x0F);
                    emit_u8(&unit->text, 0xA0);
                } else { // GS
                    emit_u8(&unit->text, 0x0F);
                    emit_u8(&unit->text, 0xA8);
                }
                return RASM_OK;
            }
            // Memory operand
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0xFF};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 6, false, unit, RELOC_PC32);
            }
            // Immediate
            if (in->op_count == 1 && is_imm(&in->ops[0])) {
                if (in->ops[0].kind == OP_IMM && is_simm8(&in->ops[0])) {
                    emit_u8(&unit->text, 0x6A);
                    emit_u8(&unit->text, (uint8_t)in->ops[0].v.imm);
                } else {
                    emit_u8(&unit->text, 0x68);
                    if (in->ops[0].kind == OP_IMM) {
                        if (unit->arch == ARCH_X86_16) {
                            // 16-bit mode: push 16-bit immediate
                            emit_u16(&unit->text, (uint16_t)in->ops[0].v.imm);
                        } else {
                            // 32/64-bit mode: push 32-bit immediate
                            emit_u32(&unit->text, (uint32_t)in->ops[0].v.imm);
                        }
                    } else {
                        emit_u32(&unit->text, 0);
                        relocation r = { .kind = RELOC_ABS32, .symbol = in->ops[0].v.sym, .offset = unit->text.len - 4, .addend = 0 };
                        VEC_PUSH(unit->text_relocs, r);
                    }
                }
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_POP: {
            // 64-bit register
            if (in->op_count == 1 && is_reg64(&in->ops[0])) {
                reg_kind r = in->ops[0].v.reg;
                bool rex_b = gpr_is_high(r);
                if (rex_b) emit_rex(&unit->text, false, false, false, true, unit->arch);
                emit_u8(&unit->text, (uint8_t)(0x58 + gpr_low3(r)));
                return RASM_OK;
            }
            // 32-bit register
            if (in->op_count == 1 && is_reg32(&in->ops[0])) {
                uint8_t pfx[1];
                size_t pfx_len = 0;
                if (unit->arch == ARCH_X86_16) pfx[pfx_len++] = 0x66; // 32-bit operand in 16-bit mode
                for (size_t i = 0; i < pfx_len; ++i) emit_u8(&unit->text, pfx[i]);
                emit_u8(&unit->text, (uint8_t)(0x58 + reg_code(in->ops[0].v.reg)));
                return RASM_OK;
            }
            // 16-bit register
            if (in->op_count == 1 && is_reg16(&in->ops[0])) {
                uint8_t pfx[1];
                size_t pfx_len = 0;
                if (unit->arch != ARCH_X86_16) pfx[pfx_len++] = 0x66; // 16-bit operand in 32/64-bit mode
                for (size_t i = 0; i < pfx_len; ++i) emit_u8(&unit->text, pfx[i]);
                emit_u8(&unit->text, (uint8_t)(0x58 + reg_code(in->ops[0].v.reg)));
                return RASM_OK;
            }
            // Segment register
            if (in->op_count == 1 && is_segreg(in->ops[0].v.reg)) {
                uint8_t seg_code = reg_code(in->ops[0].v.reg);
                // ES=0x07, CS=invalid, SS=0x17, DS=0x1F, FS=0xA1 0x0F, GS=0xA9 0x0F
                if (seg_code == 1) return RASM_ERR_INVALID_ARGUMENT; // Cannot POP CS
                if (seg_code == 0 || seg_code == 2 || seg_code == 3) { // ES, SS, DS
                    emit_u8(&unit->text, (uint8_t)(0x07 + seg_code * 8));
                } else if (seg_code == 4) { // FS
                    emit_u8(&unit->text, 0x0F);
                    emit_u8(&unit->text, 0xA1);
                } else { // GS
                    emit_u8(&unit->text, 0x0F);
                    emit_u8(&unit->text, 0xA9);
                }
                return RASM_OK;
            }
            // Memory operand
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0x8F};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 0, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_INC:
        case MNEM_DEC: {
            if (in->op_count == 1 && (is_memop(&in->ops[0]) || is_reg64(&in->ops[0]))) {
                uint8_t opc[] = {0xFF};
                uint8_t ext = (in->mnem == MNEM_INC) ? 0 : 1;
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], ext, true, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_NEG:
        case MNEM_NOT: {
            if (in->op_count == 1 && (is_memop(&in->ops[0]) || is_reg64(&in->ops[0]))) {
                uint8_t opc[] = {0xF7};
                uint8_t ext = (in->mnem == MNEM_NOT) ? 2 : 3;
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], ext, true, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_SHL:
        case MNEM_SAL:
        case MNEM_SHR:
        case MNEM_SAR: {
            uint8_t ext = 0;
            switch (in->mnem) {
                case MNEM_SHL:
                case MNEM_SAL: ext = 4; break;
                case MNEM_SHR: ext = 5; break;
                case MNEM_SAR: ext = 7; break;
                default: break;
            }
            if (in->op_count == 1 && (is_memop(&in->ops[0]) || is_reg64(&in->ops[0]))) {
                uint8_t opc[] = {0xD1};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], ext, true, unit, RELOC_PC32);
            }
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg64(&in->ops[0])) && in->ops[1].kind == OP_REG && in->ops[1].v.reg == REG_RCX) {
                uint8_t opc[] = {0xD3};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], ext, true, unit, RELOC_PC32);
            }
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg64(&in->ops[0])) && is_imm8(&in->ops[1])) {
                uint8_t opc[] = {0xC1};
                rasm_status st = emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], ext, true, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                emit_u8(&unit->text, (uint8_t)in->ops[1].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_ROL:
        case MNEM_ROR:
        case MNEM_RCL:
        case MNEM_RCR: {
            uint8_t ext = 0;
            switch (in->mnem) {
                case MNEM_ROL: ext = 0; break;
                case MNEM_ROR: ext = 1; break;
                case MNEM_RCL: ext = 2; break;
                case MNEM_RCR: ext = 3; break;
                default: break;
            }
            if (in->op_count == 1 && (is_memop(&in->ops[0]) || is_reg64(&in->ops[0]))) {
                uint8_t opc[] = {0xD1};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], ext, true, unit, RELOC_PC32);
            }
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg64(&in->ops[0])) && in->ops[1].kind == OP_REG && in->ops[1].v.reg == REG_RCX) {
                uint8_t opc[] = {0xD3};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], ext, true, unit, RELOC_PC32);
            }
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg64(&in->ops[0])) && is_imm8(&in->ops[1])) {
                uint8_t opc[] = {0xC1};
                rasm_status st = emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], ext, true, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                emit_u8(&unit->text, (uint8_t)in->ops[1].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_MOVZX:
        case MNEM_MOVSX: {
            if (in->op_count == 2 && is_reg64(&in->ops[0]) && (is_reg64(&in->ops[1]) || is_memop(&in->ops[1]))) {
                uint8_t opc[] = {0x0F, (uint8_t)(in->mnem == MNEM_MOVZX ? 0xB6 : 0xBE)};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), true, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_MOVSXD: {
            if (in->op_count == 2 && is_reg64(&in->ops[0]) && (is_reg64(&in->ops[1]) || is_memop(&in->ops[1]))) {
                uint8_t opc[] = {0x63};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), true, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_XCHG: {
            // XCHG rax, reg or reg, rax (short form)
            if (in->op_count == 2 && is_reg64(&in->ops[0]) && is_reg64(&in->ops[1])) {
                if (in->ops[0].v.reg == REG_RAX && in->ops[1].v.reg != REG_RAX) {
                    emit_rex(&unit->text, true, false, false, gpr_is_high(in->ops[1].v.reg), unit->arch);
                    emit_u8(&unit->text, 0x90 + reg_code(in->ops[1].v.reg));
                    return RASM_OK;
                }
                if (in->ops[1].v.reg == REG_RAX && in->ops[0].v.reg != REG_RAX) {
                    emit_rex(&unit->text, true, false, false, gpr_is_high(in->ops[0].v.reg), unit->arch);
                    emit_u8(&unit->text, 0x90 + reg_code(in->ops[0].v.reg));
                    return RASM_OK;
                }
                // General form: XCHG r/m, r
                uint8_t opc[] = {0x87};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], reg_code(in->ops[1].v.reg), true, unit, RELOC_PC32);
            }
            if (in->op_count == 2 && is_memop(&in->ops[0]) && is_reg64(&in->ops[1])) {
                uint8_t opc[] = {0x87};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], reg_code(in->ops[1].v.reg), true, unit, RELOC_PC32);
            }
            if (in->op_count == 2 && is_reg64(&in->ops[0]) && is_memop(&in->ops[1])) {
                uint8_t opc[] = {0x87};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), true, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_XADD: {
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg64(&in->ops[0])) && is_reg64(&in->ops[1])) {
                uint8_t opc[] = {0x0F, 0xC1};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[0], reg_code(in->ops[1].v.reg), true, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_CMPXCHG: {
            if (in->op_count == 2 && (is_memop(&in->ops[0]) || is_reg64(&in->ops[0])) && is_reg64(&in->ops[1])) {
                uint8_t opc[] = {0x0F, 0xB1};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[0], reg_code(in->ops[1].v.reg), true, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_CMPXCHG8B: {
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0x0F, 0xC7};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[0], 1, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_CMPXCHG16B: {
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                emit_rex(&unit->text, true, false, false, false, unit->arch);
                uint8_t opc[] = {0x0F, 0xC7};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[0], 1, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_MOVAPS:
        case MNEM_MOVUPS:
        case MNEM_MOVDQA:
        case MNEM_MOVDQU: {
            if (in->op_count != 2) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t prefix = 0x00;
            uint8_t opc_load = 0x28;
            uint8_t opc_store = 0x29;
            if (in->mnem == MNEM_MOVUPS) { opc_load = 0x10; opc_store = 0x11; }
            if (in->mnem == MNEM_MOVDQA) { prefix = 0x66; opc_load = 0x6F; opc_store = 0x7F; }
            if (in->mnem == MNEM_MOVDQU) { prefix = 0xF3; opc_load = 0x6F; opc_store = 0x7F; }
            uint8_t prefixes[1];
            size_t pre_len = 0;
            if (prefix != 0x00) { prefixes[0] = prefix; pre_len = 1; }
            uint8_t opc_load_bytes[] = {0x0F, opc_load};
            uint8_t opc_store_bytes[] = {0x0F, opc_store};
            if (is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1]))) {
                if (is_xmmop(&in->ops[1]) && reg_code(in->ops[1].v.reg) >= 16) return RASM_ERR_INVALID_ARGUMENT;
                return emit_op_modrm_legacy(prefixes, pre_len, opc_load_bytes, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            if (is_memop(&in->ops[0]) && is_xmmop(&in->ops[1])) {
                return emit_op_modrm_legacy(prefixes, pre_len, opc_store_bytes, 2, &in->ops[0], reg_code(in->ops[1].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_ADDPS:
        case MNEM_ADDPD:
        case MNEM_SUBPS:
        case MNEM_SUBPD:
        case MNEM_MULPS:
        case MNEM_MULPD:
        case MNEM_DIVPS:
        case MNEM_DIVPD:
        case MNEM_SQRTPS:
        case MNEM_SQRTPD:
        case MNEM_XORPS:
        case MNEM_XORPD: {
            if (in->op_count == 2 && is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1]))) {
                uint8_t prefix = 0x00;
                uint8_t opcode = 0x58;
                switch (in->mnem) {
                    case MNEM_ADDPD: prefix = 0x66; opcode = 0x58; break;
                    case MNEM_SUBPS: prefix = 0x00; opcode = 0x5C; break;
                    case MNEM_SUBPD: prefix = 0x66; opcode = 0x5C; break;
                    case MNEM_MULPS: prefix = 0x00; opcode = 0x59; break;
                    case MNEM_MULPD: prefix = 0x66; opcode = 0x59; break;
                    case MNEM_DIVPS: prefix = 0x00; opcode = 0x5E; break;
                    case MNEM_DIVPD: prefix = 0x66; opcode = 0x5E; break;
                    case MNEM_SQRTPS: prefix = 0x00; opcode = 0x51; break;
                    case MNEM_SQRTPD: prefix = 0x66; opcode = 0x51; break;
                    case MNEM_XORPS: prefix = 0x00; opcode = 0x57; break;
                    case MNEM_XORPD: prefix = 0x66; opcode = 0x57; break;
                    default: break;
                }
                uint8_t prefixes[1];
                size_t pre_len = 0;
                if (prefix != 0x00) { prefixes[0] = prefix; pre_len = 1; }
                uint8_t opc_bytes[] = {0x0F, opcode};
                return emit_op_modrm_legacy(prefixes, pre_len, opc_bytes, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // Additional SSE/SSE2 logical operations
        case MNEM_ANDPS:
        case MNEM_ANDPD:
        case MNEM_ANDNPS:
        case MNEM_ANDNPD:
        case MNEM_ORPS:
        case MNEM_ORPD: {
            if (in->op_count == 2 && is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1]))) {
                uint8_t prefix = 0x00;
                uint8_t opcode = 0x54;
                switch (in->mnem) {
                    case MNEM_ANDPS: prefix = 0x00; opcode = 0x54; break;
                    case MNEM_ANDPD: prefix = 0x66; opcode = 0x54; break;
                    case MNEM_ANDNPS: prefix = 0x00; opcode = 0x55; break;
                    case MNEM_ANDNPD: prefix = 0x66; opcode = 0x55; break;
                    case MNEM_ORPS: prefix = 0x00; opcode = 0x56; break;
                    case MNEM_ORPD: prefix = 0x66; opcode = 0x56; break;
                    default: break;
                }
                uint8_t prefixes[1];
                size_t pre_len = 0;
                if (prefix != 0x00) { prefixes[0] = prefix; pre_len = 1; }
                uint8_t opc_bytes[] = {0x0F, opcode};
                return emit_op_modrm_legacy(prefixes, pre_len, opc_bytes, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // SSE/SSE2 Min/Max
        case MNEM_MINPS:
        case MNEM_MINPD:
        case MNEM_MINSS:
        case MNEM_MINSD:
        case MNEM_MAXPS:
        case MNEM_MAXPD:
        case MNEM_MAXSS:
        case MNEM_MAXSD: {
            if (in->op_count == 2 && is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1]))) {
                uint8_t prefix = 0x00;
                uint8_t opcode = 0x5D;
                switch (in->mnem) {
                    case MNEM_MINPS: prefix = 0x00; opcode = 0x5D; break;
                    case MNEM_MINPD: prefix = 0x66; opcode = 0x5D; break;
                    case MNEM_MINSS: prefix = 0xF3; opcode = 0x5D; break;
                    case MNEM_MINSD: prefix = 0xF2; opcode = 0x5D; break;
                    case MNEM_MAXPS: prefix = 0x00; opcode = 0x5F; break;
                    case MNEM_MAXPD: prefix = 0x66; opcode = 0x5F; break;
                    case MNEM_MAXSS: prefix = 0xF3; opcode = 0x5F; break;
                    case MNEM_MAXSD: prefix = 0xF2; opcode = 0x5F; break;
                    default: break;
                }
                uint8_t prefixes[1];
                size_t pre_len = 0;
                if (prefix != 0x00) { prefixes[0] = prefix; pre_len = 1; }
                uint8_t opc_bytes[] = {0x0F, opcode};
                return emit_op_modrm_legacy(prefixes, pre_len, opc_bytes, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // SSE Reciprocal operations
        case MNEM_RCPPS:
        case MNEM_RCPSS:
        case MNEM_RSQRTPS:
        case MNEM_RSQRTSS: {
            if (in->op_count == 2 && is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1]))) {
                uint8_t prefix = 0x00;
                uint8_t opcode = 0x53;
                switch (in->mnem) {
                    case MNEM_RCPPS: prefix = 0x00; opcode = 0x53; break;
                    case MNEM_RCPSS: prefix = 0xF3; opcode = 0x53; break;
                    case MNEM_RSQRTPS: prefix = 0x00; opcode = 0x52; break;
                    case MNEM_RSQRTSS: prefix = 0xF3; opcode = 0x52; break;
                    default: break;
                }
                uint8_t prefixes[1];
                size_t pre_len = 0;
                if (prefix != 0x00) { prefixes[0] = prefix; pre_len = 1; }
                uint8_t opc_bytes[] = {0x0F, opcode};
                return emit_op_modrm_legacy(prefixes, pre_len, opc_bytes, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // SSE/SSE2 Unpack
        case MNEM_UNPCKLPS:
        case MNEM_UNPCKHPS:
        case MNEM_UNPCKLPD:
        case MNEM_UNPCKHPD: {
            if (in->op_count == 2 && is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1]))) {
                uint8_t prefix = 0x00;
                uint8_t opcode = 0x14;
                switch (in->mnem) {
                    case MNEM_UNPCKLPS: prefix = 0x00; opcode = 0x14; break;
                    case MNEM_UNPCKHPS: prefix = 0x00; opcode = 0x15; break;
                    case MNEM_UNPCKLPD: prefix = 0x66; opcode = 0x14; break;
                    case MNEM_UNPCKHPD: prefix = 0x66; opcode = 0x15; break;
                    default: break;
                }
                uint8_t prefixes[1];
                size_t pre_len = 0;
                if (prefix != 0x00) { prefixes[0] = prefix; pre_len = 1; }
                uint8_t opc_bytes[] = {0x0F, opcode};
                return emit_op_modrm_legacy(prefixes, pre_len, opc_bytes, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // SSE/SSE2 Shuffle
        case MNEM_SHUFPS:
        case MNEM_SHUFPD: {
            if (in->op_count == 3 && is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1])) && is_imm8(&in->ops[2])) {
                uint8_t prefix = (in->mnem == MNEM_SHUFPD) ? 0x66 : 0x00;
                uint8_t prefixes[1];
                size_t pre_len = 0;
                if (prefix != 0x00) { prefixes[0] = prefix; pre_len = 1; }
                uint8_t opc_bytes[] = {0x0F, 0xC6};
                rasm_status st = emit_op_modrm_legacy(prefixes, pre_len, opc_bytes, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                emit_u8(&unit->text, (uint8_t)in->ops[2].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // SSE2 Packed shuffle
        case MNEM_PSHUFD:
        case MNEM_PSHUFHW:
        case MNEM_PSHUFLW: {
            if (in->op_count == 3 && is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1])) && is_imm8(&in->ops[2])) {
                uint8_t prefix = 0x66;
                if (in->mnem == MNEM_PSHUFHW) prefix = 0xF3;
                else if (in->mnem == MNEM_PSHUFLW) prefix = 0xF2;
                uint8_t prefixes[1] = {prefix};
                uint8_t opc_bytes[] = {0x0F, 0x70};
                rasm_status st = emit_op_modrm_legacy(prefixes, 1, opc_bytes, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                emit_u8(&unit->text, (uint8_t)in->ops[2].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // MMX PSHUFW
        case MNEM_PSHUFW: {
            if (in->op_count == 3 && is_mmx(in->ops[0].v.reg) && (is_mmx(in->ops[1].v.reg) || is_memop(&in->ops[1])) && is_imm8(&in->ops[2])) {
                uint8_t opc_bytes[] = {0x0F, 0x70};
                rasm_status st = emit_op_modrm_legacy(NULL, 0, opc_bytes, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                emit_u8(&unit->text, (uint8_t)in->ops[2].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // SSE/SSE2 Half/Low packed moves
        case MNEM_MOVHPS:
        case MNEM_MOVLPS:
        case MNEM_MOVHPD:
        case MNEM_MOVLPD: {
            if (in->op_count == 2) {
                uint8_t prefix = 0x00;
                uint8_t opc_load = 0x16;
                uint8_t opc_store = 0x17;
                switch (in->mnem) {
                    case MNEM_MOVHPS: prefix = 0x00; opc_load = 0x16; opc_store = 0x17; break;
                    case MNEM_MOVLPS: prefix = 0x00; opc_load = 0x12; opc_store = 0x13; break;
                    case MNEM_MOVHPD: prefix = 0x66; opc_load = 0x16; opc_store = 0x17; break;
                    case MNEM_MOVLPD: prefix = 0x66; opc_load = 0x12; opc_store = 0x13; break;
                    default: break;
                }
                uint8_t prefixes[1];
                size_t pre_len = 0;
                if (prefix != 0x00) { prefixes[0] = prefix; pre_len = 1; }
                uint8_t opc_load_bytes[] = {0x0F, opc_load};
                uint8_t opc_store_bytes[] = {0x0F, opc_store};
                // xmm, m64 (load)
                if (is_xmmop(&in->ops[0]) && is_memop(&in->ops[1])) {
                    return emit_op_modrm_legacy(prefixes, pre_len, opc_load_bytes, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
                }
                // m64, xmm (store)
                if (is_memop(&in->ops[0]) && is_xmmop(&in->ops[1])) {
                    return emit_op_modrm_legacy(prefixes, pre_len, opc_store_bytes, 2, &in->ops[0], reg_code(in->ops[1].v.reg), false, unit, RELOC_PC32);
                }
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // SSE/SSE2 MMX conversions
        case MNEM_CVTPI2PS:
        case MNEM_CVTPS2PI:
        case MNEM_CVTTPS2PI: {
            if (in->op_count == 2) {
                uint8_t opcode = 0x2A;
                bool xmm_first = (in->mnem == MNEM_CVTPI2PS);
                if (in->mnem == MNEM_CVTPS2PI) opcode = 0x2D;
                else if (in->mnem == MNEM_CVTTPS2PI) opcode = 0x2C;
                uint8_t opc_bytes[] = {0x0F, opcode};
                if (xmm_first && is_xmmop(&in->ops[0]) && (is_mmx(in->ops[1].v.reg) || is_memop(&in->ops[1]))) {
                    return emit_op_modrm_legacy(NULL, 0, opc_bytes, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
                }
                if (!xmm_first && is_mmx(in->ops[0].v.reg) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1]))) {
                    return emit_op_modrm_legacy(NULL, 0, opc_bytes, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
                }
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_CVTPI2PD:
        case MNEM_CVTPD2PI:
        case MNEM_CVTTPD2PI: {
            if (in->op_count == 2) {
                uint8_t prefix = 0x66;
                uint8_t opcode = 0x2A;
                bool xmm_first = (in->mnem == MNEM_CVTPI2PD);
                if (in->mnem == MNEM_CVTPD2PI) opcode = 0x2D;
                else if (in->mnem == MNEM_CVTTPD2PI) opcode = 0x2C;
                uint8_t prefixes[1] = {prefix};
                uint8_t opc_bytes[] = {0x0F, opcode};
                if (xmm_first && is_xmmop(&in->ops[0]) && (is_mmx(in->ops[1].v.reg) || is_memop(&in->ops[1]))) {
                    return emit_op_modrm_legacy(prefixes, 1, opc_bytes, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
                }
                if (!xmm_first && is_mmx(in->ops[0].v.reg) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1]))) {
                    return emit_op_modrm_legacy(prefixes, 1, opc_bytes, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
                }
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // SSE2 masked move
        case MNEM_MASKMOVDQU: {
            if (in->op_count == 2 && is_xmmop(&in->ops[0]) && is_xmmop(&in->ops[1])) {
                uint8_t prefix = 0x66;
                uint8_t prefixes[1] = {prefix};
                uint8_t opc_bytes[] = {0x0F, 0xF7};
                return emit_op_modrm_legacy(prefixes, 1, opc_bytes, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // SSE/SSE2 non-temporal stores
        case MNEM_MOVNTPS:
        case MNEM_MOVNTPD:
        case MNEM_MOVNTDQ: {
            if (in->op_count == 2 && is_memop(&in->ops[0]) && is_xmmop(&in->ops[1])) {
                uint8_t prefix = 0x00;
                uint8_t opcode = 0x2B;
                if (in->mnem == MNEM_MOVNTPD) prefix = 0x66;
                else if (in->mnem == MNEM_MOVNTDQ) { prefix = 0x66; opcode = 0xE7; }
                uint8_t prefixes[1];
                size_t pre_len = 0;
                if (prefix != 0x00) { prefixes[0] = prefix; pre_len = 1; }
                uint8_t opc_bytes[] = {0x0F, opcode};
                return emit_op_modrm_legacy(prefixes, pre_len, opc_bytes, 2, &in->ops[0], reg_code(in->ops[1].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // SSE3 Instructions
        case MNEM_MOVDDUP:
        case MNEM_MOVSHDUP:
        case MNEM_MOVSLDUP: {
            if (in->op_count == 2 && is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1]))) {
                uint8_t prefix = 0xF2;
                uint8_t opcode = 0x12;
                if (in->mnem == MNEM_MOVSHDUP) { prefix = 0xF3; opcode = 0x16; }
                else if (in->mnem == MNEM_MOVSLDUP) { prefix = 0xF3; opcode = 0x12; }
                uint8_t prefixes[1] = {prefix};
                uint8_t opc_bytes[] = {0x0F, opcode};
                return emit_op_modrm_legacy(prefixes, 1, opc_bytes, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_ADDSUBPS:
        case MNEM_ADDSUBPD: {
            if (in->op_count == 2 && is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1]))) {
                uint8_t prefix = (in->mnem == MNEM_ADDSUBPS) ? 0xF2 : 0x66;
                uint8_t prefixes[1] = {prefix};
                uint8_t opc_bytes[] = {0x0F, 0xD0};
                return emit_op_modrm_legacy(prefixes, 1, opc_bytes, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // SSSE3 Instructions
        case MNEM_PABSB:
        case MNEM_PABSW:
        case MNEM_PABSD: {
            if (in->op_count == 2 && is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1]))) {
                uint8_t opcode = 0x1C;
                if (in->mnem == MNEM_PABSW) opcode = 0x1D;
                else if (in->mnem == MNEM_PABSD) opcode = 0x1E;
                uint8_t prefix = 0x66;
                uint8_t prefixes[1] = {prefix};
                uint8_t opc_bytes[] = {0x0F, 0x38, opcode};
                return emit_op_modrm_legacy(prefixes, 1, opc_bytes, 3, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_PSIGNB:
        case MNEM_PSIGNW:
        case MNEM_PSIGND: {
            if (in->op_count == 2 && is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1]))) {
                uint8_t opcode = 0x08;
                if (in->mnem == MNEM_PSIGNW) opcode = 0x09;
                else if (in->mnem == MNEM_PSIGND) opcode = 0x0A;
                uint8_t prefix = 0x66;
                uint8_t prefixes[1] = {prefix};
                uint8_t opc_bytes[] = {0x0F, 0x38, opcode};
                return emit_op_modrm_legacy(prefixes, 1, opc_bytes, 3, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_PSHUFB: {
            if (in->op_count == 2 && is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1]))) {
                uint8_t prefix = 0x66;
                uint8_t prefixes[1] = {prefix};
                uint8_t opc_bytes[] = {0x0F, 0x38, 0x00};
                return emit_op_modrm_legacy(prefixes, 1, opc_bytes, 3, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_PMULHRSW: {
            if (in->op_count == 2 && is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1]))) {
                uint8_t prefix = 0x66;
                uint8_t prefixes[1] = {prefix};
                uint8_t opc_bytes[] = {0x0F, 0x38, 0x0B};
                return emit_op_modrm_legacy(prefixes, 1, opc_bytes, 3, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_PALIGNR: {
            if (in->op_count == 3 && is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1])) && is_imm8(&in->ops[2])) {
                uint8_t prefix = 0x66;
                uint8_t prefixes[1] = {prefix};
                uint8_t opc_bytes[] = {0x0F, 0x3A, 0x0F};
                rasm_status st = emit_op_modrm_legacy(prefixes, 1, opc_bytes, 3, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                emit_u8(&unit->text, (uint8_t)in->ops[2].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // SSE4.1 Instructions (only new ones - pminub, pminsw, pmaxub, pmaxsw handled in MMX section)
        case MNEM_PMINSB:
        case MNEM_PMINUW:
        case MNEM_PMINUD:
        case MNEM_PMINSD:
        case MNEM_PMAXSB:
        case MNEM_PMAXUW:
        case MNEM_PMAXUD:
        case MNEM_PMAXSD: {
            if (in->op_count == 2 && is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1]))) {
                uint8_t prefix = 0x66;
                uint8_t opcode = 0x38;
                switch (in->mnem) {
                    case MNEM_PMINSB: opcode = 0x38; break; // 0F 38 38
                    case MNEM_PMINUW: opcode = 0x3A; break; // 0F 38 3A
                    case MNEM_PMINUD: opcode = 0x3B; break; // 0F 38 3B
                    case MNEM_PMINSD: opcode = 0x39; break; // 0F 38 39
                    case MNEM_PMAXSB: opcode = 0x3C; break; // 0F 38 3C
                    case MNEM_PMAXUW: opcode = 0x3E; break; // 0F 38 3E
                    case MNEM_PMAXUD: opcode = 0x3F; break; // 0F 38 3F
                    case MNEM_PMAXSD: opcode = 0x3D; break; // 0F 38 3D
                    default: break;
                }
                uint8_t prefixes[1] = {prefix};
                uint8_t opc_bytes[] = {0x0F, 0x38, opcode};
                return emit_op_modrm_legacy(prefixes, 1, opc_bytes, 3, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_PMULDQ: {
            if (in->op_count == 2 && is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1]))) {
                uint8_t prefix = 0x66;
                uint8_t prefixes[1] = {prefix};
                uint8_t opc_bytes[] = {0x0F, 0x38, 0x28};
                return emit_op_modrm_legacy(prefixes, 1, opc_bytes, 3, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_MOVNTDQA: {
            if (in->op_count == 2 && is_xmmop(&in->ops[0]) && is_memop(&in->ops[1])) {
                uint8_t prefix = 0x66;
                uint8_t prefixes[1] = {prefix};
                uint8_t opc_bytes[] = {0x0F, 0x38, 0x2A};
                return emit_op_modrm_legacy(prefixes, 1, opc_bytes, 3, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_PINSRB:
        case MNEM_PINSRD:
        case MNEM_PINSRQ: {
            if (in->op_count == 3 && is_xmmop(&in->ops[0]) && (is_reg32(&in->ops[1]) || is_reg64(&in->ops[1]) || is_memop(&in->ops[1])) && is_imm8(&in->ops[2])) {
                uint8_t opcode = 0x20;
                if (in->mnem == MNEM_PINSRD) opcode = 0x22;
                else if (in->mnem == MNEM_PINSRQ) opcode = 0x22;
                uint8_t prefix = 0x66;
                uint8_t prefixes[1] = {prefix};
                uint8_t opc_bytes[] = {0x0F, 0x3A, opcode};
                bool use_rex_w = (in->mnem == MNEM_PINSRQ);
                rasm_status st = emit_op_modrm_legacy(prefixes, 1, opc_bytes, 3, &in->ops[1], reg_code(in->ops[0].v.reg), use_rex_w, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                emit_u8(&unit->text, (uint8_t)in->ops[2].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_PEXTRB:
        case MNEM_PEXTRD:
        case MNEM_PEXTRQ: {
            if (in->op_count == 3 && (is_reg32(&in->ops[0]) || is_reg64(&in->ops[0]) || is_memop(&in->ops[0])) && is_xmmop(&in->ops[1]) && is_imm8(&in->ops[2])) {
                uint8_t opcode = 0x14;
                if (in->mnem == MNEM_PEXTRD) opcode = 0x16;
                else if (in->mnem == MNEM_PEXTRQ) opcode = 0x16;
                uint8_t prefix = 0x66;
                uint8_t prefixes[1] = {prefix};
                uint8_t opc_bytes[] = {0x0F, 0x3A, opcode};
                bool use_rex_w = (in->mnem == MNEM_PEXTRQ);
                rasm_status st = emit_op_modrm_legacy(prefixes, 1, opc_bytes, 3, &in->ops[0], reg_code(in->ops[1].v.reg), use_rex_w, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                emit_u8(&unit->text, (uint8_t)in->ops[2].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // SSE4.2 Instructions
        case MNEM_PCMPESTRI:
        case MNEM_PCMPESTRM:
        case MNEM_PCMPISTRI:
        case MNEM_PCMPISTRM: {
            if (in->op_count == 3 && is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1])) && is_imm8(&in->ops[2])) {
                uint8_t opcode = 0x60;
                if (in->mnem == MNEM_PCMPESTRM) opcode = 0x60;
                else if (in->mnem == MNEM_PCMPESTRI) opcode = 0x61;
                else if (in->mnem == MNEM_PCMPISTRM) opcode = 0x62;
                else if (in->mnem == MNEM_PCMPISTRI) opcode = 0x63;
                uint8_t prefix = 0x66;
                uint8_t prefixes[1] = {prefix};
                uint8_t opc_bytes[] = {0x0F, 0x3A, opcode};
                rasm_status st = emit_op_modrm_legacy(prefixes, 1, opc_bytes, 3, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                emit_u8(&unit->text, (uint8_t)in->ops[2].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_CRC32: {
            if (in->op_count == 2 && (is_reg32(&in->ops[0]) || is_reg64(&in->ops[0])) && (is_reg8(&in->ops[1]) || is_reg32(&in->ops[1]) || is_reg64(&in->ops[1]) || is_memop(&in->ops[1]))) {
                uint8_t prefix = 0xF2;
                uint8_t prefixes[1] = {prefix};
                bool use_rex_w = is_reg64(&in->ops[0]);
                // Use F0 for 8-bit operand, F1 for 16/32/64-bit
                uint8_t opcode = is_reg8(&in->ops[1]) ? 0xF0 : 0xF1;
                uint8_t opc_bytes[] = {0x0F, 0x38, opcode};
                return emit_op_modrm_legacy(prefixes, 1, opc_bytes, 3, &in->ops[1], reg_code(in->ops[0].v.reg), use_rex_w, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // AES-NI Instructions
        case MNEM_AESENC:
        case MNEM_AESENCLAST:
        case MNEM_AESDEC:
        case MNEM_AESDECLAST: {
            if (in->op_count == 2 && is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1]))) {
                uint8_t opcode = 0xDC;
                if (in->mnem == MNEM_AESENCLAST) opcode = 0xDD;
                else if (in->mnem == MNEM_AESDEC) opcode = 0xDE;
                else if (in->mnem == MNEM_AESDECLAST) opcode = 0xDF;
                uint8_t prefix = 0x66;
                uint8_t prefixes[1] = {prefix};
                uint8_t opc_bytes[] = {0x0F, 0x38, opcode};
                return emit_op_modrm_legacy(prefixes, 1, opc_bytes, 3, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_AESIMC: {
            if (in->op_count == 2 && is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1]))) {
                uint8_t prefix = 0x66;
                uint8_t prefixes[1] = {prefix};
                uint8_t opc_bytes[] = {0x0F, 0x38, 0xDB};
                return emit_op_modrm_legacy(prefixes, 1, opc_bytes, 3, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_AESKEYGENASSIST: {
            if (in->op_count == 3 && is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1])) && is_imm8(&in->ops[2])) {
                uint8_t prefix = 0x66;
                uint8_t prefixes[1] = {prefix};
                uint8_t opc_bytes[] = {0x0F, 0x3A, 0xDF};
                rasm_status st = emit_op_modrm_legacy(prefixes, 1, opc_bytes, 3, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                emit_u8(&unit->text, (uint8_t)in->ops[2].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // AVX-512 opmask operations
        // KMOV - Move between opmask registers or GPR/memory
        case MNEM_KMOVW: {
            if (in->op_count == 2) {
                // kmovw k, k/m16 - VEX.L0.0F.W0 90 /r
                if (is_opmask(in->ops[0].v.reg) && (is_opmask(in->ops[1].v.reg) || is_memop(&in->ops[1]))) {
                    uint8_t opc[] = {0x90};
                    return emit_vex_modrm(opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), REG_INVALID, false, false, 0x00, 0x01, unit, RELOC_PC32);
                }
                // kmovw m16, k - VEX.L0.0F.W0 91 /r
                if (is_memop(&in->ops[0]) && is_opmask(in->ops[1].v.reg)) {
                    uint8_t opc[] = {0x91};
                    return emit_vex_modrm(opc, 1, &in->ops[0], reg_code(in->ops[1].v.reg), REG_INVALID, false, false, 0x00, 0x01, unit, RELOC_PC32);
                }
                // kmovw k, r32 - VEX.L0.0F.W0 92 /r
                if (is_opmask(in->ops[0].v.reg) && is_gpr32(in->ops[1].v.reg)) {
                    operand regop = {.kind = OP_REG, .v = {.reg = in->ops[1].v.reg}};
                    uint8_t opc[] = {0x92};
                    return emit_vex_modrm(opc, 1, &regop, reg_code(in->ops[0].v.reg), REG_INVALID, false, false, 0x00, 0x01, unit, RELOC_PC32);
                }
                // kmovw r32, k - VEX.L0.0F.W0 93 /r
                if (is_gpr32(in->ops[0].v.reg) && is_opmask(in->ops[1].v.reg)) {
                    operand regop = {.kind = OP_REG, .v = {.reg = in->ops[0].v.reg}};
                    uint8_t opc[] = {0x93};
                    return emit_vex_modrm(opc, 1, &regop, reg_code(in->ops[1].v.reg), REG_INVALID, false, false, 0x00, 0x01, unit, RELOC_PC32);
                }
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_KMOVB: {
            if (in->op_count == 2) {
                // kmovb k, k/m8 - VEX.L0.66.0F.W0 90 /r
                if (is_opmask(in->ops[0].v.reg) && (is_opmask(in->ops[1].v.reg) || is_memop(&in->ops[1]))) {
                    uint8_t opc[] = {0x90};
                    return emit_vex_modrm(opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), REG_INVALID, false, false, 0x01, 0x01, unit, RELOC_PC32);
                }
                // kmovb m8, k - VEX.L0.66.0F.W0 91 /r
                if (is_memop(&in->ops[0]) && is_opmask(in->ops[1].v.reg)) {
                    uint8_t opc[] = {0x91};
                    return emit_vex_modrm(opc, 1, &in->ops[0], reg_code(in->ops[1].v.reg), REG_INVALID, false, false, 0x01, 0x01, unit, RELOC_PC32);
                }
                // kmovb k, r32 - VEX.L0.66.0F.W0 92 /r
                if (is_opmask(in->ops[0].v.reg) && is_gpr32(in->ops[1].v.reg)) {
                    operand regop = {.kind = OP_REG, .v = {.reg = in->ops[1].v.reg}};
                    uint8_t opc[] = {0x92};
                    return emit_vex_modrm(opc, 1, &regop, reg_code(in->ops[0].v.reg), REG_INVALID, false, false, 0x01, 0x01, unit, RELOC_PC32);
                }
                // kmovb r32, k - VEX.L0.66.0F.W0 93 /r
                if (is_gpr32(in->ops[0].v.reg) && is_opmask(in->ops[1].v.reg)) {
                    operand regop = {.kind = OP_REG, .v = {.reg = in->ops[0].v.reg}};
                    uint8_t opc[] = {0x93};
                    return emit_vex_modrm(opc, 1, &regop, reg_code(in->ops[1].v.reg), REG_INVALID, false, false, 0x01, 0x01, unit, RELOC_PC32);
                }
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_KMOVQ: {
            if (in->op_count == 2) {
                // kmovq k, k/m64 - VEX.L0.0F.W1 90 /r
                if (is_opmask(in->ops[0].v.reg) && (is_opmask(in->ops[1].v.reg) || is_memop(&in->ops[1]))) {
                    uint8_t opc[] = {0x90};
                    return emit_vex_modrm(opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), REG_INVALID, true, false, 0x00, 0x01, unit, RELOC_PC32);
                }
                // kmovq m64, k - VEX.L0.0F.W1 91 /r
                if (is_memop(&in->ops[0]) && is_opmask(in->ops[1].v.reg)) {
                    uint8_t opc[] = {0x91};
                    return emit_vex_modrm(opc, 1, &in->ops[0], reg_code(in->ops[1].v.reg), REG_INVALID, true, false, 0x00, 0x01, unit, RELOC_PC32);
                }
                // kmovq k, r64 - VEX.L0.0F.W1 92 /r
                if (is_opmask(in->ops[0].v.reg) && is_gpr64(in->ops[1].v.reg)) {
                    operand regop = {.kind = OP_REG, .v = {.reg = in->ops[1].v.reg}};
                    uint8_t opc[] = {0x92};
                    return emit_vex_modrm(opc, 1, &regop, reg_code(in->ops[0].v.reg), REG_INVALID, true, false, 0x00, 0x01, unit, RELOC_PC32);
                }
                // kmovq r64, k - VEX.L0.0F.W1 93 /r
                if (is_gpr64(in->ops[0].v.reg) && is_opmask(in->ops[1].v.reg)) {
                    operand regop = {.kind = OP_REG, .v = {.reg = in->ops[0].v.reg}};
                    uint8_t opc[] = {0x93};
                    return emit_vex_modrm(opc, 1, &regop, reg_code(in->ops[1].v.reg), REG_INVALID, true, false, 0x00, 0x01, unit, RELOC_PC32);
                }
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_KMOVD: {
            if (in->op_count == 2) {
                // kmovd k, k/m32 - VEX.L0.66.0F.W1 90 /r
                if (is_opmask(in->ops[0].v.reg) && (is_opmask(in->ops[1].v.reg) || is_memop(&in->ops[1]))) {
                    uint8_t opc[] = {0x90};
                    return emit_vex_modrm(opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), REG_INVALID, true, false, 0x01, 0x01, unit, RELOC_PC32);
                }
                // kmovd m32, k - VEX.L0.66.0F.W1 91 /r
                if (is_memop(&in->ops[0]) && is_opmask(in->ops[1].v.reg)) {
                    uint8_t opc[] = {0x91};
                    return emit_vex_modrm(opc, 1, &in->ops[0], reg_code(in->ops[1].v.reg), REG_INVALID, true, false, 0x01, 0x01, unit, RELOC_PC32);
                }
                // kmovd k, r32 - VEX.L0.F2.0F.W0 92 /r
                if (is_opmask(in->ops[0].v.reg) && is_gpr32(in->ops[1].v.reg)) {
                    operand regop = {.kind = OP_REG, .v = {.reg = in->ops[1].v.reg}};
                    uint8_t opc[] = {0x92};
                    return emit_vex_modrm(opc, 1, &regop, reg_code(in->ops[0].v.reg), REG_INVALID, false, false, 0x03, 0x01, unit, RELOC_PC32);
                }
                // kmovd r32, k - VEX.L0.F2.0F.W0 93 /r
                if (is_gpr32(in->ops[0].v.reg) && is_opmask(in->ops[1].v.reg)) {
                    operand regop = {.kind = OP_REG, .v = {.reg = in->ops[0].v.reg}};
                    uint8_t opc[] = {0x93};
                    return emit_vex_modrm(opc, 1, &regop, reg_code(in->ops[1].v.reg), REG_INVALID, false, false, 0x03, 0x01, unit, RELOC_PC32);
                }
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // KAND - Bitwise AND of opmask registers
        case MNEM_KANDW:
        case MNEM_KANDB:
        case MNEM_KANDQ:
        case MNEM_KANDD: {
            if (in->op_count == 3 && is_opmask(in->ops[0].v.reg) && is_opmask(in->ops[1].v.reg) && is_opmask(in->ops[2].v.reg)) {
                uint8_t pp = 0x00, w = 0;
                if (in->mnem == MNEM_KANDB) { pp = 0x01; w = 0; }
                else if (in->mnem == MNEM_KANDW) { pp = 0x00; w = 0; }
                else if (in->mnem == MNEM_KANDD) { pp = 0x01; w = 1; }
                else if (in->mnem == MNEM_KANDQ) { pp = 0x00; w = 1; }
                operand regop = {.kind = OP_REG, .v = {.reg = in->ops[2].v.reg}};
                uint8_t opc[] = {0x41};
                return emit_vex_modrm(opc, 1, &regop, reg_code(in->ops[0].v.reg), in->ops[1].v.reg, w, false, pp, 0x01, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // KOR - Bitwise OR of opmask registers
        case MNEM_KORW:
        case MNEM_KORB:
        case MNEM_KORQ:
        case MNEM_KORD: {
            if (in->op_count == 3 && is_opmask(in->ops[0].v.reg) && is_opmask(in->ops[1].v.reg) && is_opmask(in->ops[2].v.reg)) {
                uint8_t pp = 0x00, w = 0;
                if (in->mnem == MNEM_KORB) { pp = 0x01; w = 0; }
                else if (in->mnem == MNEM_KORW) { pp = 0x00; w = 0; }
                else if (in->mnem == MNEM_KORD) { pp = 0x01; w = 1; }
                else if (in->mnem == MNEM_KORQ) { pp = 0x00; w = 1; }
                operand regop = {.kind = OP_REG, .v = {.reg = in->ops[2].v.reg}};
                uint8_t opc[] = {0x45};
                return emit_vex_modrm(opc, 1, &regop, reg_code(in->ops[0].v.reg), in->ops[1].v.reg, w, false, pp, 0x01, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // KXOR - Bitwise XOR of opmask registers
        case MNEM_KXORW:
        case MNEM_KXORB:
        case MNEM_KXORQ:
        case MNEM_KXORD: {
            if (in->op_count == 3 && is_opmask(in->ops[0].v.reg) && is_opmask(in->ops[1].v.reg) && is_opmask(in->ops[2].v.reg)) {
                uint8_t pp = 0x00, w = 0;
                if (in->mnem == MNEM_KXORB) { pp = 0x01; w = 0; }
                else if (in->mnem == MNEM_KXORW) { pp = 0x00; w = 0; }
                else if (in->mnem == MNEM_KXORD) { pp = 0x01; w = 1; }
                else if (in->mnem == MNEM_KXORQ) { pp = 0x00; w = 0; }
                operand regop = {.kind = OP_REG, .v = {.reg = in->ops[2].v.reg}};
                uint8_t opc[] = {0x47};
                return emit_vex_modrm(opc, 1, &regop, reg_code(in->ops[0].v.reg), in->ops[1].v.reg, w, false, pp, 0x01, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // KNOT - Bitwise NOT of opmask register
        case MNEM_KNOTW:
        case MNEM_KNOTB:
        case MNEM_KNOTQ:
        case MNEM_KNOTD: {
            if (in->op_count == 2 && is_opmask(in->ops[0].v.reg) && is_opmask(in->ops[1].v.reg)) {
                uint8_t pp = 0x00, w = 0;
                if (in->mnem == MNEM_KNOTB) { pp = 0x01; w = 0; }
                else if (in->mnem == MNEM_KNOTW) { pp = 0x00; w = 0; }
                else if (in->mnem == MNEM_KNOTD) { pp = 0x01; w = 1; }
                else if (in->mnem == MNEM_KNOTQ) { pp = 0x00; w = 1; }
                operand regop = {.kind = OP_REG, .v = {.reg = in->ops[1].v.reg}};
                uint8_t opc[] = {0x44};
                return emit_vex_modrm(opc, 1, &regop, reg_code(in->ops[0].v.reg), REG_INVALID, w, false, pp, 0x01, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // AVX-512 ZMM Arithmetic Operations (512-bit)
        case MNEM_VADDPS_512:
        case MNEM_VADDPD_512:
        case MNEM_VSUBPS_512:
        case MNEM_VSUBPD_512:
        case MNEM_VMULPS_512:
        case MNEM_VMULPD_512:
        case MNEM_VDIVPS_512:
        case MNEM_VDIVPD_512: {
            if (in->op_count == 3 && is_zmm(in->ops[0].v.reg) && is_zmm(in->ops[1].v.reg) && (is_zmm(in->ops[2].v.reg) || is_memop(&in->ops[2]))) {
                uint8_t opcode = 0x58;
                bool w = false;
                uint8_t pp = 0x00;
                switch (in->mnem) {
                    case MNEM_VADDPS_512: opcode = 0x58; pp = 0x00; w = false; break;
                    case MNEM_VADDPD_512: opcode = 0x58; pp = 0x01; w = true; break;
                    case MNEM_VSUBPS_512: opcode = 0x5C; pp = 0x00; w = false; break;
                    case MNEM_VSUBPD_512: opcode = 0x5C; pp = 0x01; w = true; break;
                    case MNEM_VMULPS_512: opcode = 0x59; pp = 0x00; w = false; break;
                    case MNEM_VMULPD_512: opcode = 0x59; pp = 0x01; w = true; break;
                    case MNEM_VDIVPS_512: opcode = 0x5E; pp = 0x00; w = false; break;
                    case MNEM_VDIVPD_512: opcode = 0x5E; pp = 0x01; w = true; break;
                    default: return RASM_ERR_INVALID_ARGUMENT;
                }
                uint8_t opc[] = {opcode};
                return emit_evex_modrm(opc, 1, &in->ops[2], reg_code(in->ops[0].v.reg), in->ops[1].v.reg, REG_INVALID, w, 0x02, pp, 0x01, false, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // AVX-512 ZMM Data Movement (512-bit)
        case MNEM_VMOVAPS_512:
        case MNEM_VMOVAPD_512:
        case MNEM_VMOVUPS_512:
        case MNEM_VMOVUPD_512: {
            if (in->op_count != 2) return RASM_ERR_INVALID_ARGUMENT;
            bool w = (in->mnem == MNEM_VMOVAPD_512 || in->mnem == MNEM_VMOVUPD_512);
            uint8_t opcode_load = (in->mnem == MNEM_VMOVAPS_512 || in->mnem == MNEM_VMOVAPD_512) ? 0x28 : 0x10;
            uint8_t opcode_store = (in->mnem == MNEM_VMOVAPS_512 || in->mnem == MNEM_VMOVAPD_512) ? 0x29 : 0x11;
            uint8_t pp = (in->mnem == MNEM_VMOVAPD_512 || in->mnem == MNEM_VMOVUPD_512) ? 0x01 : 0x00;
            // zmm <- zmm/m512
            if (is_zmm(in->ops[0].v.reg) && (is_zmm(in->ops[1].v.reg) || is_memop(&in->ops[1]))) {
                uint8_t opc[] = {opcode_load};
                return emit_evex_modrm(opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), REG_INVALID, REG_INVALID, w, 0x02, pp, 0x01, false, false, unit, RELOC_PC32);
            }
            // m512 <- zmm
            if (is_memop(&in->ops[0]) && is_zmm(in->ops[1].v.reg)) {
                uint8_t opc[] = {opcode_store};
                return emit_evex_modrm(opc, 1, &in->ops[0], reg_code(in->ops[1].v.reg), REG_INVALID, REG_INVALID, w, 0x02, pp, 0x01, false, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // AVX-512 Integer Data Movement
        case MNEM_VMOVDQA32:
        case MNEM_VMOVDQA64:
        case MNEM_VMOVDQU32:
        case MNEM_VMOVDQU64: {
            if (in->op_count != 2) return RASM_ERR_INVALID_ARGUMENT;
            bool w = (in->mnem == MNEM_VMOVDQA64 || in->mnem == MNEM_VMOVDQU64);
            uint8_t pp = (in->mnem == MNEM_VMOVDQA32 || in->mnem == MNEM_VMOVDQA64) ? 0x01 : 0x02;
            uint8_t opcode_load = 0x6F;
            uint8_t opcode_store = 0x7F;
            // zmm <- zmm/m512
            if (is_zmm(in->ops[0].v.reg) && (is_zmm(in->ops[1].v.reg) || is_memop(&in->ops[1]))) {
                uint8_t opc[] = {opcode_load};
                return emit_evex_modrm(opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), REG_INVALID, REG_INVALID, w, 0x02, pp, 0x01, false, false, unit, RELOC_PC32);
            }
            // m512 <- zmm
            if (is_memop(&in->ops[0]) && is_zmm(in->ops[1].v.reg)) {
                uint8_t opc[] = {opcode_store};
                return emit_evex_modrm(opc, 1, &in->ops[0], reg_code(in->ops[1].v.reg), REG_INVALID, REG_INVALID, w, 0x02, pp, 0x01, false, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // AVX-512 Broadcast Operations
        case MNEM_VBROADCASTSS: {
            // vbroadcastss zmm, xmm/m32 - EVEX.512.66.0F38.W0 18 /r
            if (in->op_count == 2 && is_zmm(in->ops[0].v.reg) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1]))) {
                uint8_t opc[] = {0x18};
                return emit_evex_modrm(opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), REG_INVALID, REG_INVALID, false, 0x02, 0x01, 0x02, false, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_VBROADCASTSD: {
            // vbroadcastsd zmm, xmm/m64 - EVEX.512.66.0F38.W1 19 /r
            if (in->op_count == 2 && is_zmm(in->ops[0].v.reg) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1]))) {
                uint8_t opc[] = {0x19};
                return emit_evex_modrm(opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), REG_INVALID, REG_INVALID, true, 0x02, 0x01, 0x02, false, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_VBROADCASTI32X4: {
            // vbroadcasti32x4 zmm, m128 - EVEX.512.66.0F38.W0 5A /r
            if (in->op_count == 2 && is_zmm(in->ops[0].v.reg) && is_memop(&in->ops[1])) {
                uint8_t opc[] = {0x5A};
                return emit_evex_modrm(opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), REG_INVALID, REG_INVALID, false, 0x02, 0x01, 0x02, false, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_VBROADCASTI64X4: {
            // vbroadcasti64x4 zmm, m256 - EVEX.512.66.0F38.W1 5B /r
            if (in->op_count == 2 && is_zmm(in->ops[0].v.reg) && is_memop(&in->ops[1])) {
                uint8_t opc[] = {0x5B};
                return emit_evex_modrm(opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), REG_INVALID, REG_INVALID, true, 0x02, 0x01, 0x02, false, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_VPBROADCASTD: {
            // vpbroadcastd zmm, xmm/m32 - EVEX.512.66.0F38.W0 58 /r
            if (in->op_count == 2 && is_zmm(in->ops[0].v.reg) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1]))) {
                uint8_t opc[] = {0x58};
                return emit_evex_modrm(opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), REG_INVALID, REG_INVALID, false, 0x02, 0x01, 0x02, false, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_VPBROADCASTQ: {
            // vpbroadcastq zmm, xmm/m64 - EVEX.512.66.0F38.W1 59 /r
            if (in->op_count == 2 && is_zmm(in->ops[0].v.reg) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1]))) {
                uint8_t opc[] = {0x59};
                return emit_evex_modrm(opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), REG_INVALID, REG_INVALID, true, 0x02, 0x01, 0x02, false, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_CMPPS:
        case MNEM_CMPPD: {
            if (in->op_count == 3 && is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1])) && is_imm8(&in->ops[2])) {
                uint8_t prefix = (in->mnem == MNEM_CMPPD) ? 0x66 : 0x00;
                uint8_t prefixes[1];
                size_t pre_len = 0;
                if (prefix != 0x00) { prefixes[0] = prefix; pre_len = 1; }
                uint8_t opc_bytes[] = {0x0F, 0xC2};
                rasm_status st = emit_op_modrm_legacy(prefixes, pre_len, opc_bytes, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                emit_u8(&unit->text, (uint8_t)in->ops[2].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_MOVSS:
        case MNEM_MOVSD: {
            if (in->op_count != 2) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t prefix = (in->mnem == MNEM_MOVSS) ? 0xF3 : 0xF2;
            uint8_t opc_load = 0x10;
            uint8_t opc_store = 0x11;
            uint8_t prefixes[1] = {prefix};
            uint8_t opc_load_bytes[] = {0x0F, opc_load};
            uint8_t opc_store_bytes[] = {0x0F, opc_store};
            if (is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1]))) {
                return emit_op_modrm_legacy(prefixes, 1, opc_load_bytes, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            if (is_memop(&in->ops[0]) && is_xmmop(&in->ops[1])) {
                return emit_op_modrm_legacy(prefixes, 1, opc_store_bytes, 2, &in->ops[0], reg_code(in->ops[1].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_ADDSS:
        case MNEM_ADDSD:
        case MNEM_SUBSS:
        case MNEM_SUBSD:
        case MNEM_MULSS:
        case MNEM_MULSD:
        case MNEM_DIVSS:
        case MNEM_DIVSD: {
            if (in->op_count != 2 || !is_xmmop(&in->ops[0]) || !(is_xmmop(&in->ops[1]) || is_memop(&in->ops[1]))) {
                return RASM_ERR_INVALID_ARGUMENT;
            }
            uint8_t prefix = 0xF3; // default ss
            uint8_t opcode = 0x58;
            switch (in->mnem) {
                case MNEM_ADDSS: prefix = 0xF3; opcode = 0x58; break;
                case MNEM_ADDSD: prefix = 0xF2; opcode = 0x58; break;
                case MNEM_SUBSS: prefix = 0xF3; opcode = 0x5C; break;
                case MNEM_SUBSD: prefix = 0xF2; opcode = 0x5C; break;
                case MNEM_MULSS: prefix = 0xF3; opcode = 0x59; break;
                case MNEM_MULSD: prefix = 0xF2; opcode = 0x59; break;
                case MNEM_DIVSS: prefix = 0xF3; opcode = 0x5E; break;
                case MNEM_DIVSD: prefix = 0xF2; opcode = 0x5E; break;
                default: return RASM_ERR_INVALID_ARGUMENT;
            }
            uint8_t prefixes[1] = {prefix};
            uint8_t opc_bytes[] = {0x0F, opcode};
            return emit_op_modrm_legacy(prefixes, 1, opc_bytes, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
        }
        case MNEM_SQRTSS:
        case MNEM_SQRTSD: {
            if (in->op_count != 2 || !is_xmmop(&in->ops[0]) || !(is_xmmop(&in->ops[1]) || is_memop(&in->ops[1]))) {
                return RASM_ERR_INVALID_ARGUMENT;
            }
            uint8_t prefix = (in->mnem == MNEM_SQRTSS) ? 0xF3 : 0xF2;
            uint8_t prefixes[1] = {prefix};
            uint8_t opc_bytes[] = {0x0F, 0x51};
            return emit_op_modrm_legacy(prefixes, 1, opc_bytes, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
        }
        case MNEM_COMISS:
        case MNEM_COMISD:
        case MNEM_UCOMISS:
        case MNEM_UCOMISD: {
            if (in->op_count != 2 || !is_xmmop(&in->ops[0]) || !(is_xmmop(&in->ops[1]) || is_memop(&in->ops[1]))) {
                return RASM_ERR_INVALID_ARGUMENT;
            }
            uint8_t prefix = 0x00;
            uint8_t opcode = 0x2F;
            if (in->mnem == MNEM_COMISD) { prefix = 0x66; opcode = 0x2F; }
            else if (in->mnem == MNEM_UCOMISS) { prefix = 0x00; opcode = 0x2E; }
            else if (in->mnem == MNEM_UCOMISD) { prefix = 0x66; opcode = 0x2E; }
            uint8_t prefixes[1];
            size_t pre_len = 0;
            if (prefix != 0x00) { prefixes[0] = prefix; pre_len = 1; }
            uint8_t opc_bytes[] = {0x0F, opcode};
            return emit_op_modrm_legacy(prefixes, pre_len, opc_bytes, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
        }
        case MNEM_CVTSS2SD:
        case MNEM_CVTSD2SS: {
            if (in->op_count != 2 || !is_xmmop(&in->ops[0]) || !(is_xmmop(&in->ops[1]) || is_memop(&in->ops[1]))) {
                return RASM_ERR_INVALID_ARGUMENT;
            }
            uint8_t prefix = (in->mnem == MNEM_CVTSS2SD) ? 0xF3 : 0xF2;
            uint8_t prefixes[1] = {prefix};
            uint8_t opc_bytes[] = {0x0F, 0x5A};
            return emit_op_modrm_legacy(prefixes, 1, opc_bytes, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
        }
        case MNEM_CVTSI2SS:
        case MNEM_CVTSI2SD: {
            if (in->op_count != 2 || !is_xmmop(&in->ops[0]) || !(is_reg64(&in->ops[1]) || is_memop(&in->ops[1]))) {
                return RASM_ERR_INVALID_ARGUMENT;
            }
            uint8_t prefix = (in->mnem == MNEM_CVTSI2SS) ? 0xF3 : 0xF2;
            uint8_t prefixes[1] = {prefix};
            uint8_t opc_bytes[] = {0x0F, 0x2A};
            return emit_op_modrm_legacy(prefixes, 1, opc_bytes, 2, &in->ops[1], reg_code(in->ops[0].v.reg), true, unit, RELOC_PC32);
        }
        case MNEM_CVTSS2SI:
        case MNEM_CVTSD2SI:
        case MNEM_CVTTSS2SI:
        case MNEM_CVTTSD2SI: {
            if (in->op_count != 2 || !is_reg64(&in->ops[0]) || !(is_xmmop(&in->ops[1]) || is_memop(&in->ops[1]))) {
                return RASM_ERR_INVALID_ARGUMENT;
            }
            uint8_t prefix = 0xF3;
            uint8_t opcode = 0x2D;
            if (in->mnem == MNEM_CVTSD2SI) { prefix = 0xF2; opcode = 0x2D; }
            else if (in->mnem == MNEM_CVTTSS2SI) { prefix = 0xF3; opcode = 0x2C; }
            else if (in->mnem == MNEM_CVTTSD2SI) { prefix = 0xF2; opcode = 0x2C; }
            uint8_t prefixes[1] = {prefix};
            uint8_t opc_bytes[] = {0x0F, opcode};
            return emit_op_modrm_legacy(prefixes, 1, opc_bytes, 2, &in->ops[1], reg_code(in->ops[0].v.reg), true, unit, RELOC_PC32);
        }
        case MNEM_VMOVAPS:
        case MNEM_VMOVUPS:
        case MNEM_VMOVDQA:
        case MNEM_VMOVDQU: {
            if (in->op_count != 2) return RASM_ERR_INVALID_ARGUMENT;
            if (!(is_vec_op(&in->ops[0]) || is_memop(&in->ops[0]))) return RASM_ERR_INVALID_ARGUMENT;
            if (!(is_vec_op(&in->ops[1]) || is_memop(&in->ops[1]))) return RASM_ERR_INVALID_ARGUMENT;
            bool l = is_ymmop(&in->ops[0]) || is_ymmop(&in->ops[1]);
            uint8_t opcode_load = 0x28;
            uint8_t opcode_store = 0x29;
            uint8_t pp = 0x00;
            if (in->mnem == MNEM_VMOVUPS) { opcode_load = 0x10; opcode_store = 0x11; }
            if (in->mnem == MNEM_VMOVDQA) { opcode_load = 0x6F; opcode_store = 0x7F; pp = 0x01; }
            if (in->mnem == MNEM_VMOVDQU) { opcode_load = 0x6F; opcode_store = 0x7F; pp = 0x02; }
            uint8_t opc_load[] = {opcode_load};
            uint8_t opc_store[] = {opcode_store};
            if (is_vec_op(&in->ops[0]) && (is_vec_op(&in->ops[1]) || is_memop(&in->ops[1]))) {
                if (is_vec_op(&in->ops[1]) && ((is_xmmop(&in->ops[0]) != is_xmmop(&in->ops[1])) || (is_ymmop(&in->ops[0]) != is_ymmop(&in->ops[1])))) return RASM_ERR_INVALID_ARGUMENT;
                if (is_vec_op(&in->ops[0])) l = is_ymmop(&in->ops[0]);
                return emit_vex_modrm(opc_load, 1, &in->ops[1], reg_code(in->ops[0].v.reg), REG_INVALID, false, l, pp, 0x01, unit, RELOC_PC32);
            }
            if (is_memop(&in->ops[0]) && is_vec_op(&in->ops[1])) {
                l = is_ymmop(&in->ops[1]);
                return emit_vex_modrm(opc_store, 1, &in->ops[0], reg_code(in->ops[1].v.reg), REG_INVALID, false, l, pp, 0x01, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_VADDPS:
        case MNEM_VADDPD:
        case MNEM_VSUBPS:
        case MNEM_VSUBPD:
        case MNEM_VMULPS:
        case MNEM_VMULPD:
        case MNEM_VDIVPS:
        case MNEM_VDIVPD:
        case MNEM_VXORPS:
        case MNEM_VXORPD: {
            if (in->op_count == 3 && is_vec_op(&in->ops[0]) && is_vec_op(&in->ops[1]) && (is_vec_op(&in->ops[2]) || is_memop(&in->ops[2]))) {
                if ((is_xmmop(&in->ops[0]) != is_xmmop(&in->ops[1])) || (is_ymmop(&in->ops[0]) != is_ymmop(&in->ops[1]))) return RASM_ERR_INVALID_ARGUMENT;
                if (is_vec_op(&in->ops[2])) {
                    if ((is_xmmop(&in->ops[0]) != is_xmmop(&in->ops[2])) || (is_ymmop(&in->ops[0]) != is_ymmop(&in->ops[2]))) return RASM_ERR_INVALID_ARGUMENT;
                }
                bool l = is_ymmop(&in->ops[0]);
                uint8_t opcode = 0x58;
                uint8_t pp = 0x00;
                switch (in->mnem) {
                    case MNEM_VADDPD: opcode = 0x58; pp = 0x01; break;
                    case MNEM_VSUBPS: opcode = 0x5C; pp = 0x00; break;
                    case MNEM_VSUBPD: opcode = 0x5C; pp = 0x01; break;
                    case MNEM_VMULPS: opcode = 0x59; pp = 0x00; break;
                    case MNEM_VMULPD: opcode = 0x59; pp = 0x01; break;
                    case MNEM_VDIVPS: opcode = 0x5E; pp = 0x00; break;
                    case MNEM_VDIVPD: opcode = 0x5E; pp = 0x01; break;
                    case MNEM_VXORPS: opcode = 0x57; pp = 0x00; break;
                    case MNEM_VXORPD: opcode = 0x57; pp = 0x01; break;
                    default: break;
                }
                uint8_t opc[] = {opcode};
                return emit_vex_modrm(opc, 1, &in->ops[2], reg_code(in->ops[0].v.reg), in->ops[1].v.reg, false, l, pp, 0x01, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_VSQRTPS:
        case MNEM_VSQRTPD: {
            if (in->op_count == 2 && is_vec_op(&in->ops[0]) && (is_vec_op(&in->ops[1]) || is_memop(&in->ops[1]))) {
                if (is_vec_op(&in->ops[1]) && ((is_xmmop(&in->ops[0]) != is_xmmop(&in->ops[1])) || (is_ymmop(&in->ops[0]) != is_ymmop(&in->ops[1])))) return RASM_ERR_INVALID_ARGUMENT;
                bool l = is_ymmop(&in->ops[0]);
                uint8_t pp = (in->mnem == MNEM_VSQRTPD) ? 0x01 : 0x00;
                uint8_t opc[] = {0x51};
                return emit_vex_modrm(opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), REG_INVALID, false, l, pp, 0x01, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_VCMPPS:
        case MNEM_VCMPPD: {
            if (in->op_count == 4 && is_vec_op(&in->ops[0]) && is_vec_op(&in->ops[1]) && (is_vec_op(&in->ops[2]) || is_memop(&in->ops[2])) && is_imm8(&in->ops[3])) {
                if ((is_xmmop(&in->ops[0]) != is_xmmop(&in->ops[1])) || (is_ymmop(&in->ops[0]) != is_ymmop(&in->ops[1]))) return RASM_ERR_INVALID_ARGUMENT;
                if (is_vec_op(&in->ops[2])) {
                    if ((is_xmmop(&in->ops[0]) != is_xmmop(&in->ops[2])) || (is_ymmop(&in->ops[0]) != is_ymmop(&in->ops[2]))) return RASM_ERR_INVALID_ARGUMENT;
                }
                bool l = is_ymmop(&in->ops[0]);
                uint8_t pp = (in->mnem == MNEM_VCMPPD) ? 0x01 : 0x00;
                uint8_t opc[] = {0xC2};
                rasm_status st = emit_vex_modrm(opc, 1, &in->ops[2], reg_code(in->ops[0].v.reg), in->ops[1].v.reg, false, l, pp, 0x01, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                emit_u8(&unit->text, (uint8_t)in->ops[3].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_VPTEST: {
            if (in->op_count == 2 && is_vec_op(&in->ops[0]) && (is_vec_op(&in->ops[1]) || is_memop(&in->ops[1]))) {
                if (is_vec_op(&in->ops[1]) && ((is_xmmop(&in->ops[0]) != is_xmmop(&in->ops[1])) || (is_ymmop(&in->ops[0]) != is_ymmop(&in->ops[1])))) return RASM_ERR_INVALID_ARGUMENT;
                bool l = is_ymmop(&in->ops[0]);
                uint8_t opc[] = {0x17};
                return emit_vex_modrm(opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), REG_INVALID, false, l, 0x01, 0x02, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_VROUNDPS:
        case MNEM_VROUNDPD:
        case MNEM_VPERMILPS:
        case MNEM_VPERMILPD: {
            if (in->op_count == 3 && is_vec_op(&in->ops[0]) && (is_vec_op(&in->ops[1]) || is_memop(&in->ops[1])) && is_imm8(&in->ops[2])) {
                if (is_vec_op(&in->ops[1]) && ((is_xmmop(&in->ops[0]) != is_xmmop(&in->ops[1])) || (is_ymmop(&in->ops[0]) != is_ymmop(&in->ops[1])))) return RASM_ERR_INVALID_ARGUMENT;
                bool l = is_ymmop(&in->ops[0]);
                uint8_t opcode = 0;
                switch (in->mnem) {
                    case MNEM_VROUNDPS: opcode = 0x08; break;
                    case MNEM_VROUNDPD: opcode = 0x09; break;
                    case MNEM_VPERMILPS: opcode = 0x04; break;
                    case MNEM_VPERMILPD: opcode = 0x05; break;
                    default: return RASM_ERR_INVALID_ARGUMENT;
                }
                uint8_t opc[] = {opcode};
                rasm_status st = emit_vex_modrm(opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), REG_INVALID, false, l, 0x01, 0x03, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                emit_u8(&unit->text, (uint8_t)in->ops[2].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // AVX Conversion instructions
        case MNEM_VCVTPS2PD:
        case MNEM_VCVTPD2PS:
        case MNEM_VCVTPS2DQ:
        case MNEM_VCVTPD2DQ:
        case MNEM_VCVTDQ2PS:
        case MNEM_VCVTDQ2PD: {
            if (in->op_count == 2 && is_vec_op(&in->ops[0]) && (is_vec_op(&in->ops[1]) || is_memop(&in->ops[1]))) {
                // For conversions, the L bit is determined by the destination size
                bool l = is_ymmop(&in->ops[0]);
                uint8_t opcode = 0;
                uint8_t pp = 0x00;
                switch (in->mnem) {
                    case MNEM_VCVTPS2PD: opcode = 0x5A; pp = 0x00; break; // PS->PD
                    case MNEM_VCVTPD2PS: opcode = 0x5A; pp = 0x01; break; // PD->PS
                    case MNEM_VCVTPS2DQ: opcode = 0x5B; pp = 0x01; break; // PS->DQ
                    case MNEM_VCVTPD2DQ: opcode = 0xE6; pp = 0x02; break; // PD->DQ
                    case MNEM_VCVTDQ2PS: opcode = 0x5B; pp = 0x00; break; // DQ->PS
                    case MNEM_VCVTDQ2PD: opcode = 0xE6; pp = 0x03; break; // DQ->PD
                    default: return RASM_ERR_INVALID_ARGUMENT;
                }
                uint8_t opc[] = {opcode};
                return emit_vex_modrm(opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), REG_INVALID, false, l, pp, 0x01, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // SSE3 Horizontal operations
        case MNEM_HADDPS:
        case MNEM_HADDPD:
        case MNEM_HSUBPS:
        case MNEM_HSUBPD: {
            if (in->op_count == 2 && is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1]))) {
                uint8_t prefix = 0xF2; // default for haddps/hsubps
                uint8_t opcode = 0x7C;
                switch (in->mnem) {
                    case MNEM_HADDPS: prefix = 0xF2; opcode = 0x7C; break;
                    case MNEM_HSUBPS: prefix = 0xF2; opcode = 0x7D; break;
                    case MNEM_HADDPD: prefix = 0x66; opcode = 0x7C; break;
                    case MNEM_HSUBPD: prefix = 0x66; opcode = 0x7D; break;
                    default: return RASM_ERR_INVALID_ARGUMENT;
                }
                uint8_t pfx[] = {prefix};
                uint8_t opc[] = {0x0F, opcode};
                return emit_op_modrm_legacy(pfx, 1, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // AVX Horizontal operations
        case MNEM_VHADDPS:
        case MNEM_VHADDPD:
        case MNEM_VHSUBPS:
        case MNEM_VHSUBPD: {
            if (in->op_count == 3 && is_vec_op(&in->ops[0]) && is_vec_op(&in->ops[1]) && (is_vec_op(&in->ops[2]) || is_memop(&in->ops[2]))) {
                if ((is_xmmop(&in->ops[0]) != is_xmmop(&in->ops[1])) || (is_ymmop(&in->ops[0]) != is_ymmop(&in->ops[1]))) return RASM_ERR_INVALID_ARGUMENT;
                if (is_vec_op(&in->ops[2])) {
                    if ((is_xmmop(&in->ops[0]) != is_xmmop(&in->ops[2])) || (is_ymmop(&in->ops[0]) != is_ymmop(&in->ops[2]))) return RASM_ERR_INVALID_ARGUMENT;
                }
                bool l = is_ymmop(&in->ops[0]);
                uint8_t opcode = 0x7C;
                uint8_t pp = 0x02; // F2 prefix
                switch (in->mnem) {
                    case MNEM_VHADDPS: opcode = 0x7C; pp = 0x02; break; // F2
                    case MNEM_VHSUBPS: opcode = 0x7D; pp = 0x02; break; // F2
                    case MNEM_VHADDPD: opcode = 0x7C; pp = 0x01; break; // 66
                    case MNEM_VHSUBPD: opcode = 0x7D; pp = 0x01; break; // 66
                    default: return RASM_ERR_INVALID_ARGUMENT;
                }
                uint8_t opc[] = {opcode};
                return emit_vex_modrm(opc, 1, &in->ops[2], reg_code(in->ops[0].v.reg), in->ops[1].v.reg, false, l, pp, 0x01, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // SSE4.1 blend operations
        case MNEM_BLENDPS:
        case MNEM_BLENDPD: {
            if (in->op_count == 3 && is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1])) && is_imm8(&in->ops[2])) {
                uint8_t prefix = 0x66;
                uint8_t opcode = (in->mnem == MNEM_BLENDPS) ? 0x0C : 0x0D;
                emit_u8(&unit->text, prefix);
                uint8_t map_select[] = {0x0F, 0x3A, opcode};
                rasm_status st = emit_op_modrm_legacy(NULL, 0, map_select, 3, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                emit_u8(&unit->text, (uint8_t)in->ops[2].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // AVX blend operations
        case MNEM_VBLENDPS:
        case MNEM_VBLENDPD: {
            if (in->op_count == 4 && is_vec_op(&in->ops[0]) && is_vec_op(&in->ops[1]) && (is_vec_op(&in->ops[2]) || is_memop(&in->ops[2])) && is_imm8(&in->ops[3])) {
                if ((is_xmmop(&in->ops[0]) != is_xmmop(&in->ops[1])) || (is_ymmop(&in->ops[0]) != is_ymmop(&in->ops[1]))) return RASM_ERR_INVALID_ARGUMENT;
                if (is_vec_op(&in->ops[2])) {
                    if ((is_xmmop(&in->ops[0]) != is_xmmop(&in->ops[2])) || (is_ymmop(&in->ops[0]) != is_ymmop(&in->ops[2]))) return RASM_ERR_INVALID_ARGUMENT;
                }
                bool l = is_ymmop(&in->ops[0]);
                uint8_t opcode = (in->mnem == MNEM_VBLENDPS) ? 0x0C : 0x0D;
                uint8_t opc[] = {opcode};
                rasm_status st = emit_vex_modrm(opc, 1, &in->ops[2], reg_code(in->ops[0].v.reg), in->ops[1].v.reg, false, l, 0x01, 0x03, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                emit_u8(&unit->text, (uint8_t)in->ops[3].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // SSE4.1 insertps
        case MNEM_INSERTPS: {
            if (in->op_count == 3 && is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1])) && is_imm8(&in->ops[2])) {
                uint8_t prefix = 0x66;
                emit_u8(&unit->text, prefix);
                uint8_t map_select[] = {0x0F, 0x3A, 0x21};
                rasm_status st = emit_op_modrm_legacy(NULL, 0, map_select, 3, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                emit_u8(&unit->text, (uint8_t)in->ops[2].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // SSE4.1 extractps
        case MNEM_EXTRACTPS: {
            if (in->op_count == 3 && (is_reg32(&in->ops[0]) || is_memop(&in->ops[0])) && is_xmmop(&in->ops[1]) && is_imm8(&in->ops[2])) {
                uint8_t prefix = 0x66;
                emit_u8(&unit->text, prefix);
                uint8_t map_select[] = {0x0F, 0x3A, 0x17};
                rasm_status st = emit_op_modrm_legacy(NULL, 0, map_select, 3, &in->ops[0], reg_code(in->ops[1].v.reg), false, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                emit_u8(&unit->text, (uint8_t)in->ops[2].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // SSE4.1 pblendw
        case MNEM_PBLENDW: {
            if (in->op_count == 3 && is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1])) && is_imm8(&in->ops[2])) {
                uint8_t prefix = 0x66;
                emit_u8(&unit->text, prefix);
                uint8_t map_select[] = {0x0F, 0x3A, 0x0E};
                rasm_status st = emit_op_modrm_legacy(NULL, 0, map_select, 3, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                emit_u8(&unit->text, (uint8_t)in->ops[2].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // SSE4.1 roundss/roundsd
        case MNEM_ROUNDSS:
        case MNEM_ROUNDSD: {
            if (in->op_count == 3 && is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1])) && is_imm8(&in->ops[2])) {
                uint8_t prefix = 0x66;
                uint8_t opcode = (in->mnem == MNEM_ROUNDSS) ? 0x0A : 0x0B;
                emit_u8(&unit->text, prefix);
                uint8_t map_select[] = {0x0F, 0x3A, opcode};
                rasm_status st = emit_op_modrm_legacy(NULL, 0, map_select, 3, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                emit_u8(&unit->text, (uint8_t)in->ops[2].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // SSE4.1 dpps/dppd (dot product)
        case MNEM_DPPS:
        case MNEM_DPPD: {
            if (in->op_count == 3 && is_xmmop(&in->ops[0]) && (is_xmmop(&in->ops[1]) || is_memop(&in->ops[1])) && is_imm8(&in->ops[2])) {
                uint8_t prefix = 0x66;
                uint8_t opcode = (in->mnem == MNEM_DPPS) ? 0x40 : 0x41;
                emit_u8(&unit->text, prefix);
                uint8_t map_select[] = {0x0F, 0x3A, opcode};
                rasm_status st = emit_op_modrm_legacy(NULL, 0, map_select, 3, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                emit_u8(&unit->text, (uint8_t)in->ops[2].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // FMA3 instructions
        case MNEM_VFMADD132PS:
        case MNEM_VFMADD132PD:
        case MNEM_VFMADD213PS:
        case MNEM_VFMADD213PD:
        case MNEM_VFMADD231PS:
        case MNEM_VFMADD231PD:
        case MNEM_VFMSUB132PS:
        case MNEM_VFMSUB132PD:
        case MNEM_VFMSUB213PS:
        case MNEM_VFMSUB213PD:
        case MNEM_VFMSUB231PS:
        case MNEM_VFMSUB231PD:
        case MNEM_VFNMADD132PS:
        case MNEM_VFNMADD132PD:
        case MNEM_VFNMADD213PS:
        case MNEM_VFNMADD213PD:
        case MNEM_VFNMADD231PS:
        case MNEM_VFNMADD231PD:
        case MNEM_VFNMSUB132PS:
        case MNEM_VFNMSUB132PD:
        case MNEM_VFNMSUB213PS:
        case MNEM_VFNMSUB213PD:
        case MNEM_VFNMSUB231PS:
        case MNEM_VFNMSUB231PD: {
            if (in->op_count == 3 && is_vec_op(&in->ops[0]) && is_vec_op(&in->ops[1]) && (is_vec_op(&in->ops[2]) || is_memop(&in->ops[2]))) {
                if ((is_xmmop(&in->ops[0]) != is_xmmop(&in->ops[1])) || (is_ymmop(&in->ops[0]) != is_ymmop(&in->ops[1]))) return RASM_ERR_INVALID_ARGUMENT;
                if (is_vec_op(&in->ops[2])) {
                    if ((is_xmmop(&in->ops[0]) != is_xmmop(&in->ops[2])) || (is_ymmop(&in->ops[0]) != is_ymmop(&in->ops[2]))) return RASM_ERR_INVALID_ARGUMENT;
                }
                bool l = is_ymmop(&in->ops[0]);
                bool w = (in->mnem == MNEM_VFMADD132PD || in->mnem == MNEM_VFMADD213PD || in->mnem == MNEM_VFMADD231PD ||
                          in->mnem == MNEM_VFMSUB132PD || in->mnem == MNEM_VFMSUB213PD || in->mnem == MNEM_VFMSUB231PD ||
                          in->mnem == MNEM_VFNMADD132PD || in->mnem == MNEM_VFNMADD213PD || in->mnem == MNEM_VFNMADD231PD ||
                          in->mnem == MNEM_VFNMSUB132PD || in->mnem == MNEM_VFNMSUB213PD || in->mnem == MNEM_VFNMSUB231PD);
                uint8_t opcode = 0;
                switch (in->mnem) {
                    case MNEM_VFMADD132PS: case MNEM_VFMADD132PD: opcode = 0x98; break;
                    case MNEM_VFMADD213PS: case MNEM_VFMADD213PD: opcode = 0xA8; break;
                    case MNEM_VFMADD231PS: case MNEM_VFMADD231PD: opcode = 0xB8; break;
                    case MNEM_VFMSUB132PS: case MNEM_VFMSUB132PD: opcode = 0x9A; break;
                    case MNEM_VFMSUB213PS: case MNEM_VFMSUB213PD: opcode = 0xAA; break;
                    case MNEM_VFMSUB231PS: case MNEM_VFMSUB231PD: opcode = 0xBA; break;
                    case MNEM_VFNMADD132PS: case MNEM_VFNMADD132PD: opcode = 0x9C; break;
                    case MNEM_VFNMADD213PS: case MNEM_VFNMADD213PD: opcode = 0xAC; break;
                    case MNEM_VFNMADD231PS: case MNEM_VFNMADD231PD: opcode = 0xBC; break;
                    case MNEM_VFNMSUB132PS: case MNEM_VFNMSUB132PD: opcode = 0x9E; break;
                    case MNEM_VFNMSUB213PS: case MNEM_VFNMSUB213PD: opcode = 0xAE; break;
                    case MNEM_VFNMSUB231PS: case MNEM_VFNMSUB231PD: opcode = 0xBE; break;
                    default: return RASM_ERR_INVALID_ARGUMENT;
                }
                uint8_t opc[] = {opcode};
                return emit_vex_modrm(opc, 1, &in->ops[2], reg_code(in->ops[0].v.reg), in->ops[1].v.reg, w, l, 0x01, 0x02, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // AVX2 vperm2i128
        case MNEM_VPERM2I128: {
            if (in->op_count == 4 && is_ymmop(&in->ops[0]) && is_ymmop(&in->ops[1]) && (is_ymmop(&in->ops[2]) || is_memop(&in->ops[2])) && is_imm8(&in->ops[3])) {
                uint8_t opc[] = {0x46};
                rasm_status st = emit_vex_modrm(opc, 1, &in->ops[2], reg_code(in->ops[0].v.reg), in->ops[1].v.reg, false, true, 0x01, 0x03, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                emit_u8(&unit->text, (uint8_t)in->ops[3].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // AVX2 vpermd
        case MNEM_VPERMD: {
            if (in->op_count == 3 && is_ymmop(&in->ops[0]) && is_ymmop(&in->ops[1]) && (is_ymmop(&in->ops[2]) || is_memop(&in->ops[2]))) {
                uint8_t opc[] = {0x36};
                return emit_vex_modrm(opc, 1, &in->ops[2], reg_code(in->ops[0].v.reg), in->ops[1].v.reg, false, true, 0x01, 0x02, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // AVX2 vpermq
        case MNEM_VPERMQ: {
            if (in->op_count == 3 && is_ymmop(&in->ops[0]) && (is_ymmop(&in->ops[1]) || is_memop(&in->ops[1])) && is_imm8(&in->ops[2])) {
                uint8_t opc[] = {0x00};
                rasm_status st = emit_vex_modrm(opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), REG_INVALID, true, true, 0x01, 0x03, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                emit_u8(&unit->text, (uint8_t)in->ops[2].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // AVX2 vgather* instructions
        case MNEM_VGATHERDPS:
        case MNEM_VGATHERDPD:
        case MNEM_VGATHERQPS:
        case MNEM_VGATHERQPD: {
            if (in->op_count == 3 && is_vec_op(&in->ops[0]) && is_memop(&in->ops[1]) && is_vec_op(&in->ops[2])) {
                // vgather dst, vsib, mask
                // For now, simplified implementation - full vsib and mask validation would be needed
                bool l = is_ymmop(&in->ops[0]);
                bool w = (in->mnem == MNEM_VGATHERDPD || in->mnem == MNEM_VGATHERQPD);
                uint8_t opcode = 0;
                switch (in->mnem) {
                    case MNEM_VGATHERDPS: opcode = 0x92; break;
                    case MNEM_VGATHERDPD: opcode = 0x92; break;
                    case MNEM_VGATHERQPS: opcode = 0x93; break;
                    case MNEM_VGATHERQPD: opcode = 0x93; break;
                    default: return RASM_ERR_INVALID_ARGUMENT;
                }
                uint8_t opc[] = {opcode};
                return emit_vex_modrm(opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), in->ops[2].v.reg, w, l, 0x01, 0x02, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // AVX2 vpmaskmov* instructions
        case MNEM_VPMASKMOVD:
        case MNEM_VPMASKMOVQ: {
            if (in->op_count == 3) {
                bool w = (in->mnem == MNEM_VPMASKMOVQ);
                // Two forms: load (reg, reg, mem) or store (mem, reg, reg)
                if (is_vec_op(&in->ops[0]) && is_vec_op(&in->ops[1]) && is_memop(&in->ops[2])) {
                    // Load: dst, mask, mem
                    bool l = is_ymmop(&in->ops[0]);
                    uint8_t opc[] = {0x8C};
                    return emit_vex_modrm(opc, 1, &in->ops[2], reg_code(in->ops[0].v.reg), in->ops[1].v.reg, w, l, 0x01, 0x02, unit, RELOC_PC32);
                } else if (is_memop(&in->ops[0]) && is_vec_op(&in->ops[1]) && is_vec_op(&in->ops[2])) {
                    // Store: mem, mask, src
                    bool l = is_ymmop(&in->ops[1]);
                    uint8_t opc[] = {0x8E};
                    return emit_vex_modrm(opc, 1, &in->ops[0], reg_code(in->ops[2].v.reg), in->ops[1].v.reg, w, l, 0x01, 0x02, unit, RELOC_PC32);
                }
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_JMP:
        case MNEM_CALL: {
            if (in->op_count != 1) return RASM_ERR_INVALID_ARGUMENT;
            if (is_memop(&in->ops[0]) || is_reg64(&in->ops[0])) {
                uint8_t opc[] = {0xFF};
                uint8_t ext = (in->mnem == MNEM_CALL) ? 2 : 4;
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], ext, false, unit, RELOC_PC32);
            }
            
            // Try short JMP if target is close and backward (to ensure consistent sizing across passes)
            // Only optimize backward references to avoid size inconsistency between first and second pass
            if (in->mnem == MNEM_JMP && in->ops[0].kind == OP_SYMBOL) {
                const symbol *sym = find_symbol(unit, in->ops[0].v.sym);
                if (sym && sym->is_defined && sym->section == SEC_TEXT) {
                    int64_t disp = (int64_t)sym->value - (int64_t)(unit->text.len + 2);
                    // Only use short jump for backward references (disp < 0) or very close forward refs
                    // that were definitely defined in first pass at same position
                    if (disp >= -128 && disp < 0) {
                        emit_u8(&unit->text, 0xEB); // Short JMP
                        emit_u8(&unit->text, (uint8_t)disp);
                        return RASM_OK;
                    }
                }
            }
            
            // Near branch
            emit_u8(&unit->text, in->mnem == MNEM_JMP ? 0xE9 : 0xE8);
            if (in->ops[0].kind == OP_SYMBOL) {
                // In 16-bit mode, use 16-bit displacement; otherwise 32-bit
                if (unit->arch == ARCH_X86_16) {
                    emit_u16(&unit->text, 0);
                    // Note: Using RELOC_PC32 is a placeholder - ideally should be RELOC_PC16
                    relocation r = { .kind = RELOC_PC32, .symbol = in->ops[0].v.sym, .offset = unit->text.len - 2, .addend = 0 };
                    VEC_PUSH(unit->text_relocs, r);
                } else {
                    emit_u32(&unit->text, 0);
                    // Use PLT32 for external symbols (CALL) for PIE compatibility, PC32 for jumps and local symbols
                    reloc_kind rk = RELOC_PC32;
                    if (in->mnem == MNEM_CALL) {
                        const symbol *sym = find_symbol(unit, in->ops[0].v.sym);
                        if (sym && sym->is_extern) {
                            rk = RELOC_PLT32;
                        }
                    }
                    relocation r = { .kind = rk, .symbol = in->ops[0].v.sym, .offset = unit->text.len - 4, .addend = 0 };
                    VEC_PUSH(unit->text_relocs, r);
                }
            } else if (in->ops[0].kind == OP_IMM) {
                if (unit->arch == ARCH_X86_16) {
                    int64_t disp = (int64_t)in->ops[0].v.imm - (int64_t)(unit->text.len + 2);
                    emit_u16(&unit->text, (uint16_t)disp);
                } else {
                    int64_t disp = (int64_t)in->ops[0].v.imm - (int64_t)(unit->text.len + 4);
                    emit_u32(&unit->text, (uint32_t)disp);
                }
            } else if (in->ops[0].kind == OP_EXPR) {
                // Evaluate expression to get target address
                const char *unresolved = NULL;
                int64_t target = 0;
                if (!eval_expression(in->ops[0].v.expr, unit, &target, &unresolved)) {
                    return RASM_ERR_INVALID_ARGUMENT;
                }
                if (unit->arch == ARCH_X86_16) {
                    int64_t disp = target - (int64_t)(unit->origin + unit->text.len + 2);
                    emit_u16(&unit->text, (uint16_t)disp);
                } else {
                    int64_t disp = target - (int64_t)(unit->origin + unit->text.len + 4);
                    emit_u32(&unit->text, (uint32_t)disp);
                }
            } else {
                return RASM_ERR_INVALID_ARGUMENT;
            }
            return RASM_OK;
        }
        case MNEM_JE: case MNEM_JNE: case MNEM_JA: case MNEM_JAE: case MNEM_JB: case MNEM_JBE: case MNEM_JG: case MNEM_JGE: case MNEM_JL: case MNEM_JLE: case MNEM_JO: case MNEM_JNO: case MNEM_JS: case MNEM_JNS: case MNEM_JP: case MNEM_JNP: {
            if (in->op_count != 1) return RASM_ERR_INVALID_ARGUMENT;
            int cc = cond_code_from_mnemonic(in->mnem);
            if (cc < 0) return RASM_ERR_INVALID_ARGUMENT;
            
            // Try short conditional jump if target is close and backward
            // Only optimize backward references to ensure consistent sizing across passes
            if (in->ops[0].kind == OP_SYMBOL) {
                const symbol *sym = find_symbol(unit, in->ops[0].v.sym);
                if (sym && sym->is_defined && sym->section == SEC_TEXT) {
                    int64_t disp = (int64_t)sym->value - (int64_t)(unit->text.len + 2);
                    // Only use short jump for backward references (disp < 0)
                    if (disp >= -128 && disp < 0) {
                        emit_u8(&unit->text, (uint8_t)(0x70 | cc)); // Short Jcc
                        emit_u8(&unit->text, (uint8_t)disp);
                        return RASM_OK;
                    }
                }
            }
            
            // Near conditional jump
            emit_u8(&unit->text, 0x0F);
            emit_u8(&unit->text, (uint8_t)(0x80 | cc));
            if (in->ops[0].kind == OP_SYMBOL) {
                if (unit->arch == ARCH_X86_16) {
                    // 16-bit mode: use 16-bit displacement
                    emit_u16(&unit->text, 0);
                    relocation r = { .kind = RELOC_PC32, .symbol = in->ops[0].v.sym, .offset = unit->text.len - 2, .addend = -2 };
                    VEC_PUSH(unit->text_relocs, r);
                } else {
                    // 32/64-bit mode: use 32-bit displacement
                    emit_u32(&unit->text, 0);
                    relocation r = { .kind = RELOC_PC32, .symbol = in->ops[0].v.sym, .offset = unit->text.len - 4, .addend = -4 };
                    VEC_PUSH(unit->text_relocs, r);
                }
            } else if (in->ops[0].kind == OP_IMM) {
                if (unit->arch == ARCH_X86_16) {
                    int64_t disp = (int64_t)in->ops[0].v.imm - (int64_t)(unit->text.len + 2);
                    emit_u16(&unit->text, (uint16_t)disp);
                } else {
                    int64_t disp = (int64_t)in->ops[0].v.imm - (int64_t)(unit->text.len + 4);
                    emit_u32(&unit->text, (uint32_t)disp);
                }
            } else {
                return RASM_ERR_INVALID_ARGUMENT;
            }
            return RASM_OK;
        }
        case MNEM_SETE: case MNEM_SETNE: case MNEM_SETA: case MNEM_SETAE: case MNEM_SETB: case MNEM_SETBE: case MNEM_SETG: case MNEM_SETGE: case MNEM_SETL: case MNEM_SETLE: case MNEM_SETO: case MNEM_SETNO: case MNEM_SETS: case MNEM_SETNS: case MNEM_SETP: case MNEM_SETNP: {
            if (in->op_count != 1 || !(is_memop(&in->ops[0]) || is_reg64(&in->ops[0]))) return RASM_ERR_INVALID_ARGUMENT;
            int cc = cond_code_from_mnemonic(in->mnem);
            if (cc < 0) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t opc[] = {0x0F, (uint8_t)(0x90 | cc)};
            return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[0], 0, false, unit, RELOC_PC32);
        }
        case MNEM_CMOVE: case MNEM_CMOVNE: case MNEM_CMOVA: case MNEM_CMOVAE: case MNEM_CMOVB: case MNEM_CMOVBE: case MNEM_CMOVG: case MNEM_CMOVGE: case MNEM_CMOVL: case MNEM_CMOVLE: case MNEM_CMOVO: case MNEM_CMOVNO: case MNEM_CMOVS: case MNEM_CMOVNS: case MNEM_CMOVP: case MNEM_CMOVNP: {
            if (in->op_count != 2 || !is_reg64(&in->ops[0]) || !(is_reg64(&in->ops[1]) || is_memop(&in->ops[1]))) return RASM_ERR_INVALID_ARGUMENT;
            int cc = cond_code_from_mnemonic(in->mnem);
            if (cc < 0) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t opc[] = {0x0F, (uint8_t)(0x40 | cc)};
            return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), true, unit, RELOC_PC32);
        }
        case MNEM_MUL:
        case MNEM_IMUL:
        case MNEM_DIV:
        case MNEM_IDIV: {
            if (in->op_count != 1 || !(is_memop(&in->ops[0]) || is_reg64(&in->ops[0]))) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t opc[] = {0xF7};
            uint8_t ext = 0;
            switch (in->mnem) {
                case MNEM_MUL: ext = 4; break;
                case MNEM_IMUL: ext = 5; break;
                case MNEM_DIV: ext = 6; break;
                case MNEM_IDIV: ext = 7; break;
                default: break;
            }
            return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], ext, true, unit, RELOC_PC32);
        }
        case MNEM_CQO:
            if (in->op_count != 0) return RASM_ERR_INVALID_ARGUMENT;
            emit_rex(&unit->text, true, false, false, false, unit->arch);
            emit_u8(&unit->text, 0x99);
            return RASM_OK;
        case MNEM_SYSCALL:
            if (in->op_count != 0) return RASM_ERR_INVALID_ARGUMENT;
            emit_u8(&unit->text, 0x0F);
            emit_u8(&unit->text, 0x05);
            return RASM_OK;
        case MNEM_RET:
            emit_u8(&unit->text, 0xC3);
            return RASM_OK;
        case MNEM_NOP:
            emit_u8(&unit->text, 0x90);
            return RASM_OK;
        
        // Conversion instructions
        case MNEM_CBW:
            emit_u8(&unit->text, 0x66);
            emit_u8(&unit->text, 0x98);
            return RASM_OK;
        case MNEM_CWDE:
            emit_u8(&unit->text, 0x98);
            return RASM_OK;
        case MNEM_CDQE:
            emit_rex(&unit->text, true, false, false, false, unit->arch);
            emit_u8(&unit->text, 0x98);
            return RASM_OK;
        case MNEM_CDQ:
            emit_u8(&unit->text, 0x99);
            return RASM_OK;
        
        // Flag manipulation instructions
        case MNEM_CLC:
            emit_u8(&unit->text, 0xF8);
            return RASM_OK;
        case MNEM_STC:
            emit_u8(&unit->text, 0xF9);
            return RASM_OK;
        case MNEM_CMC:
            emit_u8(&unit->text, 0xF5);
            return RASM_OK;
        case MNEM_CLD:
            emit_u8(&unit->text, 0xFC);
            return RASM_OK;
        case MNEM_STD:
            emit_u8(&unit->text, 0xFD);
            return RASM_OK;
        case MNEM_CLI:
            emit_u8(&unit->text, 0xFA);
            return RASM_OK;
        case MNEM_STI:
            emit_u8(&unit->text, 0xFB);
            return RASM_OK;
        case MNEM_LAHF:
            emit_u8(&unit->text, 0x9F);
            return RASM_OK;
        case MNEM_SAHF:
            emit_u8(&unit->text, 0x9E);
            return RASM_OK;
        case MNEM_PUSHF:
            emit_u8(&unit->text, 0x9C);
            return RASM_OK;
        case MNEM_POPF:
            emit_u8(&unit->text, 0x9D);
            return RASM_OK;
        case MNEM_PUSHFQ:
            emit_u8(&unit->text, 0x9C);
            return RASM_OK;
        case MNEM_POPFQ:
            emit_u8(&unit->text, 0x9D);
            return RASM_OK;
        
        // Stack frame instructions
        case MNEM_LEAVE:
            emit_u8(&unit->text, 0xC9);
            return RASM_OK;
        case MNEM_ENTER:
            if (in->op_count != 2 || in->ops[0].kind != OP_IMM || in->ops[1].kind != OP_IMM) {
                return RASM_ERR_INVALID_ARGUMENT;
            }
            if (in->ops[0].v.imm > 0xFFFF || in->ops[1].v.imm > 0xFF) {
                return RASM_ERR_INVALID_ARGUMENT;
            }
            emit_u8(&unit->text, 0xC8);
            emit_u8(&unit->text, (uint8_t)(in->ops[0].v.imm & 0xFF));
            emit_u8(&unit->text, (uint8_t)((in->ops[0].v.imm >> 8) & 0xFF));
            emit_u8(&unit->text, (uint8_t)(in->ops[1].v.imm & 0xFF));
            return RASM_OK;
        
        // Miscellaneous instructions
        case MNEM_HLT:
            emit_u8(&unit->text, 0xF4);
            return RASM_OK;
        case MNEM_PAUSE:
            emit_u8(&unit->text, 0xF3);
            emit_u8(&unit->text, 0x90);
            return RASM_OK;
        case MNEM_CPUID:
            emit_u8(&unit->text, 0x0F);
            emit_u8(&unit->text, 0xA2);
            return RASM_OK;
        case MNEM_RDTSC:
            emit_u8(&unit->text, 0x0F);
            emit_u8(&unit->text, 0x31);
            return RASM_OK;
        case MNEM_RDTSCP:
            emit_u8(&unit->text, 0x0F);
            emit_u8(&unit->text, 0x01);
            emit_u8(&unit->text, 0xF9);
            return RASM_OK;
        
        // Protected mode instructions
        case MNEM_LGDT:
            if (in->op_count != 1 || !is_memop(&in->ops[0])) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t lgdt_opc[] = {0x0F, 0x01};
            return emit_op_modrm_legacy(NULL, 0, lgdt_opc, 2, &in->ops[0], 2, false, unit, RELOC_PC32);
        case MNEM_LIDT:
            if (in->op_count != 1 || !is_memop(&in->ops[0])) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t lidt_opc[] = {0x0F, 0x01};
            return emit_op_modrm_legacy(NULL, 0, lidt_opc, 2, &in->ops[0], 3, false, unit, RELOC_PC32);
        case MNEM_SGDT:
            if (in->op_count != 1 || !is_memop(&in->ops[0])) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t sgdt_opc[] = {0x0F, 0x01};
            return emit_op_modrm_legacy(NULL, 0, sgdt_opc, 2, &in->ops[0], 0, false, unit, RELOC_PC32);
        case MNEM_SIDT:
            if (in->op_count != 1 || !is_memop(&in->ops[0])) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t sidt_opc[] = {0x0F, 0x01};
            return emit_op_modrm_legacy(NULL, 0, sidt_opc, 2, &in->ops[0], 1, false, unit, RELOC_PC32);
        case MNEM_LTR:
            if (in->op_count != 1 || !(is_memop(&in->ops[0]) || is_reg16(&in->ops[0]))) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t ltr_opc[] = {0x0F, 0x00};
            return emit_op_modrm_legacy(NULL, 0, ltr_opc, 2, &in->ops[0], 3, false, unit, RELOC_PC32);
        case MNEM_STR:
            if (in->op_count != 1 || !(is_memop(&in->ops[0]) || is_reg16(&in->ops[0]))) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t str_opc[] = {0x0F, 0x00};
            return emit_op_modrm_legacy(NULL, 0, str_opc, 2, &in->ops[0], 1, false, unit, RELOC_PC32);
        case MNEM_LLDT:
            if (in->op_count != 1 || !(is_memop(&in->ops[0]) || is_reg16(&in->ops[0]))) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t lldt_opc[] = {0x0F, 0x00};
            return emit_op_modrm_legacy(NULL, 0, lldt_opc, 2, &in->ops[0], 2, false, unit, RELOC_PC32);
        case MNEM_SLDT:
            if (in->op_count != 1 || !(is_memop(&in->ops[0]) || is_reg16(&in->ops[0]))) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t sldt_opc[] = {0x0F, 0x00};
            return emit_op_modrm_legacy(NULL, 0, sldt_opc, 2, &in->ops[0], 0, false, unit, RELOC_PC32);
        case MNEM_LAR:
            if (in->op_count != 2) return RASM_ERR_INVALID_ARGUMENT;
            if (is_reg64(&in->ops[0]) && (is_reg64(&in->ops[1]) || is_memop(&in->ops[1]))) {
                uint8_t lar_opc[] = {0x0F, 0x02};
                return emit_op_modrm_legacy(NULL, 0, lar_opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), true, unit, RELOC_PC32);
            } else if (is_reg32(&in->ops[0]) && (is_reg32(&in->ops[1]) || is_memop(&in->ops[1]))) {
                uint8_t lar_opc[] = {0x0F, 0x02};
                return emit_op_modrm_legacy(NULL, 0, lar_opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        case MNEM_LSL:
            if (in->op_count != 2) return RASM_ERR_INVALID_ARGUMENT;
            if (is_reg64(&in->ops[0]) && (is_reg64(&in->ops[1]) || is_memop(&in->ops[1]))) {
                uint8_t lsl_opc[] = {0x0F, 0x03};
                return emit_op_modrm_legacy(NULL, 0, lsl_opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), true, unit, RELOC_PC32);
            } else if (is_reg32(&in->ops[0]) && (is_reg32(&in->ops[1]) || is_memop(&in->ops[1]))) {
                uint8_t lsl_opc[] = {0x0F, 0x03};
                return emit_op_modrm_legacy(NULL, 0, lsl_opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        case MNEM_VERR:
            if (in->op_count != 1 || !(is_memop(&in->ops[0]) || is_reg16(&in->ops[0]))) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t verr_opc[] = {0x0F, 0x00};
            return emit_op_modrm_legacy(NULL, 0, verr_opc, 2, &in->ops[0], 4, false, unit, RELOC_PC32);
        case MNEM_VERW:
            if (in->op_count != 1 || !(is_memop(&in->ops[0]) || is_reg16(&in->ops[0]))) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t verw_opc[] = {0x0F, 0x00};
            return emit_op_modrm_legacy(NULL, 0, verw_opc, 2, &in->ops[0], 5, false, unit, RELOC_PC32);
        case MNEM_CLTS:
            emit_u8(&unit->text, 0x0F);
            emit_u8(&unit->text, 0x06);
            return RASM_OK;
        case MNEM_LMSW:
            if (in->op_count != 1 || !(is_memop(&in->ops[0]) || is_reg16(&in->ops[0]))) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t lmsw_opc[] = {0x0F, 0x01};
            return emit_op_modrm_legacy(NULL, 0, lmsw_opc, 2, &in->ops[0], 6, false, unit, RELOC_PC32);
        case MNEM_SMSW:
            if (in->op_count != 1 || !(is_memop(&in->ops[0]) || is_reg16(&in->ops[0]))) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t smsw_opc[] = {0x0F, 0x01};
            return emit_op_modrm_legacy(NULL, 0, smsw_opc, 2, &in->ops[0], 4, false, unit, RELOC_PC32);
        case MNEM_INVLPG:
            if (in->op_count != 1 || !is_memop(&in->ops[0])) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t invlpg_opc[] = {0x0F, 0x01};
            return emit_op_modrm_legacy(NULL, 0, invlpg_opc, 2, &in->ops[0], 7, false, unit, RELOC_PC32);
        case MNEM_INVD:
            emit_u8(&unit->text, 0x0F);
            emit_u8(&unit->text, 0x08);
            return RASM_OK;
        case MNEM_WBINVD:
            emit_u8(&unit->text, 0x0F);
            emit_u8(&unit->text, 0x09);
            return RASM_OK;
        
        // Double-precision shifts: SHLD/SHRD
        case MNEM_SHLD:
        case MNEM_SHRD: {
            // SHLD/SHRD r/m, reg, imm8  or  SHLD/SHRD r/m, reg, CL
            if (in->op_count != 3) return RASM_ERR_INVALID_ARGUMENT;
            if (!is_memop(&in->ops[0]) && (in->ops[0].kind != OP_REG || !is_gpr(in->ops[0].v.reg))) return RASM_ERR_INVALID_ARGUMENT;
            if (in->ops[1].kind != OP_REG || !is_gpr(in->ops[1].v.reg)) return RASM_ERR_INVALID_ARGUMENT;
            
            uint8_t base_opcode = (in->mnem == MNEM_SHLD) ? 0xA4 : 0xAC;
            bool is_cl = (in->ops[2].kind == OP_REG && in->ops[2].v.reg == REG_CL);
            
            if (is_cl) {
                base_opcode++; // 0xA5 for SHLD, 0xAD for SHRD
                uint8_t opc[] = {0x0F, base_opcode};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[0], reg_code(in->ops[1].v.reg), false, unit, RELOC_PC32);
            } else if (in->ops[2].kind == OP_IMM) {
                uint8_t opc[] = {0x0F, base_opcode};
                rasm_status st = emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[0], reg_code(in->ops[1].v.reg), false, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                emit_u8(&unit->text, (uint8_t)in->ops[2].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        
        // Memory fences
        case MNEM_MFENCE:
            emit_u8(&unit->text, 0x0F);
            emit_u8(&unit->text, 0xAE);
            emit_u8(&unit->text, 0xF0);
            return RASM_OK;
        case MNEM_LFENCE:
            emit_u8(&unit->text, 0x0F);
            emit_u8(&unit->text, 0xAE);
            emit_u8(&unit->text, 0xE8);
            return RASM_OK;
        case MNEM_SFENCE:
            emit_u8(&unit->text, 0x0F);
            emit_u8(&unit->text, 0xAE);
            emit_u8(&unit->text, 0xF8);
            return RASM_OK;
        
        // System instructions
        case MNEM_UD2:
            emit_u8(&unit->text, 0x0F);
            emit_u8(&unit->text, 0x0B);
            return RASM_OK;
        
        case MNEM_IRET:
            emit_u8(&unit->text, 0xCF);
            return RASM_OK;
        case MNEM_IRETD:
            if (unit->arch == ARCH_X86_16) emit_u8(&unit->text, 0x66);
            emit_u8(&unit->text, 0xCF);
            return RASM_OK;
        case MNEM_IRETQ:
            if (unit->arch != ARCH_X86_64) return RASM_ERR_INVALID_ARGUMENT;
            emit_u8(&unit->text, 0x48);  // REX.W
            emit_u8(&unit->text, 0xCF);
            return RASM_OK;
        
        case MNEM_JCXZ:
            if (in->op_count != 1) return RASM_ERR_INVALID_ARGUMENT;
            if (unit->arch != ARCH_X86_16) emit_u8(&unit->text, 0x67);  // Address-size override
            emit_u8(&unit->text, 0xE3);
            if (in->ops[0].kind == OP_SYMBOL) {
                const symbol *sym = find_symbol(unit, in->ops[0].v.sym);
                if (sym && sym->is_defined && sym->section == SEC_TEXT) {
                    int64_t disp = (int64_t)sym->value - (int64_t)(unit->text.len + 1);
                    emit_u8(&unit->text, (uint8_t)disp);
                } else {
                    emit_u8(&unit->text, 0);
                    // For 8-bit relative jumps, we can't use standard relocation - just emit 0
                    // In a proper implementation, would need RELOC_PC8 type
                }
            } else if (in->ops[0].kind == OP_IMM) {
                int64_t disp = (int64_t)in->ops[0].v.imm - (int64_t)(unit->text.len + 1);
                emit_u8(&unit->text, (uint8_t)disp);
            } else {
                return RASM_ERR_INVALID_ARGUMENT;
            }
            return RASM_OK;
        case MNEM_JECXZ:
            if (in->op_count != 1) return RASM_ERR_INVALID_ARGUMENT;
            if (unit->arch == ARCH_X86_16) emit_u8(&unit->text, 0x67);
            emit_u8(&unit->text, 0xE3);
            if (in->ops[0].kind == OP_SYMBOL) {
                const symbol *sym = find_symbol(unit, in->ops[0].v.sym);
                if (sym && sym->is_defined && sym->section == SEC_TEXT) {
                    int64_t disp = (int64_t)sym->value - (int64_t)(unit->text.len + 1);
                    emit_u8(&unit->text, (uint8_t)disp);
                } else {
                    emit_u8(&unit->text, 0);
                }
            } else if (in->ops[0].kind == OP_IMM) {
                int64_t disp = (int64_t)in->ops[0].v.imm - (int64_t)(unit->text.len + 1);
                emit_u8(&unit->text, (uint8_t)disp);
            } else {
                return RASM_ERR_INVALID_ARGUMENT;
            }
            return RASM_OK;
        case MNEM_JRCXZ:
            if (in->op_count != 1) return RASM_ERR_INVALID_ARGUMENT;
            if (unit->arch != ARCH_X86_64) return RASM_ERR_INVALID_ARGUMENT;
            emit_u8(&unit->text, 0xE3);
            if (in->ops[0].kind == OP_SYMBOL) {
                const symbol *sym = find_symbol(unit, in->ops[0].v.sym);
                if (sym && sym->is_defined && sym->section == SEC_TEXT) {
                    int64_t disp = (int64_t)sym->value - (int64_t)(unit->text.len + 1);
                    emit_u8(&unit->text, (uint8_t)disp);
                } else {
                    emit_u8(&unit->text, 0);
                }
            } else if (in->ops[0].kind == OP_IMM) {
                int64_t disp = (int64_t)in->ops[0].v.imm - (int64_t)(unit->text.len + 1);
                emit_u8(&unit->text, (uint8_t)disp);
            } else {
                return RASM_ERR_INVALID_ARGUMENT;
            }
            return RASM_OK;
        
        case MNEM_RETF:
            if (in->op_count == 0) {
                emit_u8(&unit->text, 0xCB);
                return RASM_OK;
            } else if (in->op_count == 1 && in->ops[0].kind == OP_IMM) {
                emit_u8(&unit->text, 0xCA);
                emit_u16(&unit->text, (uint16_t)in->ops[0].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_SYSENTER:
            emit_u8(&unit->text, 0x0F);
            emit_u8(&unit->text, 0x34);
            return RASM_OK;
        case MNEM_SYSEXIT:
            emit_u8(&unit->text, 0x0F);
            emit_u8(&unit->text, 0x35);
            return RASM_OK;
        case MNEM_SYSRET:
            emit_u8(&unit->text, 0x0F);
            emit_u8(&unit->text, 0x07);
            return RASM_OK;
        
        // Cache control - Prefetch variants
        case MNEM_PREFETCHNTA:
            if (in->op_count != 1 || !is_memop(&in->ops[0])) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t prefetchnta_opc[] = {0x0F, 0x18};
            return emit_op_modrm_legacy(NULL, 0, prefetchnta_opc, 2, &in->ops[0], 0, false, unit, RELOC_PC32);
        case MNEM_PREFETCHT0:
            if (in->op_count != 1 || !is_memop(&in->ops[0])) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t prefetcht0_opc[] = {0x0F, 0x18};
            return emit_op_modrm_legacy(NULL, 0, prefetcht0_opc, 2, &in->ops[0], 1, false, unit, RELOC_PC32);
        case MNEM_PREFETCHT1:
            if (in->op_count != 1 || !is_memop(&in->ops[0])) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t prefetcht1_opc[] = {0x0F, 0x18};
            return emit_op_modrm_legacy(NULL, 0, prefetcht1_opc, 2, &in->ops[0], 2, false, unit, RELOC_PC32);
        case MNEM_PREFETCHT2:
            if (in->op_count != 1 || !is_memop(&in->ops[0])) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t prefetcht2_opc[] = {0x0F, 0x18};
            return emit_op_modrm_legacy(NULL, 0, prefetcht2_opc, 2, &in->ops[0], 3, false, unit, RELOC_PC32);
        
        case MNEM_CLFLUSH:
            if (in->op_count != 1 || !is_memop(&in->ops[0])) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t clflush_opc[] = {0x0F, 0xAE};
            return emit_op_modrm_legacy(NULL, 0, clflush_opc, 2, &in->ops[0], 7, false, unit, RELOC_PC32);
        case MNEM_CLFLUSHOPT:
            if (in->op_count != 1 || !is_memop(&in->ops[0])) return RASM_ERR_INVALID_ARGUMENT;
            emit_u8(&unit->text, 0x66);  // Prefix to distinguish from CLFLUSH
            uint8_t clflushopt_opc[] = {0x0F, 0xAE};
            return emit_op_modrm_legacy(NULL, 0, clflushopt_opc, 2, &in->ops[0], 7, false, unit, RELOC_PC32);
        
        // Random number generation
        case MNEM_RDRAND:
            if (in->op_count != 1 || in->ops[0].kind != OP_REG || !is_gpr(in->ops[0].v.reg)) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t rdrand_opc[] = {0x0F, 0xC7};
            return emit_op_modrm_legacy(NULL, 0, rdrand_opc, 2, &in->ops[0], 6, false, unit, RELOC_PC32);
        case MNEM_RDSEED:
            if (in->op_count != 1 || in->ops[0].kind != OP_REG || !is_gpr(in->ops[0].v.reg)) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t rdseed_opc[] = {0x0F, 0xC7};
            return emit_op_modrm_legacy(NULL, 0, rdseed_opc, 2, &in->ops[0], 7, false, unit, RELOC_PC32);
        
        // Segment register loads (LDS, LES, LFS, LGS, LSS)
        case MNEM_LDS:
            if (unit->arch == ARCH_X86_64) return RASM_ERR_INVALID_ARGUMENT;  // Invalid in 64-bit mode
            if (in->op_count != 2 || in->ops[0].kind != OP_REG || !is_memop(&in->ops[1])) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t lds_opc[] = {0xC5};
            return emit_op_modrm_legacy(NULL, 0, lds_opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
        case MNEM_LES:
            if (unit->arch == ARCH_X86_64) return RASM_ERR_INVALID_ARGUMENT;
            if (in->op_count != 2 || in->ops[0].kind != OP_REG || !is_memop(&in->ops[1])) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t les_opc[] = {0xC4};
            return emit_op_modrm_legacy(NULL, 0, les_opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
        case MNEM_LFS:
            if (in->op_count != 2 || in->ops[0].kind != OP_REG || !is_memop(&in->ops[1])) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t lfs_opc[] = {0x0F, 0xB4};
            return emit_op_modrm_legacy(NULL, 0, lfs_opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
        case MNEM_LGS:
            if (in->op_count != 2 || in->ops[0].kind != OP_REG || !is_memop(&in->ops[1])) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t lgs_opc[] = {0x0F, 0xB5};
            return emit_op_modrm_legacy(NULL, 0, lgs_opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
        case MNEM_LSS:
            if (in->op_count != 2 || in->ops[0].kind != OP_REG || !is_memop(&in->ops[1])) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t lss_opc[] = {0x0F, 0xB2};
            return emit_op_modrm_legacy(NULL, 0, lss_opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
        
        // BCD arithmetic
        case MNEM_AAA:
            if (unit->arch == ARCH_X86_64) return RASM_ERR_INVALID_ARGUMENT;
            emit_u8(&unit->text, 0x37);
            return RASM_OK;
        case MNEM_AAD:
            if (unit->arch == ARCH_X86_64) return RASM_ERR_INVALID_ARGUMENT;
            emit_u8(&unit->text, 0xD5);
            emit_u8(&unit->text, (in->op_count == 1 && in->ops[0].kind == OP_IMM) ? (uint8_t)in->ops[0].v.imm : 0x0A);
            return RASM_OK;
        case MNEM_AAM:
            if (unit->arch == ARCH_X86_64) return RASM_ERR_INVALID_ARGUMENT;
            emit_u8(&unit->text, 0xD4);
            emit_u8(&unit->text, (in->op_count == 1 && in->ops[0].kind == OP_IMM) ? (uint8_t)in->ops[0].v.imm : 0x0A);
            return RASM_OK;
        case MNEM_AAS:
            if (unit->arch == ARCH_X86_64) return RASM_ERR_INVALID_ARGUMENT;
            emit_u8(&unit->text, 0x3F);
            return RASM_OK;
        case MNEM_DAA:
            if (unit->arch == ARCH_X86_64) return RASM_ERR_INVALID_ARGUMENT;
            emit_u8(&unit->text, 0x27);
            return RASM_OK;
        case MNEM_DAS:
            if (unit->arch == ARCH_X86_64) return RASM_ERR_INVALID_ARGUMENT;
            emit_u8(&unit->text, 0x2F);
            return RASM_OK;
        
        // Legacy instructions
        case MNEM_BOUND:
            if (unit->arch == ARCH_X86_64) return RASM_ERR_INVALID_ARGUMENT;
            if (in->op_count != 2 || in->ops[0].kind != OP_REG || !is_memop(&in->ops[1])) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t bound_opc[] = {0x62};
            return emit_op_modrm_legacy(NULL, 0, bound_opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
        case MNEM_ARPL:
            if (unit->arch == ARCH_X86_64) return RASM_ERR_INVALID_ARGUMENT;
            if (in->op_count != 2 || !is_reg16(&in->ops[0]) || in->ops[1].kind != OP_REG || !is_gpr16(in->ops[1].v.reg)) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t arpl_opc[] = {0x63};
            return emit_op_modrm_legacy(NULL, 0, arpl_opc, 1, &in->ops[0], reg_code(in->ops[1].v.reg), false, unit, RELOC_PC32);
        case MNEM_INTO:
            if (unit->arch == ARCH_X86_64) return RASM_ERR_INVALID_ARGUMENT;
            emit_u8(&unit->text, 0xCE);
            return RASM_OK;
        case MNEM_SALC:
            if (unit->arch == ARCH_X86_64) return RASM_ERR_INVALID_ARGUMENT;
            emit_u8(&unit->text, 0xD6);
            return RASM_OK;
        
        // Extended state save/restore
        case MNEM_XSAVE:
        case MNEM_XSAVE64:
            if (in->op_count != 1 || !is_memop(&in->ops[0])) return RASM_ERR_INVALID_ARGUMENT;
            if (in->mnem == MNEM_XSAVE64 && unit->arch != ARCH_X86_64) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t xsave_opc[] = {0x0F, 0xAE};
            return emit_op_modrm_legacy(NULL, 0, xsave_opc, 2, &in->ops[0], 4, false, unit, RELOC_PC32);
        case MNEM_XRSTOR:
        case MNEM_XRSTOR64:
            if (in->op_count != 1 || !is_memop(&in->ops[0])) return RASM_ERR_INVALID_ARGUMENT;
            if (in->mnem == MNEM_XRSTOR64 && unit->arch != ARCH_X86_64) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t xrstor_opc[] = {0x0F, 0xAE};
            return emit_op_modrm_legacy(NULL, 0, xrstor_opc, 2, &in->ops[0], 5, false, unit, RELOC_PC32);
        case MNEM_XSAVEOPT:
        case MNEM_XSAVEOPT64:
            if (in->op_count != 1 || !is_memop(&in->ops[0])) return RASM_ERR_INVALID_ARGUMENT;
            if (in->mnem == MNEM_XSAVEOPT64 && unit->arch != ARCH_X86_64) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t xsaveopt_opc[] = {0x0F, 0xAE};
            return emit_op_modrm_legacy(NULL, 0, xsaveopt_opc, 2, &in->ops[0], 6, false, unit, RELOC_PC32);
        case MNEM_XSAVEC:
        case MNEM_XSAVEC64:
            if (in->op_count != 1 || !is_memop(&in->ops[0])) return RASM_ERR_INVALID_ARGUMENT;
            if (in->mnem == MNEM_XSAVEC64 && unit->arch != ARCH_X86_64) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t xsavec_opc[] = {0x0F, 0xC7};
            return emit_op_modrm_legacy(NULL, 0, xsavec_opc, 2, &in->ops[0], 4, false, unit, RELOC_PC32);
        case MNEM_XSAVES:
        case MNEM_XSAVES64:
            if (in->op_count != 1 || !is_memop(&in->ops[0])) return RASM_ERR_INVALID_ARGUMENT;
            if (in->mnem == MNEM_XSAVES64 && unit->arch != ARCH_X86_64) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t xsaves_opc[] = {0x0F, 0xC7};
            return emit_op_modrm_legacy(NULL, 0, xsaves_opc, 2, &in->ops[0], 5, false, unit, RELOC_PC32);
        case MNEM_XRSTORS:
        case MNEM_XRSTORS64:
            if (in->op_count != 1 || !is_memop(&in->ops[0])) return RASM_ERR_INVALID_ARGUMENT;
            if (in->mnem == MNEM_XRSTORS64 && unit->arch != ARCH_X86_64) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t xrstors_opc[] = {0x0F, 0xC7};
            return emit_op_modrm_legacy(NULL, 0, xrstors_opc, 2, &in->ops[0], 3, false, unit, RELOC_PC32);
        
        // Extended control registers
        case MNEM_XGETBV:
            emit_u8(&unit->text, 0x0F);
            emit_u8(&unit->text, 0x01);
            emit_u8(&unit->text, 0xD0);
            return RASM_OK;
        case MNEM_XSETBV:
            emit_u8(&unit->text, 0x0F);
            emit_u8(&unit->text, 0x01);
            emit_u8(&unit->text, 0xD1);
            return RASM_OK;
        
        // CPU monitoring
        case MNEM_MONITOR:
            emit_u8(&unit->text, 0x0F);
            emit_u8(&unit->text, 0x01);
            emit_u8(&unit->text, 0xC8);
            return RASM_OK;
        case MNEM_MWAIT:
            emit_u8(&unit->text, 0x0F);
            emit_u8(&unit->text, 0x01);
            emit_u8(&unit->text, 0xC9);
            return RASM_OK;
        
        // x87 FPU instructions
        case MNEM_FLD:
            // FLD ST(i) - D9 C0+i
            if (in->op_count == 1 && in->ops[0].kind == OP_REG && is_st(in->ops[0].v.reg)) {
                emit_u8(&unit->text, 0xD9);
                emit_u8(&unit->text, 0xC0 + reg_code(in->ops[0].v.reg));
                return RASM_OK;
            }
            // FLD m32fp - D9 /0
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0xD9};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 0, false, unit, RELOC_PC32);
            }
            // FLD m64fp - DD /0 (handled by size inference)
            // FLD m80fp - DB /5 (handled by size inference)
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FST:
            // FST ST(i) - DD D0+i
            if (in->op_count == 1 && in->ops[0].kind == OP_REG && is_st(in->ops[0].v.reg)) {
                emit_u8(&unit->text, 0xDD);
                emit_u8(&unit->text, 0xD0 + reg_code(in->ops[0].v.reg));
                return RASM_OK;
            }
            // FST m32fp - D9 /2
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0xD9};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 2, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FSTP:
            // FSTP ST(i) - DD D8+i
            if (in->op_count == 1 && in->ops[0].kind == OP_REG && is_st(in->ops[0].v.reg)) {
                emit_u8(&unit->text, 0xDD);
                emit_u8(&unit->text, 0xD8 + reg_code(in->ops[0].v.reg));
                return RASM_OK;
            }
            // FSTP m32fp - D9 /3
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0xD9};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 3, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FILD:
            // FILD m16int - DF /0
            // FILD m32int - DB /0
            // FILD m64int - DF /5
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0xDB};  // Default to m32int
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 0, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FIST:
            // FIST m16int - DF /2
            // FIST m32int - DB /2
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0xDB};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 2, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FISTP:
            // FISTP m16int - DF /3
            // FISTP m32int - DB /3
            // FISTP m64int - DF /7
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0xDB};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 3, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FBLD:
            // FBLD m80bcd - DF /4
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0xDF};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 4, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FBSTP:
            // FBSTP m80bcd - DF /6
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0xDF};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 6, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FXCH:
            // FXCH - D9 C9 (exchange with ST(1))
            if (in->op_count == 0) {
                emit_u8(&unit->text, 0xD9);
                emit_u8(&unit->text, 0xC9);
                return RASM_OK;
            }
            // FXCH ST(i) - D9 C8+i
            if (in->op_count == 1 && in->ops[0].kind == OP_REG && is_st(in->ops[0].v.reg)) {
                emit_u8(&unit->text, 0xD9);
                emit_u8(&unit->text, 0xC8 + reg_code(in->ops[0].v.reg));
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FADD:
            // FADD - DC C1 (add ST(0) = ST(0) + ST(1))
            if (in->op_count == 0) {
                emit_u8(&unit->text, 0xDC);
                emit_u8(&unit->text, 0xC1);
                return RASM_OK;
            }
            // FADD ST(i) - D8 C0+i
            if (in->op_count == 1 && in->ops[0].kind == OP_REG && is_st(in->ops[0].v.reg)) {
                emit_u8(&unit->text, 0xD8);
                emit_u8(&unit->text, 0xC0 + reg_code(in->ops[0].v.reg));
                return RASM_OK;
            }
            // FADD ST(i), ST(0) - DC C0+i
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_st(in->ops[0].v.reg) &&
                in->ops[1].kind == OP_REG && in->ops[1].v.reg == REG_ST0) {
                emit_u8(&unit->text, 0xDC);
                emit_u8(&unit->text, 0xC0 + reg_code(in->ops[0].v.reg));
                return RASM_OK;
            }
            // FADD m32fp - D8 /0
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0xD8};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 0, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FADDP:
            // FADDP - DE C1
            if (in->op_count == 0) {
                emit_u8(&unit->text, 0xDE);
                emit_u8(&unit->text, 0xC1);
                return RASM_OK;
            }
            // FADDP ST(i), ST(0) - DE C0+i
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_st(in->ops[0].v.reg) &&
                in->ops[1].kind == OP_REG && in->ops[1].v.reg == REG_ST0) {
                emit_u8(&unit->text, 0xDE);
                emit_u8(&unit->text, 0xC0 + reg_code(in->ops[0].v.reg));
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FIADD:
            // FIADD m32int - DA /0
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0xDA};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 0, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FSUB:
            // FSUB ST(i) - D8 E0+i
            if (in->op_count == 1 && in->ops[0].kind == OP_REG && is_st(in->ops[0].v.reg)) {
                emit_u8(&unit->text, 0xD8);
                emit_u8(&unit->text, 0xE0 + reg_code(in->ops[0].v.reg));
                return RASM_OK;
            }
            // FSUB m32fp - D8 /4
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0xD8};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 4, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FSUBP:
            // FSUBP ST(i), ST(0) - DE E8+i
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_st(in->ops[0].v.reg) &&
                in->ops[1].kind == OP_REG && in->ops[1].v.reg == REG_ST0) {
                emit_u8(&unit->text, 0xDE);
                emit_u8(&unit->text, 0xE8 + reg_code(in->ops[0].v.reg));
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FISUB:
            // FISUB m32int - DA /4
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0xDA};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 4, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FSUBR:
            // FSUBR ST(i) - D8 E8+i
            if (in->op_count == 1 && in->ops[0].kind == OP_REG && is_st(in->ops[0].v.reg)) {
                emit_u8(&unit->text, 0xD8);
                emit_u8(&unit->text, 0xE8 + reg_code(in->ops[0].v.reg));
                return RASM_OK;
            }
            // FSUBR m32fp - D8 /5
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0xD8};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 5, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FSUBRP:
            // FSUBRP ST(i), ST(0) - DE E0+i
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_st(in->ops[0].v.reg) &&
                in->ops[1].kind == OP_REG && in->ops[1].v.reg == REG_ST0) {
                emit_u8(&unit->text, 0xDE);
                emit_u8(&unit->text, 0xE0 + reg_code(in->ops[0].v.reg));
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FISUBR:
            // FISUBR m32int - DA /5
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0xDA};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 5, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FMUL:
            // FMUL ST(i) - D8 C8+i
            if (in->op_count == 1 && in->ops[0].kind == OP_REG && is_st(in->ops[0].v.reg)) {
                emit_u8(&unit->text, 0xD8);
                emit_u8(&unit->text, 0xC8 + reg_code(in->ops[0].v.reg));
                return RASM_OK;
            }
            // FMUL m32fp - D8 /1
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0xD8};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 1, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FMULP:
            // FMULP ST(i), ST(0) - DE C8+i
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_st(in->ops[0].v.reg) &&
                in->ops[1].kind == OP_REG && in->ops[1].v.reg == REG_ST0) {
                emit_u8(&unit->text, 0xDE);
                emit_u8(&unit->text, 0xC8 + reg_code(in->ops[0].v.reg));
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FIMUL:
            // FIMUL m32int - DA /1
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0xDA};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 1, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FDIV:
            // FDIV ST(i) - D8 F0+i
            if (in->op_count == 1 && in->ops[0].kind == OP_REG && is_st(in->ops[0].v.reg)) {
                emit_u8(&unit->text, 0xD8);
                emit_u8(&unit->text, 0xF0 + reg_code(in->ops[0].v.reg));
                return RASM_OK;
            }
            // FDIV m32fp - D8 /6
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0xD8};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 6, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FDIVP:
            // FDIVP ST(i), ST(0) - DE F8+i
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_st(in->ops[0].v.reg) &&
                in->ops[1].kind == OP_REG && in->ops[1].v.reg == REG_ST0) {
                emit_u8(&unit->text, 0xDE);
                emit_u8(&unit->text, 0xF8 + reg_code(in->ops[0].v.reg));
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FIDIV:
            // FIDIV m32int - DA /6
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0xDA};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 6, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FDIVR:
            // FDIVR ST(i) - D8 F8+i
            if (in->op_count == 1 && in->ops[0].kind == OP_REG && is_st(in->ops[0].v.reg)) {
                emit_u8(&unit->text, 0xD8);
                emit_u8(&unit->text, 0xF8 + reg_code(in->ops[0].v.reg));
                return RASM_OK;
            }
            // FDIVR m32fp - D8 /7
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0xD8};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 7, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FDIVRP:
            // FDIVRP ST(i), ST(0) - DE F0+i
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_st(in->ops[0].v.reg) &&
                in->ops[1].kind == OP_REG && in->ops[1].v.reg == REG_ST0) {
                emit_u8(&unit->text, 0xDE);
                emit_u8(&unit->text, 0xF0 + reg_code(in->ops[0].v.reg));
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FIDIVR:
            // FIDIVR m32int - DA /7
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0xDA};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 7, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        // Transcendental and other x87 instructions
        case MNEM_FSQRT:
            emit_u8(&unit->text, 0xD9);
            emit_u8(&unit->text, 0xFA);
            return RASM_OK;
        case MNEM_FSCALE:
            emit_u8(&unit->text, 0xD9);
            emit_u8(&unit->text, 0xFD);
            return RASM_OK;
        case MNEM_FPREM:
            emit_u8(&unit->text, 0xD9);
            emit_u8(&unit->text, 0xF8);
            return RASM_OK;
        case MNEM_FPREM1:
            emit_u8(&unit->text, 0xD9);
            emit_u8(&unit->text, 0xF5);
            return RASM_OK;
        case MNEM_FRNDINT:
            emit_u8(&unit->text, 0xD9);
            emit_u8(&unit->text, 0xFC);
            return RASM_OK;
        case MNEM_FXTRACT:
            emit_u8(&unit->text, 0xD9);
            emit_u8(&unit->text, 0xF4);
            return RASM_OK;
        case MNEM_FABS:
            emit_u8(&unit->text, 0xD9);
            emit_u8(&unit->text, 0xE1);
            return RASM_OK;
        case MNEM_FCHS:
            emit_u8(&unit->text, 0xD9);
            emit_u8(&unit->text, 0xE0);
            return RASM_OK;
        
        // Comparison instructions
        case MNEM_FCOM:
            if (in->op_count == 0) {
                emit_u8(&unit->text, 0xD8);
                emit_u8(&unit->text, 0xD1);
                return RASM_OK;
            }
            if (in->op_count == 1 && in->ops[0].kind == OP_REG && is_st(in->ops[0].v.reg)) {
                emit_u8(&unit->text, 0xD8);
                emit_u8(&unit->text, 0xD0 + reg_code(in->ops[0].v.reg));
                return RASM_OK;
            }
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0xD8};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 2, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FCOMP:
            if (in->op_count == 0) {
                emit_u8(&unit->text, 0xD8);
                emit_u8(&unit->text, 0xD9);
                return RASM_OK;
            }
            if (in->op_count == 1 && in->ops[0].kind == OP_REG && is_st(in->ops[0].v.reg)) {
                emit_u8(&unit->text, 0xD8);
                emit_u8(&unit->text, 0xD8 + reg_code(in->ops[0].v.reg));
                return RASM_OK;
            }
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0xD8};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 3, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FCOMPP:
            emit_u8(&unit->text, 0xDE);
            emit_u8(&unit->text, 0xD9);
            return RASM_OK;
        
        case MNEM_FUCOM:
            if (in->op_count == 0) {
                emit_u8(&unit->text, 0xDD);
                emit_u8(&unit->text, 0xE1);
                return RASM_OK;
            }
            if (in->op_count == 1 && in->ops[0].kind == OP_REG && is_st(in->ops[0].v.reg)) {
                emit_u8(&unit->text, 0xDD);
                emit_u8(&unit->text, 0xE0 + reg_code(in->ops[0].v.reg));
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FUCOMP:
            if (in->op_count == 0) {
                emit_u8(&unit->text, 0xDD);
                emit_u8(&unit->text, 0xE9);
                return RASM_OK;
            }
            if (in->op_count == 1 && in->ops[0].kind == OP_REG && is_st(in->ops[0].v.reg)) {
                emit_u8(&unit->text, 0xDD);
                emit_u8(&unit->text, 0xE8 + reg_code(in->ops[0].v.reg));
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FUCOMPP:
            emit_u8(&unit->text, 0xDA);
            emit_u8(&unit->text, 0xE9);
            return RASM_OK;
        
        case MNEM_FICOM:
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0xDA};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 2, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FICOMP:
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0xDA};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 3, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FCOMI:
            if (in->op_count == 1 && in->ops[0].kind == OP_REG && is_st(in->ops[0].v.reg)) {
                emit_u8(&unit->text, 0xDB);
                emit_u8(&unit->text, 0xF0 + reg_code(in->ops[0].v.reg));
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FCOMIP:
            if (in->op_count == 1 && in->ops[0].kind == OP_REG && is_st(in->ops[0].v.reg)) {
                emit_u8(&unit->text, 0xDF);
                emit_u8(&unit->text, 0xF0 + reg_code(in->ops[0].v.reg));
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FUCOMI:
            if (in->op_count == 1 && in->ops[0].kind == OP_REG && is_st(in->ops[0].v.reg)) {
                emit_u8(&unit->text, 0xDB);
                emit_u8(&unit->text, 0xE8 + reg_code(in->ops[0].v.reg));
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FUCOMIP:
            if (in->op_count == 1 && in->ops[0].kind == OP_REG && is_st(in->ops[0].v.reg)) {
                emit_u8(&unit->text, 0xDF);
                emit_u8(&unit->text, 0xE8 + reg_code(in->ops[0].v.reg));
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FTST:
            emit_u8(&unit->text, 0xD9);
            emit_u8(&unit->text, 0xE4);
            return RASM_OK;
        
        case MNEM_FXAM:
            emit_u8(&unit->text, 0xD9);
            emit_u8(&unit->text, 0xE5);
            return RASM_OK;
        
        // Transcendental instructions
        case MNEM_FSIN:
            emit_u8(&unit->text, 0xD9);
            emit_u8(&unit->text, 0xFE);
            return RASM_OK;
        
        case MNEM_FCOS:
            emit_u8(&unit->text, 0xD9);
            emit_u8(&unit->text, 0xFF);
            return RASM_OK;
        
        case MNEM_FSINCOS:
            emit_u8(&unit->text, 0xD9);
            emit_u8(&unit->text, 0xFB);
            return RASM_OK;
        
        case MNEM_FPTAN:
            emit_u8(&unit->text, 0xD9);
            emit_u8(&unit->text, 0xF2);
            return RASM_OK;
        
        case MNEM_FPATAN:
            emit_u8(&unit->text, 0xD9);
            emit_u8(&unit->text, 0xF3);
            return RASM_OK;
        
        case MNEM_F2XM1:
            emit_u8(&unit->text, 0xD9);
            emit_u8(&unit->text, 0xF0);
            return RASM_OK;
        
        case MNEM_FYL2X:
            emit_u8(&unit->text, 0xD9);
            emit_u8(&unit->text, 0xF1);
            return RASM_OK;
        
        case MNEM_FYL2XP1:
            emit_u8(&unit->text, 0xD9);
            emit_u8(&unit->text, 0xF9);
            return RASM_OK;
        
        // Load constants
        case MNEM_FLD1:
            emit_u8(&unit->text, 0xD9);
            emit_u8(&unit->text, 0xE8);
            return RASM_OK;
        
        case MNEM_FLDL2T:
            emit_u8(&unit->text, 0xD9);
            emit_u8(&unit->text, 0xE9);
            return RASM_OK;
        
        case MNEM_FLDL2E:
            emit_u8(&unit->text, 0xD9);
            emit_u8(&unit->text, 0xEA);
            return RASM_OK;
        
        case MNEM_FLDPI:
            emit_u8(&unit->text, 0xD9);
            emit_u8(&unit->text, 0xEB);
            return RASM_OK;
        
        case MNEM_FLDLG2:
            emit_u8(&unit->text, 0xD9);
            emit_u8(&unit->text, 0xEC);
            return RASM_OK;
        
        case MNEM_FLDLN2:
            emit_u8(&unit->text, 0xD9);
            emit_u8(&unit->text, 0xED);
            return RASM_OK;
        
        case MNEM_FLDZ:
            emit_u8(&unit->text, 0xD9);
            emit_u8(&unit->text, 0xEE);
            return RASM_OK;
        
        // Control instructions
        case MNEM_FINIT:
            emit_u8(&unit->text, 0x9B);
            emit_u8(&unit->text, 0xDB);
            emit_u8(&unit->text, 0xE3);
            return RASM_OK;
        
        case MNEM_FNINIT:
            emit_u8(&unit->text, 0xDB);
            emit_u8(&unit->text, 0xE3);
            return RASM_OK;
        
        case MNEM_FCLEX:
            emit_u8(&unit->text, 0x9B);
            emit_u8(&unit->text, 0xDB);
            emit_u8(&unit->text, 0xE2);
            return RASM_OK;
        
        case MNEM_FNCLEX:
            emit_u8(&unit->text, 0xDB);
            emit_u8(&unit->text, 0xE2);
            return RASM_OK;
        
        case MNEM_FSTCW:
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                emit_u8(&unit->text, 0x9B);
                uint8_t opc[] = {0xD9};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 7, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FNSTCW:
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0xD9};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 7, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FLDCW:
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0xD9};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 5, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FSTENV:
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                emit_u8(&unit->text, 0x9B);
                uint8_t opc[] = {0xD9};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 6, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FNSTENV:
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0xD9};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 6, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FLDENV:
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0xD9};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 4, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FSAVE:
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                emit_u8(&unit->text, 0x9B);
                uint8_t opc[] = {0xDD};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 6, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FNSAVE:
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0xDD};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 6, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FRSTOR:
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0xDD};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 4, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FSTSW:
            if (in->op_count == 1 && in->ops[0].kind == OP_REG && in->ops[0].v.reg == REG_AX) {
                emit_u8(&unit->text, 0x9B);
                emit_u8(&unit->text, 0xDF);
                emit_u8(&unit->text, 0xE0);
                return RASM_OK;
            }
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                emit_u8(&unit->text, 0x9B);
                uint8_t opc[] = {0xDD};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 7, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FNSTSW:
            if (in->op_count == 1 && in->ops[0].kind == OP_REG && in->ops[0].v.reg == REG_AX) {
                emit_u8(&unit->text, 0xDF);
                emit_u8(&unit->text, 0xE0);
                return RASM_OK;
            }
            if (in->op_count == 1 && is_memop(&in->ops[0])) {
                uint8_t opc[] = {0xDD};
                return emit_op_modrm_legacy(NULL, 0, opc, 1, &in->ops[0], 7, false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FINCSTP:
            emit_u8(&unit->text, 0xD9);
            emit_u8(&unit->text, 0xF7);
            return RASM_OK;
        
        case MNEM_FDECSTP:
            emit_u8(&unit->text, 0xD9);
            emit_u8(&unit->text, 0xF6);
            return RASM_OK;
        
        case MNEM_FFREE:
            if (in->op_count == 1 && in->ops[0].kind == OP_REG && is_st(in->ops[0].v.reg)) {
                emit_u8(&unit->text, 0xDD);
                emit_u8(&unit->text, 0xC0 + reg_code(in->ops[0].v.reg));
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FFREEP:
            if (in->op_count == 1 && in->ops[0].kind == OP_REG && is_st(in->ops[0].v.reg)) {
                emit_u8(&unit->text, 0xDF);
                emit_u8(&unit->text, 0xC0 + reg_code(in->ops[0].v.reg));
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_FNOP:
            emit_u8(&unit->text, 0xD9);
            emit_u8(&unit->text, 0xD0);
            return RASM_OK;
        
        case MNEM_FWAIT:
            emit_u8(&unit->text, 0x9B);
            return RASM_OK;
        
        // MMX instructions
        case MNEM_EMMS:
            emit_u8(&unit->text, 0x0F);
            emit_u8(&unit->text, 0x77);
            return RASM_OK;
        
        case MNEM_MOVD:
            // MOVD mm, r/m32 - 0F 6E /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg) &&
                ((in->ops[1].kind == OP_REG && is_gpr32(in->ops[1].v.reg)) || is_memop(&in->ops[1]))) {
                uint8_t opc[] = {0x0F, 0x6E};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            // MOVD r/m32, mm - 0F 7E /r
            if (in->op_count == 2 && ((in->ops[0].kind == OP_REG && is_gpr32(in->ops[0].v.reg)) || is_memop(&in->ops[0])) &&
                in->ops[1].kind == OP_REG && is_mmx(in->ops[1].v.reg)) {
                uint8_t opc[] = {0x0F, 0x7E};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[0], reg_code(in->ops[1].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_MOVQ:
            // MOVQ mm1, mm2/m64 - 0F 6F /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg) &&
                ((in->ops[1].kind == OP_REG && is_mmx(in->ops[1].v.reg)) || is_memop(&in->ops[1]))) {
                uint8_t opc[] = {0x0F, 0x6F};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            // MOVQ mm2/m64, mm1 - 0F 7F /r
            if (in->op_count == 2 && ((in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) || is_memop(&in->ops[0])) &&
                in->ops[1].kind == OP_REG && is_mmx(in->ops[1].v.reg)) {
                uint8_t opc[] = {0x0F, 0x7F};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[0], reg_code(in->ops[1].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PACKSSWB:
            // PACKSSWB mm1, mm2/m64 - 0F 63 /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0x63};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PACKSSDW:
            // PACKSSDW mm1, mm2/m64 - 0F 6B /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0x6B};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PACKUSWB:
            // PACKUSWB mm1, mm2/m64 - 0F 67 /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0x67};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PADDB:
            // PADDB mm1, mm2/m64 - 0F FC /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0xFC};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PADDW:
            // PADDW mm1, mm2/m64 - 0F FD /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0xFD};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        // PADDD - handled in shared SSE2/MMX section below
        
        case MNEM_PADDSB:
            // PADDSB mm1, mm2/m64 - 0F EC /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0xEC};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PADDSW:
            // PADDSW mm1, mm2/m64 - 0F ED /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0xED};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PADDUSB:
            // PADDUSB mm1, mm2/m64 - 0F DC /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0xDC};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PADDUSW:
            // PADDUSW mm1, mm2/m64 - 0F DD /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0xDD};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        // PAND - handled in shared SSE2/MMX section below
        
        case MNEM_PANDN:
            // PANDN mm1, mm2/m64 - 0F DF /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0xDF};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PCMPEQB:
            // PCMPEQB mm1, mm2/m64 - 0F 74 /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0x74};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PCMPEQW:
            // PCMPEQW mm1, mm2/m64 - 0F 75 /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0x75};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        // PCMPEQD - handled in shared SSE2/MMX section below
        
        case MNEM_PCMPGTB:
            // PCMPGTB mm1, mm2/m64 - 0F 64 /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0x64};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PCMPGTW:
            // PCMPGTW mm1, mm2/m64 - 0F 65 /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0x65};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        // PCMPGTD - handled in shared SSE2/MMX section below
        
        case MNEM_PMADDWD:
            // PMADDWD mm1, mm2/m64 - 0F F5 /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0xF5};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PMULHW:
            // PMULHW mm1, mm2/m64 - 0F E5 /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0xE5};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PMULLW:
            // PMULLW mm1, mm2/m64 - 0F D5 /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0xD5};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        // POR - handled in shared SSE2/MMX section below
        
        case MNEM_PSLLD:
            // PSLLD mm1, mm2/m64 - 0F F2 /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg) && 
                ((in->ops[1].kind == OP_REG && is_mmx(in->ops[1].v.reg)) || is_memop(&in->ops[1]))) {
                uint8_t opc[] = {0x0F, 0xF2};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            // PSLLD mm, imm8 - 0F 72 /6 ib
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg) && in->ops[1].kind == OP_IMM) {
                emit_u8(&unit->text, 0x0F);
                emit_u8(&unit->text, 0x72);
                emit_u8(&unit->text, 0xC0 | (6 << 3) | reg_code(in->ops[0].v.reg));
                emit_u8(&unit->text, (uint8_t)in->ops[1].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        // PSLLQ - handled in shared SSE2/MMX section below
        
        case MNEM_PSLLW:
            // PSLLW mm1, mm2/m64 - 0F F1 /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg) && 
                ((in->ops[1].kind == OP_REG && is_mmx(in->ops[1].v.reg)) || is_memop(&in->ops[1]))) {
                uint8_t opc[] = {0x0F, 0xF1};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            // PSLLW mm, imm8 - 0F 71 /6 ib
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg) && in->ops[1].kind == OP_IMM) {
                emit_u8(&unit->text, 0x0F);
                emit_u8(&unit->text, 0x71);
                emit_u8(&unit->text, 0xC0 | (6 << 3) | reg_code(in->ops[0].v.reg));
                emit_u8(&unit->text, (uint8_t)in->ops[1].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PSRAD:
            // PSRAD mm1, mm2/m64 - 0F E2 /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg) && 
                ((in->ops[1].kind == OP_REG && is_mmx(in->ops[1].v.reg)) || is_memop(&in->ops[1]))) {
                uint8_t opc[] = {0x0F, 0xE2};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            // PSRAD mm, imm8 - 0F 72 /4 ib
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg) && in->ops[1].kind == OP_IMM) {
                emit_u8(&unit->text, 0x0F);
                emit_u8(&unit->text, 0x72);
                emit_u8(&unit->text, 0xC0 | (4 << 3) | reg_code(in->ops[0].v.reg));
                emit_u8(&unit->text, (uint8_t)in->ops[1].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PSRAW:
            // PSRAW mm1, mm2/m64 - 0F E1 /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg) && 
                ((in->ops[1].kind == OP_REG && is_mmx(in->ops[1].v.reg)) || is_memop(&in->ops[1]))) {
                uint8_t opc[] = {0x0F, 0xE1};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            // PSRAW mm, imm8 - 0F 71 /4 ib
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg) && in->ops[1].kind == OP_IMM) {
                emit_u8(&unit->text, 0x0F);
                emit_u8(&unit->text, 0x71);
                emit_u8(&unit->text, 0xC0 | (4 << 3) | reg_code(in->ops[0].v.reg));
                emit_u8(&unit->text, (uint8_t)in->ops[1].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PSRLD:
            // PSRLD mm1, mm2/m64 - 0F D2 /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg) && 
                ((in->ops[1].kind == OP_REG && is_mmx(in->ops[1].v.reg)) || is_memop(&in->ops[1]))) {
                uint8_t opc[] = {0x0F, 0xD2};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            // PSRLD mm, imm8 - 0F 72 /2 ib
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg) && in->ops[1].kind == OP_IMM) {
                emit_u8(&unit->text, 0x0F);
                emit_u8(&unit->text, 0x72);
                emit_u8(&unit->text, 0xC0 | (2 << 3) | reg_code(in->ops[0].v.reg));
                emit_u8(&unit->text, (uint8_t)in->ops[1].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        // PSRLQ - handled in shared SSE2/MMX section below
        
        case MNEM_PSRLW:
            // PSRLW mm1, mm2/m64 - 0F D1 /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg) && 
                ((in->ops[1].kind == OP_REG && is_mmx(in->ops[1].v.reg)) || is_memop(&in->ops[1]))) {
                uint8_t opc[] = {0x0F, 0xD1};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            // PSRLW mm, imm8 - 0F 71 /2 ib
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg) && in->ops[1].kind == OP_IMM) {
                emit_u8(&unit->text, 0x0F);
                emit_u8(&unit->text, 0x71);
                emit_u8(&unit->text, 0xC0 | (2 << 3) | reg_code(in->ops[0].v.reg));
                emit_u8(&unit->text, (uint8_t)in->ops[1].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PSUBB:
            // PSUBB mm1, mm2/m64 - 0F F8 /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0xF8};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PSUBW:
            // PSUBW mm1, mm2/m64 - 0F F9 /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0xF9};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        // PSUBD - handled in shared SSE2/MMX section below
        
        case MNEM_PSUBSB:
            // PSUBSB mm1, mm2/m64 - 0F E8 /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0xE8};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PSUBSW:
            // PSUBSW mm1, mm2/m64 - 0F E9 /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0xE9};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PSUBUSB:
            // PSUBUSB mm1, mm2/m64 - 0F D8 /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0xD8};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PSUBUSW:
            // PSUBUSW mm1, mm2/m64 - 0F D9 /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0xD9};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PUNPCKHBW:
            // PUNPCKHBW mm1, mm2/m64 - 0F 68 /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0x68};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PUNPCKHWD:
            // PUNPCKHWD mm1, mm2/m64 - 0F 69 /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0x69};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PUNPCKHDQ:
            // PUNPCKHDQ mm1, mm2/m64 - 0F 6A /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0x6A};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PUNPCKLBW:
            // PUNPCKLBW mm1, mm2/m64 - 0F 60 /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0x60};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PUNPCKLWD:
            // PUNPCKLWD mm1, mm2/m64 - 0F 61 /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0x61};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PUNPCKLDQ:
            // PUNPCKLDQ mm1, mm2/m64 - 0F 62 /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0x62};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PMULHUW:
            // PMULHUW mm1, mm2/m64 - 0F E4 /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0xE4};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PAVGB:
            // PAVGB mm1, mm2/m64 - 0F E0 /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0xE0};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PAVGW:
            // PAVGW mm1, mm2/m64 - 0F E3 /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0xE3};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PMAXSW:
            // PMAXSW mm1, mm2/m64 - 0F EE /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0xEE};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PMAXUB:
            // PMAXUB mm1, mm2/m64 - 0F DE /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0xDE};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PMINSW:
            // PMINSW mm1, mm2/m64 - 0F EA /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0xEA};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PMINUB:
            // PMINUB mm1, mm2/m64 - 0F DA /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0xDA};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PMOVMSKB:
            // PMOVMSKB r32, mm - 0F D7 /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_gpr32(in->ops[0].v.reg) &&
                in->ops[1].kind == OP_REG && is_mmx(in->ops[1].v.reg)) {
                emit_u8(&unit->text, 0x0F);
                emit_u8(&unit->text, 0xD7);
                emit_u8(&unit->text, 0xC0 | (reg_code(in->ops[0].v.reg) << 3) | reg_code(in->ops[1].v.reg));
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PSADBW:
            // PSADBW mm1, mm2/m64 - 0F F6 /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opc[] = {0x0F, 0xF6};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PEXTRW:
            // PEXTRW r32, mm, imm8 - 0F C5 /r ib
            if (in->op_count == 3 && in->ops[0].kind == OP_REG && is_gpr32(in->ops[0].v.reg) &&
                in->ops[1].kind == OP_REG && is_mmx(in->ops[1].v.reg) && in->ops[2].kind == OP_IMM) {
                emit_u8(&unit->text, 0x0F);
                emit_u8(&unit->text, 0xC5);
                emit_u8(&unit->text, 0xC0 | (reg_code(in->ops[0].v.reg) << 3) | reg_code(in->ops[1].v.reg));
                emit_u8(&unit->text, (uint8_t)in->ops[2].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_PINSRW:
            // PINSRW mm, r32/m16, imm8 - 0F C4 /r ib
            if (in->op_count == 3 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg) &&
                ((in->ops[1].kind == OP_REG && is_gpr32(in->ops[1].v.reg)) || is_memop(&in->ops[1])) &&
                in->ops[2].kind == OP_IMM) {
                uint8_t opc[] = {0x0F, 0xC4};
                rasm_status err = emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
                if (err != RASM_OK) return err;
                emit_u8(&unit->text, (uint8_t)in->ops[2].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_MASKMOVQ:
            // MASKMOVQ mm1, mm2 - 0F F7 /r
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg) &&
                in->ops[1].kind == OP_REG && is_mmx(in->ops[1].v.reg)) {
                emit_u8(&unit->text, 0x0F);
                emit_u8(&unit->text, 0xF7);
                emit_u8(&unit->text, 0xC0 | (reg_code(in->ops[0].v.reg) << 3) | reg_code(in->ops[1].v.reg));
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_MOVNTQ:
            // MOVNTQ m64, mm - 0F E7 /r
            if (in->op_count == 2 && is_memop(&in->ops[0]) && in->ops[1].kind == OP_REG && is_mmx(in->ops[1].v.reg)) {
                uint8_t opc[] = {0x0F, 0xE7};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[0], reg_code(in->ops[1].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        
        case MNEM_INT:
            if (in->op_count != 1 || in->ops[0].kind != OP_IMM) {
                return RASM_ERR_INVALID_ARGUMENT;
            }
            if (in->ops[0].v.imm > 0xFF) {
                return RASM_ERR_INVALID_ARGUMENT;
            }
            emit_u8(&unit->text, 0xCD);
            emit_u8(&unit->text, (uint8_t)in->ops[0].v.imm);
            return RASM_OK;
        
        // Loop instructions
        case MNEM_LOOP:
        case MNEM_LOOPE:
        case MNEM_LOOPNE: {
            if (in->op_count != 1) return RASM_ERR_INVALID_ARGUMENT;
            
            // Decode target address (symbol or immediate)
            uint64_t target_addr;
            bool target_found = false;
            if (in->ops[0].kind == OP_SYMBOL) {
                const symbol *sym = find_symbol(unit, in->ops[0].v.sym);
                if (!sym || !sym->is_defined || sym->section != SEC_TEXT) {
                    return RASM_ERR_INVALID_ARGUMENT;
                }
                target_addr = unit->origin + sym->value;
                target_found = true;
            } else if (in->ops[0].kind == OP_IMM) {
                target_addr = in->ops[0].v.imm;
                target_found = true;
            }
            
            if (!target_found) return RASM_ERR_INVALID_ARGUMENT;
            
            // Calculate displacement (8-bit signed)
            uint64_t current_addr = unit->origin + unit->text.len + 2; // After this instruction
            int64_t disp = (int64_t)target_addr - (int64_t)current_addr;
            
            if (disp < -128 || disp > 127) {
                fprintf(stderr, "error: loop target out of range (must be within -128 to +127 bytes)\n");
                return RASM_ERR_INVALID_ARGUMENT;
            }
            
            // Emit opcode
            if (in->mnem == MNEM_LOOP) {
                emit_u8(&unit->text, 0xE2);
            } else if (in->mnem == MNEM_LOOPE) {
                emit_u8(&unit->text, 0xE1);
            } else { // MNEM_LOOPNE
                emit_u8(&unit->text, 0xE0);
            }
            
            // Emit displacement
            emit_u8(&unit->text, (uint8_t)disp);
            return RASM_OK;
        }
        
        // Table lookup translation
        case MNEM_XLAT:
            // XLAT/XLATB: D7 - Loads AL from DS:[BX/EBX/RBX + AL]
            // No operands, implicit addressing mode based on arch
            if (in->op_count != 0) return RASM_ERR_INVALID_ARGUMENT;
            emit_u8(&unit->text, 0xD7);
            return RASM_OK;
        
        // Port I/O instructions
        case MNEM_IN: {
            // IN AL/AX/EAX, imm8 or IN AL/AX/EAX, DX
            if (in->op_count != 2) return RASM_ERR_INVALID_ARGUMENT;
            if (in->ops[0].kind != OP_REG) return RASM_ERR_INVALID_ARGUMENT;
            
            reg_kind acc_reg = in->ops[0].v.reg;
            // Simplified: assume AL for 8-bit, use register checking for proper sizing
            
            if (in->ops[1].kind == OP_IMM) {
                // IN AL/AX/EAX, imm8 (E4/E5)
                if (in->ops[1].v.imm > 0xFF) return RASM_ERR_INVALID_ARGUMENT;
                emit_u8(&unit->text, acc_reg == REG_RAX ? 0xE4 : 0xE5);
                emit_u8(&unit->text, (uint8_t)in->ops[1].v.imm);
            } else if (in->ops[1].kind == OP_REG && in->ops[1].v.reg == REG_RDX) {
                // IN AL/AX/EAX, DX (EC/ED)
                emit_u8(&unit->text, acc_reg == REG_RAX ? 0xEC : 0xED);
            } else {
                return RASM_ERR_INVALID_ARGUMENT;
            }
            return RASM_OK;
        }
        
        case MNEM_OUT: {
            // OUT imm8, AL/AX/EAX or OUT DX, AL/AX/EAX
            if (in->op_count != 2) return RASM_ERR_INVALID_ARGUMENT;
            if (in->ops[1].kind != OP_REG) return RASM_ERR_INVALID_ARGUMENT;
            
            reg_kind acc_reg = in->ops[1].v.reg;
            
            if (in->ops[0].kind == OP_IMM) {
                // OUT imm8, AL/AX/EAX (E6/E7)
                if (in->ops[0].v.imm > 0xFF) return RASM_ERR_INVALID_ARGUMENT;
                emit_u8(&unit->text, acc_reg == REG_RAX ? 0xE6 : 0xE7);
                emit_u8(&unit->text, (uint8_t)in->ops[0].v.imm);
            } else if (in->ops[0].kind == OP_REG && in->ops[0].v.reg == REG_RDX) {
                // OUT DX, AL/AX/EAX (EE/EF)
                emit_u8(&unit->text, acc_reg == REG_RAX ? 0xEE : 0xEF);
            } else {
                return RASM_ERR_INVALID_ARGUMENT;
            }
            return RASM_OK;
        }
        
        // String I/O instructions
        case MNEM_INSB:
            emit_u8(&unit->text, 0x6C);
            return RASM_OK;
        case MNEM_INSW:
            if (unit->arch != ARCH_X86_16) emit_u8(&unit->text, 0x66);
            emit_u8(&unit->text, 0x6D);
            return RASM_OK;
        case MNEM_INSD:
            if (unit->arch == ARCH_X86_16) emit_u8(&unit->text, 0x66);
            emit_u8(&unit->text, 0x6D);
            return RASM_OK;
        case MNEM_OUTSB:
            emit_u8(&unit->text, 0x6E);
            return RASM_OK;
        case MNEM_OUTSW:
            if (unit->arch != ARCH_X86_16) emit_u8(&unit->text, 0x66);
            emit_u8(&unit->text, 0x6F);
            return RASM_OK;
        case MNEM_OUTSD:
            if (unit->arch == ARCH_X86_16) emit_u8(&unit->text, 0x66);
            emit_u8(&unit->text, 0x6F);
            return RASM_OK;
        
        // MOVBE - Move with byte swap
        case MNEM_MOVBE: {
            // MOVBE r16/r32/r64, m16/m32/m64 (0F 38 F0)
            // MOVBE m16/m32/m64, r16/r32/r64 (0F 38 F1)
            if (in->op_count != 2) return RASM_ERR_INVALID_ARGUMENT;
            
            bool reg_first = (in->ops[0].kind == OP_REG);
            const operand *reg_op = reg_first ? &in->ops[0] : &in->ops[1];
            const operand *mem_op = reg_first ? &in->ops[1] : &in->ops[0];
            
            if (reg_op->kind != OP_REG || mem_op->kind != OP_MEM) {
                return RASM_ERR_INVALID_ARGUMENT;
            }
            
            // MOVBE uses 0F 38 F0 (reg <- mem) or 0F 38 F1 (mem <- reg)
            uint8_t opc[] = {0x0F, 0x38, (uint8_t)(reg_first ? 0xF0 : 0xF1)};
            return emit_op_modrm_legacy(NULL, 0, opc, 3, mem_op, reg_code(reg_op->v.reg), true, unit, RELOC_PC32);
        }
        
        // SSE2 Integer Operations (also handles MMX)
        case MNEM_PADDD:
        case MNEM_PADDQ:
        case MNEM_PSUBD:
        case MNEM_PSUBQ:
        case MNEM_PMULUDQ:
        case MNEM_PMULLD:
        case MNEM_PAND:
        case MNEM_POR:
        case MNEM_PXOR:
        case MNEM_PCMPEQD:
        case MNEM_PCMPGTD: {
            // MMX version (MM registers)
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                uint8_t opcode = 0;
                switch (in->mnem) {
                    case MNEM_PADDD: opcode = 0xFE; break;
                    case MNEM_PSUBD: opcode = 0xFA; break;
                    case MNEM_PAND: opcode = 0xDB; break;
                    case MNEM_POR: opcode = 0xEB; break;
                    case MNEM_PXOR: opcode = 0xEF; break;
                    case MNEM_PCMPEQD: opcode = 0x76; break;
                    case MNEM_PCMPGTD: opcode = 0x66; break;
                    default: return RASM_ERR_INVALID_ARGUMENT;
                }
                uint8_t opc[] = {0x0F, opcode};
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            // SSE2 version (XMM registers)
            if (in->op_count != 2 || !is_vec_op(&in->ops[0]) || !(is_vec_op(&in->ops[1]) || is_memop(&in->ops[1]))) return RASM_ERR_INVALID_ARGUMENT;
            if (is_vec_op(&in->ops[1]) && !is_xmmop(&in->ops[1])) return RASM_ERR_INVALID_ARGUMENT;
            if (!is_xmmop(&in->ops[0])) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t opcode = 0;
            uint8_t prefix2 = 0x0F;
            uint8_t prefix3 = 0;
            switch (in->mnem) {
                case MNEM_PADDD: opcode = 0xFE; break;
                case MNEM_PADDQ: opcode = 0xD4; break;
                case MNEM_PSUBD: opcode = 0xFA; break;
                case MNEM_PSUBQ: opcode = 0xFB; break;
                case MNEM_PMULUDQ: opcode = 0xF4; break;
                case MNEM_PMULLD: prefix2 = 0x0F; prefix3 = 0x38; opcode = 0x40; break;
                case MNEM_PAND: opcode = 0xDB; break;
                case MNEM_POR: opcode = 0xEB; break;
                case MNEM_PXOR: opcode = 0xEF; break;
                case MNEM_PCMPEQD: opcode = 0x76; break;
                case MNEM_PCMPGTD: opcode = 0x66; break;
                default: return RASM_ERR_INVALID_ARGUMENT;
            }
            uint8_t pfx[] = {0x66};
            if (prefix3 != 0) {
                uint8_t opc[] = {prefix2, prefix3, opcode};
                return emit_op_modrm_legacy(pfx, 1, opc, 3, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            } else {
                uint8_t opc[] = {prefix2, opcode};
                return emit_op_modrm_legacy(pfx, 1, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
        }
        case MNEM_PSLLQ:
        case MNEM_PSRLQ:
        case MNEM_PSRAQ: {
            // MMX version (MM registers)
            if (in->op_count == 2 && in->ops[0].kind == OP_REG && is_mmx(in->ops[0].v.reg)) {
                // Register or memory operand
                if ((in->ops[1].kind == OP_REG && is_mmx(in->ops[1].v.reg)) || is_memop(&in->ops[1])) {
                    uint8_t opcode = 0;
                    switch (in->mnem) {
                        case MNEM_PSLLQ: opcode = 0xF3; break;
                        case MNEM_PSRLQ: opcode = 0xD3; break;
                        default: return RASM_ERR_INVALID_ARGUMENT;
                    }
                    uint8_t opc[] = {0x0F, opcode};
                    return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
                }
                // Immediate operand
                if (in->ops[1].kind == OP_IMM) {
                    uint8_t ext = 0;
                    uint8_t opcode = 0x73;
                    switch (in->mnem) {
                        case MNEM_PSLLQ: ext = 6; break;
                        case MNEM_PSRLQ: ext = 2; break;
                        default: return RASM_ERR_INVALID_ARGUMENT;
                    }
                    emit_u8(&unit->text, 0x0F);
                    emit_u8(&unit->text, opcode);
                    emit_u8(&unit->text, 0xC0 | (ext << 3) | reg_code(in->ops[0].v.reg));
                    emit_u8(&unit->text, (uint8_t)in->ops[1].v.imm);
                    return RASM_OK;
                }
                return RASM_ERR_INVALID_ARGUMENT;
            }
            // SSE2 version (XMM registers)
            if (in->op_count != 2 || !is_xmmop(&in->ops[0])) return RASM_ERR_INVALID_ARGUMENT;
            if (is_imm8(&in->ops[1])) {
                uint8_t ext = 0;
                uint8_t opcode = 0x73;
                switch (in->mnem) {
                    case MNEM_PSLLQ: ext = 6; break;
                    case MNEM_PSRLQ: ext = 2; break;
                    case MNEM_PSRAQ: ext = 4; opcode = 0x72; break;
                    default: return RASM_ERR_INVALID_ARGUMENT;
                }
                uint8_t pfx[] = {0x66};
                uint8_t opc[] = {0x0F, opcode};
                operand reg_as_rm = {.kind = OP_REG, .v = {.reg = in->ops[0].v.reg}};
                rasm_status st = emit_op_modrm_legacy(pfx, 1, opc, 2, &reg_as_rm, ext, false, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                emit_u8(&unit->text, (uint8_t)in->ops[1].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // AVX Integer Operations
        case MNEM_VPADDD:
        case MNEM_VPADDQ:
        case MNEM_VPSUBD:
        case MNEM_VPSUBQ:
        case MNEM_VPMULUDQ:
        case MNEM_VPMULLD:
        case MNEM_VPAND:
        case MNEM_VPOR:
        case MNEM_VPXOR: {
            if (in->op_count == 3 && is_vec_op(&in->ops[0]) && is_vec_op(&in->ops[1]) && (is_vec_op(&in->ops[2]) || is_memop(&in->ops[2]))) {
                if ((is_xmmop(&in->ops[0]) != is_xmmop(&in->ops[1])) || (is_ymmop(&in->ops[0]) != is_ymmop(&in->ops[1]))) return RASM_ERR_INVALID_ARGUMENT;
                if (is_vec_op(&in->ops[2])) {
                    if ((is_xmmop(&in->ops[0]) != is_xmmop(&in->ops[2])) || (is_ymmop(&in->ops[0]) != is_ymmop(&in->ops[2]))) return RASM_ERR_INVALID_ARGUMENT;
                }
                bool l = is_ymmop(&in->ops[0]);
                uint8_t opcode = 0;
                uint8_t mmmmm = 0x01;
                switch (in->mnem) {
                    case MNEM_VPADDD: opcode = 0xFE; break;
                    case MNEM_VPADDQ: opcode = 0xD4; break;
                    case MNEM_VPSUBD: opcode = 0xFA; break;
                    case MNEM_VPSUBQ: opcode = 0xFB; break;
                    case MNEM_VPMULUDQ: opcode = 0xF4; break;
                    case MNEM_VPMULLD: opcode = 0x40; mmmmm = 0x02; break;
                    case MNEM_VPAND: opcode = 0xDB; break;
                    case MNEM_VPOR: opcode = 0xEB; break;
                    case MNEM_VPXOR: opcode = 0xEF; break;
                    default: return RASM_ERR_INVALID_ARGUMENT;
                }
                uint8_t opc[] = {opcode};
                return emit_vex_modrm(opc, 1, &in->ops[2], reg_code(in->ops[0].v.reg), in->ops[1].v.reg, false, l, 0x01, mmmmm, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // Bit Scan/Test Instructions
        case MNEM_BSF:
        case MNEM_BSR: {
            if (in->op_count != 2) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t opcode = (in->mnem == MNEM_BSF) ? 0xBC : 0xBD;
            uint8_t opc[] = {0x0F, opcode};
            // 64-bit
            if (is_reg64(&in->ops[0]) && (is_reg64(&in->ops[1]) || is_memop(&in->ops[1]))) {
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), true, unit, RELOC_PC32);
            }
            // 32-bit
            if (is_reg32(&in->ops[0]) && (is_reg32(&in->ops[1]) || is_memop(&in->ops[1]))) {
                return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            // 16-bit
            if (is_reg16(&in->ops[0]) && (is_reg16(&in->ops[1]) || is_memop(&in->ops[1]))) {
                uint8_t pfx[1];
                size_t pfx_len = 0;
                if (unit->arch != ARCH_X86_16) pfx[pfx_len++] = 0x66;
                return emit_op_modrm_legacy(pfx, 1, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_BT:
        case MNEM_BTC:
        case MNEM_BTR:
        case MNEM_BTS: {
            if (in->op_count != 2) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t opcode = 0;
            switch (in->mnem) {
                case MNEM_BT: opcode = 0xA3; break;
                case MNEM_BTC: opcode = 0xBB; break;
                case MNEM_BTR: opcode = 0xB3; break;
                case MNEM_BTS: opcode = 0xAB; break;
                default: return RASM_ERR_INVALID_ARGUMENT;
            }
            // Register form
            if (is_reg64(&in->ops[0]) || is_memop(&in->ops[0])) {
                if (is_reg64(&in->ops[1])) {
                    uint8_t opc[] = {0x0F, opcode};
                    return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[0], reg_code(in->ops[1].v.reg), true, unit, RELOC_PC32);
                }
            }
            if (is_reg32(&in->ops[0]) || is_memop(&in->ops[0])) {
                if (is_reg32(&in->ops[1])) {
                    uint8_t opc[] = {0x0F, opcode};
                    return emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[0], reg_code(in->ops[1].v.reg), false, unit, RELOC_PC32);
                }
            }
            if (is_reg16(&in->ops[0]) || is_memop(&in->ops[0])) {
                if (is_reg16(&in->ops[1])) {
                    uint8_t pfx[1];
                    size_t pfx_len = 0;
                    if (unit->arch != ARCH_X86_16) pfx[pfx_len++] = 0x66;
                    uint8_t opc[] = {0x0F, opcode};
                    return emit_op_modrm_legacy(pfx, 1, opc, 2, &in->ops[0], reg_code(in->ops[1].v.reg), false, unit, RELOC_PC32);
                }
            }
            // Immediate form
            if (is_imm8(&in->ops[1])) {
                uint8_t ext = 0;
                switch (in->mnem) {
                    case MNEM_BT: ext = 4; break;
                    case MNEM_BTC: ext = 7; break;
                    case MNEM_BTR: ext = 6; break;
                    case MNEM_BTS: ext = 5; break;
                    default: return RASM_ERR_INVALID_ARGUMENT;
                }
                uint8_t opc[] = {0x0F, 0xBA};
                // 64-bit
                if (is_reg64(&in->ops[0]) || is_memop(&in->ops[0])) {
                    rasm_status st = emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[0], ext, true, unit, RELOC_PC32);
                    if (st != RASM_OK) return st;
                    emit_u8(&unit->text, (uint8_t)in->ops[1].v.imm);
                    return RASM_OK;
                }
                // 32-bit
                if (is_reg32(&in->ops[0])) {
                    rasm_status st = emit_op_modrm_legacy(NULL, 0, opc, 2, &in->ops[0], ext, false, unit, RELOC_PC32);
                    if (st != RASM_OK) return st;
                    emit_u8(&unit->text, (uint8_t)in->ops[1].v.imm);
                    return RASM_OK;
                }
                // 16-bit
                if (is_reg16(&in->ops[0])) {
                    uint8_t pfx[1];
                    size_t pfx_len = 0;
                    if (unit->arch != ARCH_X86_16) pfx[pfx_len++] = 0x66;
                    rasm_status st = emit_op_modrm_legacy(pfx, 1, opc, 2, &in->ops[0], ext, false, unit, RELOC_PC32);
                    if (st != RASM_OK) return st;
                    emit_u8(&unit->text, (uint8_t)in->ops[1].v.imm);
                    return RASM_OK;
                }
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_BSWAP: {
            if (in->op_count != 1) return RASM_ERR_INVALID_ARGUMENT;
            // 64-bit
            if (is_reg64(&in->ops[0])) {
                emit_rex(&unit->text, true, false, false, (reg_code(in->ops[0].v.reg) & 8) != 0, unit->arch);
                emit_u8(&unit->text, 0x0F);
                emit_u8(&unit->text, 0xC8 | (reg_code(in->ops[0].v.reg) & 7));
                return RASM_OK;
            }
            // 32-bit
            if (is_reg32(&in->ops[0])) {
                if ((reg_code(in->ops[0].v.reg) & 8) != 0) {
                    emit_rex(&unit->text, false, false, false, true, unit->arch);
                }
                emit_u8(&unit->text, 0x0F);
                emit_u8(&unit->text, 0xC8 | (reg_code(in->ops[0].v.reg) & 7));
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // BMI/BMI2 Instructions
        case MNEM_LZCNT:
        case MNEM_TZCNT:
        case MNEM_POPCNT: {
            if (in->op_count != 2) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t pfx = 0;
            uint8_t opcode = 0;
            switch (in->mnem) {
                case MNEM_LZCNT: pfx = 0xF3; opcode = 0xBD; break;
                case MNEM_TZCNT: pfx = 0xF3; opcode = 0xBC; break;
                case MNEM_POPCNT: pfx = 0xF3; opcode = 0xB8; break;
                default: return RASM_ERR_INVALID_ARGUMENT;
            }
            uint8_t prefix[] = {pfx};
            uint8_t opc[] = {0x0F, opcode};
            // 64-bit
            if (is_reg64(&in->ops[0]) && (is_reg64(&in->ops[1]) || is_memop(&in->ops[1]))) {
                return emit_op_modrm_legacy(prefix, 1, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), true, unit, RELOC_PC32);
            }
            // 32-bit
            if (is_reg32(&in->ops[0]) && (is_reg32(&in->ops[1]) || is_memop(&in->ops[1]))) {
                return emit_op_modrm_legacy(prefix, 1, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            // 16-bit
            if (is_reg16(&in->ops[0]) && (is_reg16(&in->ops[1]) || is_memop(&in->ops[1]))) {
                uint8_t pfx2[] = {0x66, pfx};
                return emit_op_modrm_legacy(pfx2, 2, opc, 2, &in->ops[1], reg_code(in->ops[0].v.reg), false, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_ANDN:
        case MNEM_PDEP:
        case MNEM_PEXT: {
            if (in->op_count != 3) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t opcode = 0;
            uint8_t mmmmm = 0x02;
            uint8_t pp = 0;
            switch (in->mnem) {
                case MNEM_ANDN: opcode = 0xF2; pp = 0x00; break;
                case MNEM_PDEP: opcode = 0xF5; pp = 0x02; break;
                case MNEM_PEXT: opcode = 0xF5; pp = 0x03; break;
                default: return RASM_ERR_INVALID_ARGUMENT;
            }
            uint8_t opc[] = {opcode};
            // 64-bit
            if (is_reg64(&in->ops[0]) && is_reg64(&in->ops[1]) && (is_reg64(&in->ops[2]) || is_memop(&in->ops[2]))) {
                return emit_vex_modrm(opc, 1, &in->ops[2], reg_code(in->ops[0].v.reg), in->ops[1].v.reg, true, false, pp, mmmmm, unit, RELOC_PC32);
            }
            // 32-bit
            if (is_reg32(&in->ops[0]) && is_reg32(&in->ops[1]) && (is_reg32(&in->ops[2]) || is_memop(&in->ops[2]))) {
                return emit_vex_modrm(opc, 1, &in->ops[2], reg_code(in->ops[0].v.reg), in->ops[1].v.reg, false, false, pp, mmmmm, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_BLSI:
        case MNEM_BLSMSK:
        case MNEM_BLSR: {
            if (in->op_count != 2) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t ext = 0;
            switch (in->mnem) {
                case MNEM_BLSI: ext = 3; break;
                case MNEM_BLSMSK: ext = 2; break;
                case MNEM_BLSR: ext = 1; break;
                default: return RASM_ERR_INVALID_ARGUMENT;
            }
            uint8_t opc[] = {0xF3};
            // 64-bit
            if (is_reg64(&in->ops[0]) && (is_reg64(&in->ops[1]) || is_memop(&in->ops[1]))) {
                return emit_vex_modrm(opc, 1, &in->ops[1], ext, in->ops[0].v.reg, true, false, 0x00, 0x02, unit, RELOC_PC32);
            }
            // 32-bit
            if (is_reg32(&in->ops[0]) && (is_reg32(&in->ops[1]) || is_memop(&in->ops[1]))) {
                return emit_vex_modrm(opc, 1, &in->ops[1], ext, in->ops[0].v.reg, false, false, 0x00, 0x02, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_BEXTR:
        case MNEM_BZHI:
        case MNEM_SARX:
        case MNEM_SHLX:
        case MNEM_SHRX: {
            if (in->op_count != 3) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t opcode = 0;
            uint8_t pp = 0;
            switch (in->mnem) {
                case MNEM_BEXTR: opcode = 0xF7; pp = 0x00; break;
                case MNEM_BZHI: opcode = 0xF5; pp = 0x00; break;
                case MNEM_SARX: opcode = 0xF7; pp = 0x03; break;
                case MNEM_SHLX: opcode = 0xF7; pp = 0x01; break;
                case MNEM_SHRX: opcode = 0xF7; pp = 0x02; break;
                default: return RASM_ERR_INVALID_ARGUMENT;
            }
            uint8_t opc[] = {opcode};
            // 64-bit
            if (is_reg64(&in->ops[0]) && (is_reg64(&in->ops[1]) || is_memop(&in->ops[1])) && is_reg64(&in->ops[2])) {
                return emit_vex_modrm(opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), in->ops[2].v.reg, true, false, pp, 0x02, unit, RELOC_PC32);
            }
            // 32-bit
            if (is_reg32(&in->ops[0]) && (is_reg32(&in->ops[1]) || is_memop(&in->ops[1])) && is_reg32(&in->ops[2])) {
                return emit_vex_modrm(opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), in->ops[2].v.reg, false, false, pp, 0x02, unit, RELOC_PC32);
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        case MNEM_RORX: {
            if (in->op_count != 3) return RASM_ERR_INVALID_ARGUMENT;
            uint8_t opc[] = {0xF0};
            // 64-bit
            if (is_reg64(&in->ops[0]) && (is_reg64(&in->ops[1]) || is_memop(&in->ops[1])) && is_imm8(&in->ops[2])) {
                rasm_status st = emit_vex_modrm(opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), REG_INVALID, true, false, 0x03, 0x03, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                emit_u8(&unit->text, (uint8_t)in->ops[2].v.imm);
                return RASM_OK;
            }
            // 32-bit
            if (is_reg32(&in->ops[0]) && (is_reg32(&in->ops[1]) || is_memop(&in->ops[1])) && is_imm8(&in->ops[2])) {
                rasm_status st = emit_vex_modrm(opc, 1, &in->ops[1], reg_code(in->ops[0].v.reg), REG_INVALID, false, false, 0x03, 0x03, unit, RELOC_PC32);
                if (st != RASM_OK) return st;
                emit_u8(&unit->text, (uint8_t)in->ops[2].v.imm);
                return RASM_OK;
            }
            return RASM_ERR_INVALID_ARGUMENT;
        }
        // String Operations
        case MNEM_MOVSB:
            if (in->op_count != 0) return RASM_ERR_INVALID_ARGUMENT;
            emit_u8(&unit->text, 0xA4);
            return RASM_OK;
        case MNEM_MOVSW:
            if (in->op_count != 0) return RASM_ERR_INVALID_ARGUMENT;
            emit_u8(&unit->text, 0x66);
            emit_u8(&unit->text, 0xA5);
            return RASM_OK;
        case MNEM_MOVSQ:
            if (in->op_count != 0) return RASM_ERR_INVALID_ARGUMENT;
            emit_rex(&unit->text, true, false, false, false, unit->arch);
            emit_u8(&unit->text, 0xA5);
            return RASM_OK;
        case MNEM_STOSB:
            if (in->op_count != 0) return RASM_ERR_INVALID_ARGUMENT;
            emit_u8(&unit->text, 0xAA);
            return RASM_OK;
        case MNEM_STOSW:
            if (in->op_count != 0) return RASM_ERR_INVALID_ARGUMENT;
            emit_u8(&unit->text, 0x66);
            emit_u8(&unit->text, 0xAB);
            return RASM_OK;
        case MNEM_STOSD:
            if (in->op_count != 0) return RASM_ERR_INVALID_ARGUMENT;
            emit_u8(&unit->text, 0xAB);
            return RASM_OK;
        case MNEM_STOSQ:
            if (in->op_count != 0) return RASM_ERR_INVALID_ARGUMENT;
            emit_rex(&unit->text, true, false, false, false, unit->arch);
            emit_u8(&unit->text, 0xAB);
            return RASM_OK;
        case MNEM_LODSB:
            if (in->op_count != 0) return RASM_ERR_INVALID_ARGUMENT;
            emit_u8(&unit->text, 0xAC);
            return RASM_OK;
        case MNEM_LODSW:
            if (in->op_count != 0) return RASM_ERR_INVALID_ARGUMENT;
            emit_u8(&unit->text, 0x66);
            emit_u8(&unit->text, 0xAD);
            return RASM_OK;
        case MNEM_LODSD:
            if (in->op_count != 0) return RASM_ERR_INVALID_ARGUMENT;
            emit_u8(&unit->text, 0xAD);
            return RASM_OK;
        case MNEM_LODSQ:
            if (in->op_count != 0) return RASM_ERR_INVALID_ARGUMENT;
            emit_rex(&unit->text, true, false, false, false, unit->arch);
            emit_u8(&unit->text, 0xAD);
            return RASM_OK;
        case MNEM_SCASB:
            if (in->op_count != 0) return RASM_ERR_INVALID_ARGUMENT;
            emit_u8(&unit->text, 0xAE);
            return RASM_OK;
        case MNEM_SCASW:
            if (in->op_count != 0) return RASM_ERR_INVALID_ARGUMENT;
            emit_u8(&unit->text, 0x66);
            emit_u8(&unit->text, 0xAF);
            return RASM_OK;
        case MNEM_SCASD:
            if (in->op_count != 0) return RASM_ERR_INVALID_ARGUMENT;
            emit_u8(&unit->text, 0xAF);
            return RASM_OK;
        case MNEM_SCASQ:
            if (in->op_count != 0) return RASM_ERR_INVALID_ARGUMENT;
            emit_rex(&unit->text, true, false, false, false, unit->arch);
            emit_u8(&unit->text, 0xAF);
            return RASM_OK;
        case MNEM_CMPSB:
            if (in->op_count != 0) return RASM_ERR_INVALID_ARGUMENT;
            emit_u8(&unit->text, 0xA6);
            return RASM_OK;
        case MNEM_CMPSW:
            if (in->op_count != 0) return RASM_ERR_INVALID_ARGUMENT;
            emit_u8(&unit->text, 0x66);
            emit_u8(&unit->text, 0xA7);
            return RASM_OK;
        case MNEM_CMPSQ:
            if (in->op_count != 0) return RASM_ERR_INVALID_ARGUMENT;
            emit_rex(&unit->text, true, false, false, false, unit->arch);
            emit_u8(&unit->text, 0xA7);
            return RASM_OK;
        case MNEM_REP:
        case MNEM_REPE:
        case MNEM_REPNE:
        case MNEM_LOCK:
            // Prefixes are handled in prefix parsing, not encoding
            return RASM_OK;
        default:
            return RASM_ERR_INVALID_ARGUMENT;
    }
}

static rasm_status encode_data_item(const data_item *d, asm_unit *unit, uint64_t data_off) {
    switch (d->value.kind) {
        case OP_IMM: {
            uint64_t v = d->value.v.imm;
            size_t w = width_bytes(d->width);
            for (size_t i = 0; i < w; ++i) emit_u8(&unit->data, (uint8_t)((v >> (i * 8)) & 0xFF));
            break;
        }
        case OP_SYMBOL: {
            size_t w = width_bytes(d->width);
            for (size_t i = 0; i < w; ++i) emit_u8(&unit->data, 0);
            relocation r = { .kind = w == 8 ? RELOC_ABS64 : RELOC_ABS32, .symbol = d->value.v.sym, .offset = data_off, .addend = 0 };
            VEC_PUSH(unit->data_relocs, r);
            break;
        }
        case OP_EXPR: {
            // Try to evaluate expression
            int64_t val;
            const char *unresolved = NULL;
            if (eval_expression(d->value.v.expr, unit, &val, &unresolved)) {
                // Expression evaluated to constant
                size_t w = width_bytes(d->width);
                for (size_t i = 0; i < w; ++i) emit_u8(&unit->data, (uint8_t)(((uint64_t)val >> (i * 8)) & 0xFF));
            } else {
                // Expression has unresolved symbols - can't handle in data section yet
                fprintf(stderr, "encode error line %zu: unresolved symbol '%s' in data expression\n", d->line, unresolved ? unresolved : "?");
                return RASM_ERR_INVALID_ARGUMENT;
            }
            break;
        }
        default:
            fprintf(stderr, "encode error line %zu: invalid data operand\n", d->line);
            return RASM_ERR_INVALID_ARGUMENT;
    }
    return RASM_OK;
}

static rasm_status second_pass_encode(asm_unit *unit, FILE *log) {
    uint64_t off_text = unit->text.len;
    uint64_t off_data = unit->data.len;
    uint64_t off_bss = 0;
    for (size_t i = 0; i < unit->stmts.len; ++i) {
        statement *st = &unit->stmts.data[i];
        switch (st->kind) {
            case STMT_LABEL:
                // already handled
                break;
            case STMT_INSTR: {
                if (st->section != SEC_TEXT) {
                    if (log) fprintf(log, "encode error line %zu: instructions only allowed in .text\n", st->v.instr.line);
                    return RASM_ERR_INVALID_ARGUMENT;
                }
                // Validate register sizes for two-operand instructions (except CRC32 which allows mixed sizes)
                if (st->v.instr.op_count == 2 && st->v.instr.mnem != MNEM_CRC32) {
                    if (!validate_reg_sizes(&st->v.instr.ops[0], &st->v.instr.ops[1], log, st->v.instr.line)) {
                        return RASM_ERR_INVALID_ARGUMENT;
                    }
                }
                rasm_status enc = encode_instr(&st->v.instr, unit);
                if (enc != RASM_OK) return enc;
                off_text = unit->text.len;
                break;
            }
            case STMT_DATA: {
                rasm_status enc;
                if (st->section == SEC_TEXT) {
                    enc = encode_data_item(&st->v.data, unit, off_text);
                    if (enc != RASM_OK) return enc;
                    off_text = unit->text.len;
                } else {
                    enc = encode_data_item(&st->v.data, unit, off_data);
                    if (enc != RASM_OK) return enc;
                    off_data = unit->data.len;
                }
                break;
            }
            case STMT_RESERVE:
                if (st->section == SEC_TEXT) {
                    size_t bytes = st->v.res.count * width_bytes(st->v.res.width);
                    for (size_t j = 0; j < bytes; ++j) emit_u8(&unit->text, 0);
                    off_text = unit->text.len;
                    break;
                }
                if (st->section == SEC_DATA) {
                    size_t bytes = st->v.res.count * width_bytes(st->v.res.width);
                    for (size_t j = 0; j < bytes; ++j) emit_u8(&unit->data, 0);
                    off_data = unit->data.len;
                } else if (st->section == SEC_BSS) {
                    off_bss += st->v.res.count * width_bytes(st->v.res.width);
                } else {
                    if (log) fprintf(log, "encode error line %zu: reserve allowed only in .text/.data/.bss\n", st->v.res.line);
                    return RASM_ERR_INVALID_ARGUMENT;
                }
                // bss handled via size only
                break;
            case STMT_ALIGN: {
                size_t a = st->v.align.align;
                if (a == 0) break;
                if (st->section == SEC_TEXT) {
                    uint64_t new_off = align_up(off_text, a);
                    while (off_text < new_off) { emit_u8(&unit->text, 0x90); off_text++; }
                    off_text = unit->text.len;
                } else if (st->section == SEC_DATA) {
                    uint64_t new_off = align_up(off_data, a);
                    while (off_data < new_off) { emit_u8(&unit->data, 0); off_data++; }
                    off_data = unit->data.len;
                } else if (st->section == SEC_BSS) {
                    off_bss = align_up(off_bss, a);
                }
                break;
            }
            case STMT_TIMES: {
                // Evaluate the expression with current position
                const char *unresolved = NULL;
                int64_t count_val = 0;
                if (!eval_expression(st->v.times.count_expr, unit, &count_val, &unresolved)) {
                    if (log) {
                        fprintf(log, "error line %zu: cannot evaluate times count expression", st->v.times.line);
                        if (unresolved) fprintf(log, " (unresolved symbol: %s)", unresolved);
                        fprintf(log, "\n");
                    }
                    return RASM_ERR_INVALID_ARGUMENT;
                }
                if (count_val <= 0) {
                    if (log) fprintf(log, "error line %zu: times count must be positive (got %lld)\n", st->v.times.line, (long long)count_val);
                    return RASM_ERR_INVALID_ARGUMENT;
                }
                
                if (st->v.times.kind == TIMES_DATA) {
                    // Emit the data value count_val times
                    for (int64_t j = 0; j < count_val; j++) {
                        data_item di = { .width = st->v.times.u.data.width, .value = st->v.times.u.data.value, .line = st->v.times.line };
                        rasm_status enc;
                        if (st->section == SEC_TEXT) {
                            enc = encode_data_item(&di, unit, off_text);
                            if (enc != RASM_OK) return enc;
                            off_text = unit->text.len;
                        } else {
                            enc = encode_data_item(&di, unit, off_data);
                            if (enc != RASM_OK) return enc;
                            off_data = unit->data.len;
                        }
                    }
                } else { // TIMES_INSTR
                    // Emit the instruction count_val times
                    for (int64_t j = 0; j < count_val; j++) {
                        rasm_status enc = encode_instr(&st->v.times.u.instr, unit);
                        if (enc != RASM_OK) {
                            if (log) fprintf(log, "encode error line %zu: failed to encode instruction\n", st->v.times.line);
                            return enc;
                        }
                        if (st->section == SEC_TEXT) {
                            off_text = unit->text.len;
                        } else {
                            off_data = unit->data.len;
                        }
                    }
                }
                break;
            }
        }
    }
    return RASM_OK;
}

typedef struct {
    VEC(uint8_t) buf;
} bin_writer;

static void bw_emit(bin_writer *bw, const void *data, size_t n) {
    vec_reserve_raw((void**)&bw->buf.data, &bw->buf.cap, sizeof(uint8_t), bw->buf.len + n);
    memcpy(bw->buf.data + bw->buf.len, data, n);
    bw->buf.len += n;
}

static void bw_pad(bin_writer *bw, size_t align) {
    size_t pad = (align - (bw->buf.len % align)) % align;
    for (size_t i = 0; i < pad; ++i) VEC_PUSH(bw->buf, 0);
}

static void bw_emit_u8(bin_writer *bw, uint8_t val) {
    bw_emit(bw, &val, 1);
}

static void bw_emit_u16(bin_writer *bw, uint16_t val) {
    bw_emit(bw, &val, 2);
}

static void bw_emit_u32(bin_writer *bw, uint32_t val) {
    bw_emit(bw, &val, 4);
}

static void bw_emit_u64(bin_writer *bw, uint64_t val) {
    bw_emit(bw, &val, 8);
}

typedef struct {
    size_t sh_text;
    size_t sh_data;
    size_t sh_bss;
    size_t sh_rela_text;
    size_t sh_rela_data;
    size_t sh_note_gnu_stack;
    size_t sh_debug_line;
    size_t sh_debug_info;
    size_t sh_debug_abbrev;
    size_t sh_symtab;
    size_t sh_strtab;
    size_t sh_shstrtab;
} section_indices;

static size_t add_str(VEC(uint8_t) *strtab, const char *s) {
    size_t off = strtab->len;
    size_t len = strlen(s);
    vec_reserve_raw((void**)&strtab->data, &strtab->cap, sizeof(uint8_t), strtab->len + len + 1);
    memcpy(strtab->data + strtab->len, s, len + 1);
    strtab->len += len + 1;
    return off;
}

static uint8_t elf_info_bind(bool global) { return (global ? STB_GLOBAL : STB_LOCAL) << 4; }

static void append_sym(VEC(Elf64_Sym) *syms, uint32_t name_off, uint8_t info, uint16_t shndx, uint64_t value, uint64_t size) {
    Elf64_Sym s = {0};
    s.st_name = name_off;
    s.st_info = info;
    s.st_other = 0;
    s.st_shndx = shndx;
    s.st_value = value;
    s.st_size = size;
    VEC_PUSH(*syms, s);
}

static uint32_t reloc_type_elf(reloc_kind k) {
    switch (k) {
        case RELOC_ABS32: return R_X86_64_32;
        case RELOC_ABS64: return R_X86_64_64;
        case RELOC_PC32: return R_X86_64_PC32;
        case RELOC_PLT32: return R_X86_64_PLT32;
        default: return 0;
    }
}

static uint16_t section_index_for(section_kind k, const section_indices *idx) {
    switch (k) {
        case SEC_TEXT: return (uint16_t)idx->sh_text;
        case SEC_DATA: return (uint16_t)idx->sh_data;
        case SEC_BSS: return (uint16_t)idx->sh_bss;
        case SEC_ABS: return SHN_ABS;  // Absolute symbols
    }
    return 0;
}

// Check for undefined symbols (excluding externs)
static rasm_status check_undefined_symbols(const asm_unit *unit, FILE *log) {
    bool has_undefined = false;
    
    // Check all symbol references in relocations
    for (size_t i = 0; i < unit->text_relocs.len; ++i) {
        const char *sym_name = unit->text_relocs.data[i].symbol;
        const symbol *sym = find_symbol(unit, sym_name);
        
        if (!sym || (!sym->is_defined && !sym->is_extern)) {
            if (!has_undefined && log) {
                fprintf(log, "error: undefined symbols:\n");
            }
            has_undefined = true;
            if (log) fprintf(log, "  %s\n", sym_name);
        }
    }
    
    for (size_t i = 0; i < unit->data_relocs.len; ++i) {
        const char *sym_name = unit->data_relocs.data[i].symbol;
        const symbol *sym = find_symbol(unit, sym_name);
        
        if (!sym || (!sym->is_defined && !sym->is_extern)) {
            if (!has_undefined && log) {
                fprintf(log, "error: undefined symbols:\n");
            }
            has_undefined = true;
            if (log) fprintf(log, "  %s\n", sym_name);
        }
    }
    
    return has_undefined ? RASM_ERR_INVALID_ARGUMENT : RASM_OK;
}

static rasm_status write_elf64(const asm_unit *unit, FILE *out, FILE *log) {
    (void)log;
    bin_writer bw = {0};
    VEC(uint8_t) shstr = {0};
    VEC(uint8_t) strtab = {0};
    VEC(Elf64_Sym) syms = {0};
    size_t *sym_indices = NULL;
    if (unit->symbols.len) {
        sym_indices = calloc(unit->symbols.len, sizeof(size_t));
        if (!sym_indices) return RASM_ERR_IO;
    }

    // strtabs start with NUL
    VEC_PUSH(shstr, 0);
    VEC_PUSH(strtab, 0);

    section_indices idx = {0};
    idx.sh_text = 1;
    idx.sh_rela_text = 2;
    idx.sh_data = 3;
    idx.sh_rela_data = 4;
    idx.sh_bss = 5;
    idx.sh_note_gnu_stack = 6;
    idx.sh_debug_line = 7;
    idx.sh_debug_info = 8;
    idx.sh_debug_abbrev = 9;
    idx.sh_symtab = 10;
    idx.sh_strtab = 11;
    idx.sh_shstrtab = 12;

    size_t off_text_name = add_str(&shstr, ".text");
    size_t off_rela_text_name = add_str(&shstr, ".rela.text");
    size_t off_data_name = add_str(&shstr, ".data");
    size_t off_rela_data_name = add_str(&shstr, ".rela.data");
    size_t off_bss_name = add_str(&shstr, ".bss");
    size_t off_note_gnu_stack_name = add_str(&shstr, ".note.GNU-stack");
    size_t off_debug_line_name = add_str(&shstr, ".debug_line");
    size_t off_debug_info_name = add_str(&shstr, ".debug_info");
    size_t off_debug_abbrev_name = add_str(&shstr, ".debug_abbrev");
    size_t off_symtab_name = add_str(&shstr, ".symtab");
    size_t off_strtab_name = add_str(&shstr, ".strtab");
    size_t off_shstr_name = add_str(&shstr, ".shstrtab");

    // symbols: first null
    append_sym(&syms, 0, 0, SHN_UNDEF, 0, 0);
    size_t local_count = 1; // includes null
    // locals first
    for (size_t i = 0; i < unit->symbols.len; ++i) {
        const symbol *s = &unit->symbols.data[i];
        bool glob = s->is_global || s->is_extern;
        if (glob) continue;
        uint32_t name_off = (uint32_t)add_str(&strtab, s->name);
        uint16_t shndx = s->is_defined ? section_index_for(s->section, &idx) : SHN_UNDEF;
        append_sym(&syms, name_off, elf_info_bind(false), shndx, s->value, 0);
        sym_indices[i] = syms.len - 1;
        local_count++;
    }
    // globals next
    for (size_t i = 0; i < unit->symbols.len; ++i) {
        const symbol *s = &unit->symbols.data[i];
        bool glob = s->is_global || s->is_extern;
        if (!glob) continue;
        uint32_t name_off = (uint32_t)add_str(&strtab, s->name);
        uint16_t shndx = s->is_defined ? section_index_for(s->section, &idx) : SHN_UNDEF;
        append_sym(&syms, name_off, elf_info_bind(true), shndx, s->value, 0);
        sym_indices[i] = syms.len - 1;
    }

    // begin writing file
    Elf64_Ehdr eh = {0};
    memset(eh.e_ident, 0, EI_NIDENT);
    eh.e_ident[EI_MAG0] = ELFMAG0;
    eh.e_ident[EI_MAG1] = ELFMAG1;
    eh.e_ident[EI_MAG2] = ELFMAG2;
    eh.e_ident[EI_MAG3] = ELFMAG3;
    eh.e_ident[EI_CLASS] = ELFCLASS64;
    eh.e_ident[EI_DATA] = ELFDATA2LSB;
    eh.e_ident[EI_VERSION] = EV_CURRENT;
    eh.e_type = ET_REL;
    eh.e_machine = EM_X86_64;
    eh.e_version = EV_CURRENT;
    eh.e_ehsize = sizeof(Elf64_Ehdr);
    eh.e_shentsize = sizeof(Elf64_Shdr);
    eh.e_shnum = 13;
    eh.e_shstrndx = (Elf64_Half)idx.sh_shstrtab;

    bw_emit(&bw, &eh, sizeof(eh));

    // .text
    bw_pad(&bw, 16);
    Elf64_Off text_off = bw.buf.len;
    bw_emit(&bw, unit->text.data, unit->text.len);

    // .rela.text
    bw_pad(&bw, 8);
    Elf64_Off rela_text_off = bw.buf.len;
    for (size_t i = 0; i < unit->text_relocs.len; ++i) {
        relocation r = unit->text_relocs.data[i];
        Elf64_Rela rela = {0};
        int sym_index = -1;
        for (size_t j = 0; j < unit->symbols.len; ++j) {
            if (strcmp(unit->symbols.data[j].name, r.symbol) == 0) {
                sym_index = (int)sym_indices[j];
                break;
            }
        }
        if (sym_index < 0) {
            // Undefined symbol referenced in relocation - add as global undefined
            sym_index = (int)syms.len;
            uint32_t noff = (uint32_t)add_str(&strtab, r.symbol);
            append_sym(&syms, noff, elf_info_bind(true), SHN_UNDEF, 0, 0); // Global bind for undefined
        }
        rela.r_offset = r.offset;
        rela.r_info = ELF64_R_INFO((Elf64_Xword)sym_index, reloc_type_elf(r.kind));
        rela.r_addend = r.addend;
        bw_emit(&bw, &rela, sizeof(rela));
    }
    size_t rela_text_size = unit->text_relocs.len * sizeof(Elf64_Rela);

    // .data
    bw_pad(&bw, 16);
    Elf64_Off data_off = bw.buf.len;
    bw_emit(&bw, unit->data.data, unit->data.len);

    // .rela.data
    bw_pad(&bw, 8);
    Elf64_Off rela_data_off = bw.buf.len;
    for (size_t i = 0; i < unit->data_relocs.len; ++i) {
        relocation r = unit->data_relocs.data[i];
        Elf64_Rela rela = {0};
        int sym_index = -1;
        for (size_t j = 0; j < unit->symbols.len; ++j) {
            if (strcmp(unit->symbols.data[j].name, r.symbol) == 0) {
                sym_index = (int)sym_indices[j];
                break;
            }
        }
        if (sym_index < 0) {
            // Undefined symbol referenced in relocation - add as global undefined
            sym_index = (int)syms.len;
            uint32_t noff = (uint32_t)add_str(&strtab, r.symbol);
            append_sym(&syms, noff, elf_info_bind(true), SHN_UNDEF, 0, 0); // Global bind for undefined
        }
        rela.r_offset = r.offset;
        rela.r_info = ELF64_R_INFO((Elf64_Xword)sym_index, reloc_type_elf(r.kind));
        rela.r_addend = r.addend;
        bw_emit(&bw, &rela, sizeof(rela));
    }
    size_t rela_data_size = unit->data_relocs.len * sizeof(Elf64_Rela);

    // Build .debug_line section (DWARF line number program)
    bw_pad(&bw, 4);
    Elf64_Off debug_line_off = bw.buf.len;
    bin_writer dbg_line = {0};
    
    // Line number program header
    uint32_t unit_length_pos = (uint32_t)dbg_line.buf.len;
    bw_emit_u32(&dbg_line, 0); // Placeholder for unit_length
    bw_emit_u16(&dbg_line, 2); // DWARF version 2
    uint32_t header_length_pos = (uint32_t)dbg_line.buf.len;
    bw_emit_u32(&dbg_line, 0); // Placeholder for header_length
    bw_emit_u8(&dbg_line, 1); // minimum_instruction_length
    bw_emit_u8(&dbg_line, 1); // default_is_stmt
    bw_emit_u8(&dbg_line, 1); // line_base
    bw_emit_u8(&dbg_line, 1); // line_range
    bw_emit_u8(&dbg_line, 10); // opcode_base (standard opcodes 1-9)
    
    // Standard opcode lengths (for opcodes 1-9)
    bw_emit_u8(&dbg_line, 0); // DW_LNS_copy
    bw_emit_u8(&dbg_line, 1); // DW_LNS_advance_pc
    bw_emit_u8(&dbg_line, 1); // DW_LNS_advance_line
    bw_emit_u8(&dbg_line, 1); // DW_LNS_set_file
    bw_emit_u8(&dbg_line, 1); // DW_LNS_set_column
    bw_emit_u8(&dbg_line, 0); // DW_LNS_negate_stmt
    bw_emit_u8(&dbg_line, 0); // DW_LNS_set_basic_block
    bw_emit_u8(&dbg_line, 0); // DW_LNS_const_add_pc
    bw_emit_u8(&dbg_line, 1); // DW_LNS_fixed_advance_pc
    
    // Include directory table (empty, terminated by 0)
    bw_emit_u8(&dbg_line, 0);
    
    // File name table (one file: "input.asm")
    const char *filename = "input.asm";
    for (const char *p = filename; *p; p++) bw_emit_u8(&dbg_line, (uint8_t)*p);
    bw_emit_u8(&dbg_line, 0);
    bw_emit_u8(&dbg_line, 0); // directory index (0 = current)
    bw_emit_u8(&dbg_line, 0); // last modification time
    bw_emit_u8(&dbg_line, 0); // file length
    bw_emit_u8(&dbg_line, 0); // End of file name table
    
    uint32_t header_length = (uint32_t)(dbg_line.buf.len - header_length_pos - 4);
    memcpy(dbg_line.buf.data + header_length_pos, &header_length, 4);
    
    // Line number program: emit DW_LNE_set_address and DW_LNS_advance_line for each instruction
    uint64_t current_line = 1;
    uint64_t current_addr = 0;
    
    for (size_t i = 0; i < unit->stmts.len; ++i) {
        const statement *st = &unit->stmts.data[i];
        if (st->kind != STMT_INSTR || st->section != SEC_TEXT) continue;
        
        uint64_t line = st->v.instr.line;
        if (line == 0) line = 1;
        
        // DW_LNE_set_address (extended opcode)
        bw_emit_u8(&dbg_line, 0); // Extended opcode
        bw_emit_u8(&dbg_line, 9); // Length (1 + 8 for address)
        bw_emit_u8(&dbg_line, 2); // DW_LNE_set_address
        bw_emit_u64(&dbg_line, current_addr);
        
        // DW_LNS_advance_line
        if (line != current_line) {
            bw_emit_u8(&dbg_line, 3); // DW_LNS_advance_line
            int64_t line_delta = (int64_t)line - (int64_t)current_line;
            // Simple SLEB128 encoding for small values
            if (line_delta >= -64 && line_delta < 64) {
                bw_emit_u8(&dbg_line, (uint8_t)(line_delta & 0x7F));
            } else {
                bw_emit_u8(&dbg_line, (uint8_t)((line_delta & 0x7F) | 0x80));
                bw_emit_u8(&dbg_line, (uint8_t)((line_delta >> 7) & 0x7F));
            }
            current_line = line;
        }
        
        // DW_LNS_copy
        bw_emit_u8(&dbg_line, 1);
        
        current_addr += 16; // Approximate instruction size
    }
    
    // DW_LNE_end_sequence
    bw_emit_u8(&dbg_line, 0); // Extended opcode
    bw_emit_u8(&dbg_line, 1); // Length
    bw_emit_u8(&dbg_line, 1); // DW_LNE_end_sequence
    
    uint32_t unit_length = (uint32_t)(dbg_line.buf.len - unit_length_pos - 4);
    memcpy(dbg_line.buf.data + unit_length_pos, &unit_length, 4);
    
    bw_emit(&bw, dbg_line.buf.data, dbg_line.buf.len);
    size_t debug_line_size = dbg_line.buf.len;

    // Minimal .debug_info section
    bw_pad(&bw, 4);
    Elf64_Off debug_info_off = bw.buf.len;
    bin_writer dbg_info = {0};
    bw_emit_u32(&dbg_info, 0); // unit_length placeholder
    uint32_t info_start = (uint32_t)dbg_info.buf.len;
    bw_emit_u16(&dbg_info, 2); // DWARF version 2
    bw_emit_u32(&dbg_info, 0); // debug_abbrev_offset
    bw_emit_u8(&dbg_info, 8); // address_size
    bw_emit_u8(&dbg_info, 1); // abbrev code 1 (DW_TAG_compile_unit)
    // DW_AT_stmt_list (offset into .debug_line)
    bw_emit_u32(&dbg_info, 0);
    bw_emit_u8(&dbg_info, 0); // End of DIEs
    uint32_t info_length = (uint32_t)dbg_info.buf.len - info_start;
    memcpy(dbg_info.buf.data, &info_length, 4);
    bw_emit(&bw, dbg_info.buf.data, dbg_info.buf.len);
    size_t debug_info_size = dbg_info.buf.len;

    // Minimal .debug_abbrev section
    bw_pad(&bw, 1);
    Elf64_Off debug_abbrev_off = bw.buf.len;
    bin_writer dbg_abbrev = {0};
    bw_emit_u8(&dbg_abbrev, 1); // abbrev code
    bw_emit_u8(&dbg_abbrev, 0x11); // DW_TAG_compile_unit
    bw_emit_u8(&dbg_abbrev, 0); // DW_CHILDREN_no
    bw_emit_u8(&dbg_abbrev, 0x10); // DW_AT_stmt_list
    bw_emit_u8(&dbg_abbrev, 0x06); // DW_FORM_data4
    bw_emit_u8(&dbg_abbrev, 0); // End of attributes
    bw_emit_u8(&dbg_abbrev, 0);
    bw_emit_u8(&dbg_abbrev, 0); // End of abbreviations
    bw_emit(&bw, dbg_abbrev.buf.data, dbg_abbrev.buf.len);
    size_t debug_abbrev_size = dbg_abbrev.buf.len;

    // .symtab
    bw_pad(&bw, 8);
    Elf64_Off symtab_off = bw.buf.len;
    for (size_t i = 0; i < syms.len; ++i) {
        bw_emit(&bw, &syms.data[i], sizeof(Elf64_Sym));
    }
    size_t symtab_size = syms.len * sizeof(Elf64_Sym);

    // .strtab
    bw_pad(&bw, 1);
    Elf64_Off strtab_off = bw.buf.len;
    bw_emit(&bw, strtab.data, strtab.len);
    size_t strtab_size = strtab.len;

    // .shstrtab
    bw_pad(&bw, 1);
    Elf64_Off shstr_off = bw.buf.len;
    bw_emit(&bw, shstr.data, shstr.len);
    size_t shstr_size = shstr.len;

    // section headers
    bw_pad(&bw, 8);
    eh.e_shoff = bw.buf.len;

    Elf64_Shdr sh_null = {0};
    bw_emit(&bw, &sh_null, sizeof(sh_null));

    Elf64_Shdr sh_text = {0};
    sh_text.sh_name = (Elf64_Word)off_text_name;
    sh_text.sh_type = SHT_PROGBITS;
    sh_text.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    sh_text.sh_addr = 0;
    sh_text.sh_offset = text_off;
    sh_text.sh_size = unit->text.len;
    sh_text.sh_link = 0;
    sh_text.sh_info = 0;
    sh_text.sh_addralign = 16;
    sh_text.sh_entsize = 0;
    bw_emit(&bw, &sh_text, sizeof(sh_text));

    Elf64_Shdr sh_rela_text = {0};
    sh_rela_text.sh_name = (Elf64_Word)off_rela_text_name;
    sh_rela_text.sh_type = SHT_RELA;
    sh_rela_text.sh_flags = SHF_INFO_LINK;
    sh_rela_text.sh_addr = 0;
    sh_rela_text.sh_offset = rela_text_off;
    sh_rela_text.sh_size = rela_text_size;
    sh_rela_text.sh_link = idx.sh_symtab;
    sh_rela_text.sh_info = idx.sh_text;
    sh_rela_text.sh_addralign = 8;
    sh_rela_text.sh_entsize = sizeof(Elf64_Rela);
    bw_emit(&bw, &sh_rela_text, sizeof(sh_rela_text));

    Elf64_Shdr sh_data = {0};
    sh_data.sh_name = (Elf64_Word)off_data_name;
    sh_data.sh_type = SHT_PROGBITS;
    sh_data.sh_flags = SHF_ALLOC | SHF_WRITE;
    sh_data.sh_addr = 0;
    sh_data.sh_offset = data_off;
    sh_data.sh_size = unit->data.len;
    sh_data.sh_link = 0;
    sh_data.sh_info = 0;
    sh_data.sh_addralign = 8;
    sh_data.sh_entsize = 0;
    bw_emit(&bw, &sh_data, sizeof(sh_data));

    Elf64_Shdr sh_rela_data = {0};
    sh_rela_data.sh_name = (Elf64_Word)off_rela_data_name;
    sh_rela_data.sh_type = SHT_RELA;
    sh_rela_data.sh_flags = SHF_INFO_LINK;
    sh_rela_data.sh_addr = 0;
    sh_rela_data.sh_offset = rela_data_off;
    sh_rela_data.sh_size = rela_data_size;
    sh_rela_data.sh_link = idx.sh_symtab;
    sh_rela_data.sh_info = idx.sh_data;
    sh_rela_data.sh_addralign = 8;
    sh_rela_data.sh_entsize = sizeof(Elf64_Rela);
    bw_emit(&bw, &sh_rela_data, sizeof(sh_rela_data));

    Elf64_Shdr sh_bss = {0};
    sh_bss.sh_name = (Elf64_Word)off_bss_name;
    sh_bss.sh_type = SHT_NOBITS;
    sh_bss.sh_flags = SHF_ALLOC | SHF_WRITE;
    sh_bss.sh_addr = 0;
    sh_bss.sh_offset = data_off + unit->data.len;
    sh_bss.sh_size = unit->bss_size;
    sh_bss.sh_link = 0;
    sh_bss.sh_info = 0;
    sh_bss.sh_addralign = 8;
    sh_bss.sh_entsize = 0;
    bw_emit(&bw, &sh_bss, sizeof(sh_bss));

    Elf64_Shdr sh_note_gnu_stack = {0};
    sh_note_gnu_stack.sh_name = (Elf64_Word)off_note_gnu_stack_name;
    sh_note_gnu_stack.sh_type = SHT_PROGBITS;
    sh_note_gnu_stack.sh_flags = 0; // not alloc, marks non-exec stack
    sh_note_gnu_stack.sh_addr = 0;
    sh_note_gnu_stack.sh_offset = bw.buf.len; // no payload
    sh_note_gnu_stack.sh_size = 0;
    sh_note_gnu_stack.sh_link = 0;
    sh_note_gnu_stack.sh_info = 0;
    sh_note_gnu_stack.sh_addralign = 1;
    sh_note_gnu_stack.sh_entsize = 0;
    bw_emit(&bw, &sh_note_gnu_stack, sizeof(sh_note_gnu_stack));

    Elf64_Shdr sh_debug_line = {0};
    sh_debug_line.sh_name = (Elf64_Word)off_debug_line_name;
    sh_debug_line.sh_type = SHT_PROGBITS;
    sh_debug_line.sh_flags = 0;
    sh_debug_line.sh_addr = 0;
    sh_debug_line.sh_offset = debug_line_off;
    sh_debug_line.sh_size = debug_line_size;
    sh_debug_line.sh_link = 0;
    sh_debug_line.sh_info = 0;
    sh_debug_line.sh_addralign = 1;
    sh_debug_line.sh_entsize = 0;
    bw_emit(&bw, &sh_debug_line, sizeof(sh_debug_line));

    Elf64_Shdr sh_debug_info = {0};
    sh_debug_info.sh_name = (Elf64_Word)off_debug_info_name;
    sh_debug_info.sh_type = SHT_PROGBITS;
    sh_debug_info.sh_flags = 0;
    sh_debug_info.sh_addr = 0;
    sh_debug_info.sh_offset = debug_info_off;
    sh_debug_info.sh_size = debug_info_size;
    sh_debug_info.sh_link = 0;
    sh_debug_info.sh_info = 0;
    sh_debug_info.sh_addralign = 1;
    sh_debug_info.sh_entsize = 0;
    bw_emit(&bw, &sh_debug_info, sizeof(sh_debug_info));

    Elf64_Shdr sh_debug_abbrev = {0};
    sh_debug_abbrev.sh_name = (Elf64_Word)off_debug_abbrev_name;
    sh_debug_abbrev.sh_type = SHT_PROGBITS;
    sh_debug_abbrev.sh_flags = 0;
    sh_debug_abbrev.sh_addr = 0;
    sh_debug_abbrev.sh_offset = debug_abbrev_off;
    sh_debug_abbrev.sh_size = debug_abbrev_size;
    sh_debug_abbrev.sh_link = 0;
    sh_debug_abbrev.sh_info = 0;
    sh_debug_abbrev.sh_addralign = 1;
    sh_debug_abbrev.sh_entsize = 0;
    bw_emit(&bw, &sh_debug_abbrev, sizeof(sh_debug_abbrev));

    Elf64_Shdr sh_symtab = {0};
    sh_symtab.sh_name = (Elf64_Word)off_symtab_name;
    sh_symtab.sh_type = SHT_SYMTAB;
    sh_symtab.sh_flags = 0;
    sh_symtab.sh_addr = 0;
    sh_symtab.sh_offset = symtab_off;
    sh_symtab.sh_size = symtab_size;
    sh_symtab.sh_link = idx.sh_strtab;
    sh_symtab.sh_info = (Elf64_Word)local_count; // index of first global symbol
    sh_symtab.sh_addralign = 8;
    sh_symtab.sh_entsize = sizeof(Elf64_Sym);
    bw_emit(&bw, &sh_symtab, sizeof(sh_symtab));

    Elf64_Shdr sh_strtab = {0};
    sh_strtab.sh_name = (Elf64_Word)off_strtab_name;
    sh_strtab.sh_type = SHT_STRTAB;
    sh_strtab.sh_flags = 0;
    sh_strtab.sh_addr = 0;
    sh_strtab.sh_offset = strtab_off;
    sh_strtab.sh_size = strtab_size;
    sh_strtab.sh_link = 0;
    sh_strtab.sh_info = 0;
    sh_strtab.sh_addralign = 1;
    sh_strtab.sh_entsize = 0;
    bw_emit(&bw, &sh_strtab, sizeof(sh_strtab));

    Elf64_Shdr sh_shstr = {0};
    sh_shstr.sh_name = (Elf64_Word)off_shstr_name;
    sh_shstr.sh_type = SHT_STRTAB;
    sh_shstr.sh_flags = 0;
    sh_shstr.sh_addr = 0;
    sh_shstr.sh_offset = shstr_off;
    sh_shstr.sh_size = shstr_size;
    sh_shstr.sh_link = 0;
    sh_shstr.sh_info = 0;
    sh_shstr.sh_addralign = 1;
    sh_shstr.sh_entsize = 0;
    bw_emit(&bw, &sh_shstr, sizeof(sh_shstr));

    // patch ehdr
    ((Elf64_Ehdr*)bw.buf.data)->e_shoff = eh.e_shoff;

    if (fwrite(bw.buf.data, 1, bw.buf.len, out) != bw.buf.len) {
        free(sym_indices);
        return RASM_ERR_IO;
    }
    free(sym_indices);
    return RASM_OK;
}

static uint32_t reloc_type_elf32(reloc_kind k) {
    switch (k) {
        case RELOC_PC32: return 2;  // R_386_PC32
        case RELOC_ABS32: return 1; // R_386_32
        case RELOC_PLT32: return 4; // R_386_PLT32
        case RELOC_ABS64: return 1; // No 64-bit in 32-bit mode, use 32
        case RELOC_NONE:
        default: return 0;
    }
}

static rasm_status write_elf32(const asm_unit *unit, FILE *out, FILE *log) {
    (void)log;
    bin_writer bw = {0};
    VEC(uint8_t) shstr = {0};
    VEC(uint8_t) strtab = {0};
    
    // For ELF32, we need Elf32_Sym structures
    typedef struct { Elf32_Sym *data; size_t len; size_t cap; } vec_Elf32_Sym;
    vec_Elf32_Sym syms = {0};
    
    size_t *sym_indices = NULL;
    if (unit->symbols.len) {
        sym_indices = calloc(unit->symbols.len, sizeof(size_t));
        if (!sym_indices) return RASM_ERR_IO;
    }

    // strtabs start with NUL
    VEC_PUSH(shstr, 0);
    VEC_PUSH(strtab, 0);

    section_indices idx = {0};
    idx.sh_text = 1;
    idx.sh_rela_text = 2;
    idx.sh_data = 3;
    idx.sh_rela_data = 4;
    idx.sh_bss = 5;
    idx.sh_note_gnu_stack = 6;
    idx.sh_symtab = 7;
    idx.sh_strtab = 8;
    idx.sh_shstrtab = 9;

    size_t off_text_name = add_str(&shstr, ".text");
    size_t off_rel_text_name = add_str(&shstr, ".rel.text");
    size_t off_data_name = add_str(&shstr, ".data");
    size_t off_rel_data_name = add_str(&shstr, ".rel.data");
    size_t off_bss_name = add_str(&shstr, ".bss");
    size_t off_note_gnu_stack_name = add_str(&shstr, ".note.GNU-stack");
    size_t off_symtab_name = add_str(&shstr, ".symtab");
    size_t off_strtab_name = add_str(&shstr, ".strtab");
    size_t off_shstr_name = add_str(&shstr, ".shstrtab");

    // Build symbol table - null symbol first
    Elf32_Sym null_sym = {0};
    vec_reserve_raw((void**)&syms.data, &syms.cap, sizeof(Elf32_Sym), syms.len + 1);
    syms.data[syms.len++] = null_sym;
    
    size_t local_count = 1;
    
    // Local symbols first
    for (size_t i = 0; i < unit->symbols.len; ++i) {
        const symbol *s = &unit->symbols.data[i];
        bool glob = s->is_global || s->is_extern;
        if (glob) continue;
        
        Elf32_Sym esym = {0};
        esym.st_name = (Elf32_Word)add_str(&strtab, s->name);
        esym.st_value = (Elf32_Addr)s->value;
        esym.st_size = 0;
        uint16_t shndx = s->is_defined ? section_index_for(s->section, &idx) : SHN_UNDEF;
        esym.st_shndx = shndx;
        esym.st_info = (STB_LOCAL << 4);
        esym.st_other = 0;
        
        vec_reserve_raw((void**)&syms.data, &syms.cap, sizeof(Elf32_Sym), syms.len + 1);
        syms.data[syms.len] = esym;
        sym_indices[i] = syms.len;
        syms.len++;
        local_count++;
    }
    
    // Global symbols next
    for (size_t i = 0; i < unit->symbols.len; ++i) {
        const symbol *s = &unit->symbols.data[i];
        bool glob = s->is_global || s->is_extern;
        if (!glob) continue;
        
        Elf32_Sym esym = {0};
        esym.st_name = (Elf32_Word)add_str(&strtab, s->name);
        esym.st_value = (Elf32_Addr)s->value;
        esym.st_size = 0;
        uint16_t shndx = s->is_defined ? section_index_for(s->section, &idx) : SHN_UNDEF;
        esym.st_shndx = shndx;
        esym.st_info = (STB_GLOBAL << 4);
        esym.st_other = 0;
        
        vec_reserve_raw((void**)&syms.data, &syms.cap, sizeof(Elf32_Sym), syms.len + 1);
        syms.data[syms.len] = esym;
        sym_indices[i] = syms.len;
        syms.len++;
    }

    // Write ELF32 header
    Elf32_Ehdr eh = {0};
    eh.e_ident[EI_MAG0] = ELFMAG0;
    eh.e_ident[EI_MAG1] = ELFMAG1;
    eh.e_ident[EI_MAG2] = ELFMAG2;
    eh.e_ident[EI_MAG3] = ELFMAG3;
    eh.e_ident[EI_CLASS] = ELFCLASS32;
    eh.e_ident[EI_DATA] = ELFDATA2LSB;
    eh.e_ident[EI_VERSION] = EV_CURRENT;
    eh.e_type = ET_REL;
    eh.e_machine = EM_386;
    eh.e_version = EV_CURRENT;
    eh.e_ehsize = sizeof(Elf32_Ehdr);
    eh.e_shentsize = sizeof(Elf32_Shdr);
    eh.e_shnum = 10;
    eh.e_shstrndx = (Elf32_Half)idx.sh_shstrtab;

    bw_emit(&bw, &eh, sizeof(eh));

    // .text section
    bw_pad(&bw, 16);
    Elf32_Off text_off = (Elf32_Off)bw.buf.len;
    bw_emit(&bw, unit->text.data, unit->text.len);

    // .rel.text (32-bit uses REL, not RELA)
    bw_pad(&bw, 4);
    Elf32_Off rel_text_off = (Elf32_Off)bw.buf.len;
    for (size_t i = 0; i < unit->text_relocs.len; ++i) {
        relocation r = unit->text_relocs.data[i];
        Elf32_Rel rel = {0};
        int sym_index = -1;
        for (size_t j = 0; j < unit->symbols.len; ++j) {
            if (strcmp(unit->symbols.data[j].name, r.symbol) == 0) {
                sym_index = (int)sym_indices[j];
                break;
            }
        }
        if (sym_index < 0) {
            sym_index = (int)syms.len;
            Elf32_Sym esym = {0};
            esym.st_name = (Elf32_Word)add_str(&strtab, r.symbol);
            esym.st_info = (STB_GLOBAL << 4);
            esym.st_shndx = SHN_UNDEF;
            vec_reserve_raw((void**)&syms.data, &syms.cap, sizeof(Elf32_Sym), syms.len + 1);
            syms.data[syms.len++] = esym;
        }
        rel.r_offset = (Elf32_Addr)r.offset;
        rel.r_info = ELF32_R_INFO(sym_index, reloc_type_elf32(r.kind));
        bw_emit(&bw, &rel, sizeof(rel));
    }
    size_t rel_text_size = unit->text_relocs.len * sizeof(Elf32_Rel);

    // .data section
    bw_pad(&bw, 4);
    Elf32_Off data_off = (Elf32_Off)bw.buf.len;
    bw_emit(&bw, unit->data.data, unit->data.len);

    // .rel.data
    bw_pad(&bw, 4);
    Elf32_Off rel_data_off = (Elf32_Off)bw.buf.len;
    for (size_t i = 0; i < unit->data_relocs.len; ++i) {
        relocation r = unit->data_relocs.data[i];
        Elf32_Rel rel = {0};
        int sym_index = -1;
        for (size_t j = 0; j < unit->symbols.len; ++j) {
            if (strcmp(unit->symbols.data[j].name, r.symbol) == 0) {
                sym_index = (int)sym_indices[j];
                break;
            }
        }
        if (sym_index < 0) {
            sym_index = (int)syms.len;
            Elf32_Sym esym = {0};
            esym.st_name = (Elf32_Word)add_str(&strtab, r.symbol);
            esym.st_info = (STB_GLOBAL << 4);
            esym.st_shndx = SHN_UNDEF;
            vec_reserve_raw((void**)&syms.data, &syms.cap, sizeof(Elf32_Sym), syms.len + 1);
            syms.data[syms.len++] = esym;
        }
        rel.r_offset = (Elf32_Addr)r.offset;
        rel.r_info = ELF32_R_INFO(sym_index, reloc_type_elf32(r.kind));
        bw_emit(&bw, &rel, sizeof(rel));
    }
    size_t rel_data_size = unit->data_relocs.len * sizeof(Elf32_Rel);

    // .symtab
    bw_pad(&bw, 4);
    Elf32_Off symtab_off = (Elf32_Off)bw.buf.len;
    for (size_t i = 0; i < syms.len; ++i) {
        bw_emit(&bw, &syms.data[i], sizeof(Elf32_Sym));
    }
    size_t symtab_size = syms.len * sizeof(Elf32_Sym);

    // .strtab
    bw_pad(&bw, 1);
    Elf32_Off strtab_off = (Elf32_Off)bw.buf.len;
    bw_emit(&bw, strtab.data, strtab.len);
    size_t strtab_size = strtab.len;

    // .shstrtab
    bw_pad(&bw, 1);
    Elf32_Off shstr_off = (Elf32_Off)bw.buf.len;
    bw_emit(&bw, shstr.data, shstr.len);
    size_t shstr_size = shstr.len;

    // Section headers
    bw_pad(&bw, 4);
    eh.e_shoff = (Elf32_Off)bw.buf.len;

    Elf32_Shdr sh_null = {0};
    bw_emit(&bw, &sh_null, sizeof(sh_null));

    Elf32_Shdr sh_text = {0};
    sh_text.sh_name = (Elf32_Word)off_text_name;
    sh_text.sh_type = SHT_PROGBITS;
    sh_text.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    sh_text.sh_addr = 0;
    sh_text.sh_offset = text_off;
    sh_text.sh_size = (Elf32_Word)unit->text.len;
    sh_text.sh_link = 0;
    sh_text.sh_info = 0;
    sh_text.sh_addralign = 16;
    sh_text.sh_entsize = 0;
    bw_emit(&bw, &sh_text, sizeof(sh_text));

    Elf32_Shdr sh_rel_text = {0};
    sh_rel_text.sh_name = (Elf32_Word)off_rel_text_name;
    sh_rel_text.sh_type = SHT_REL;
    sh_rel_text.sh_flags = 0;
    sh_rel_text.sh_addr = 0;
    sh_rel_text.sh_offset = rel_text_off;
    sh_rel_text.sh_size = (Elf32_Word)rel_text_size;
    sh_rel_text.sh_link = idx.sh_symtab;
    sh_rel_text.sh_info = idx.sh_text;
    sh_rel_text.sh_addralign = 4;
    sh_rel_text.sh_entsize = sizeof(Elf32_Rel);
    bw_emit(&bw, &sh_rel_text, sizeof(sh_rel_text));

    Elf32_Shdr sh_data = {0};
    sh_data.sh_name = (Elf32_Word)off_data_name;
    sh_data.sh_type = SHT_PROGBITS;
    sh_data.sh_flags = SHF_ALLOC | SHF_WRITE;
    sh_data.sh_addr = 0;
    sh_data.sh_offset = data_off;
    sh_data.sh_size = (Elf32_Word)unit->data.len;
    sh_data.sh_link = 0;
    sh_data.sh_info = 0;
    sh_data.sh_addralign = 4;
    sh_data.sh_entsize = 0;
    bw_emit(&bw, &sh_data, sizeof(sh_data));

    Elf32_Shdr sh_rel_data = {0};
    sh_rel_data.sh_name = (Elf32_Word)off_rel_data_name;
    sh_rel_data.sh_type = SHT_REL;
    sh_rel_data.sh_flags = 0;
    sh_rel_data.sh_addr = 0;
    sh_rel_data.sh_offset = rel_data_off;
    sh_rel_data.sh_size = (Elf32_Word)rel_data_size;
    sh_rel_data.sh_link = idx.sh_symtab;
    sh_rel_data.sh_info = idx.sh_data;
    sh_rel_data.sh_addralign = 4;
    sh_rel_data.sh_entsize = sizeof(Elf32_Rel);
    bw_emit(&bw, &sh_rel_data, sizeof(sh_rel_data));

    Elf32_Shdr sh_bss = {0};
    sh_bss.sh_name = (Elf32_Word)off_bss_name;
    sh_bss.sh_type = SHT_NOBITS;
    sh_bss.sh_flags = SHF_ALLOC | SHF_WRITE;
    sh_bss.sh_addr = 0;
    sh_bss.sh_offset = data_off + unit->data.len;
    sh_bss.sh_size = (Elf32_Word)unit->bss_size;
    sh_bss.sh_link = 0;
    sh_bss.sh_info = 0;
    sh_bss.sh_addralign = 4;
    sh_bss.sh_entsize = 0;
    bw_emit(&bw, &sh_bss, sizeof(sh_bss));

    Elf32_Shdr sh_note_gnu_stack = {0};
    sh_note_gnu_stack.sh_name = (Elf32_Word)off_note_gnu_stack_name;
    sh_note_gnu_stack.sh_type = SHT_PROGBITS;
    sh_note_gnu_stack.sh_flags = 0;
    sh_note_gnu_stack.sh_addr = 0;
    sh_note_gnu_stack.sh_offset = (Elf32_Off)bw.buf.len;
    sh_note_gnu_stack.sh_size = 0;
    sh_note_gnu_stack.sh_link = 0;
    sh_note_gnu_stack.sh_info = 0;
    sh_note_gnu_stack.sh_addralign = 1;
    sh_note_gnu_stack.sh_entsize = 0;
    bw_emit(&bw, &sh_note_gnu_stack, sizeof(sh_note_gnu_stack));

    Elf32_Shdr sh_symtab = {0};
    sh_symtab.sh_name = (Elf32_Word)off_symtab_name;
    sh_symtab.sh_type = SHT_SYMTAB;
    sh_symtab.sh_flags = 0;
    sh_symtab.sh_addr = 0;
    sh_symtab.sh_offset = symtab_off;
    sh_symtab.sh_size = (Elf32_Word)symtab_size;
    sh_symtab.sh_link = idx.sh_strtab;
    sh_symtab.sh_info = (Elf32_Word)local_count;
    sh_symtab.sh_addralign = 4;
    sh_symtab.sh_entsize = sizeof(Elf32_Sym);
    bw_emit(&bw, &sh_symtab, sizeof(sh_symtab));

    Elf32_Shdr sh_strtab = {0};
    sh_strtab.sh_name = (Elf32_Word)off_strtab_name;
    sh_strtab.sh_type = SHT_STRTAB;
    sh_strtab.sh_flags = 0;
    sh_strtab.sh_addr = 0;
    sh_strtab.sh_offset = strtab_off;
    sh_strtab.sh_size = (Elf32_Word)strtab_size;
    sh_strtab.sh_link = 0;
    sh_strtab.sh_info = 0;
    sh_strtab.sh_addralign = 1;
    sh_strtab.sh_entsize = 0;
    bw_emit(&bw, &sh_strtab, sizeof(sh_strtab));

    Elf32_Shdr sh_shstr = {0};
    sh_shstr.sh_name = (Elf32_Word)off_shstr_name;
    sh_shstr.sh_type = SHT_STRTAB;
    sh_shstr.sh_flags = 0;
    sh_shstr.sh_addr = 0;
    sh_shstr.sh_offset = shstr_off;
    sh_shstr.sh_size = (Elf32_Word)shstr_size;
    sh_shstr.sh_link = 0;
    sh_shstr.sh_info = 0;
    sh_shstr.sh_addralign = 1;
    sh_shstr.sh_entsize = 0;
    bw_emit(&bw, &sh_shstr, sizeof(sh_shstr));

    // Patch ELF header
    memcpy(bw.buf.data + offsetof(Elf32_Ehdr, e_shoff), &eh.e_shoff, sizeof(eh.e_shoff));

    if (fwrite(bw.buf.data, 1, bw.buf.len, out) != bw.buf.len) {
        free(sym_indices);
        free(syms.data);
        return RASM_ERR_IO;
    }
    
    free(sym_indices);
    free(syms.data);
    return RASM_OK;
}

static uint16_t reloc_type_pe(reloc_kind k) {
    switch (k) {
        case RELOC_PC32: return IMAGE_REL_AMD64_REL32;
        case RELOC_ABS32: return IMAGE_REL_AMD64_ADDR32;
        case RELOC_ABS64: return IMAGE_REL_AMD64_ADDR64;
        case RELOC_PLT32: return IMAGE_REL_AMD64_REL32;
        case RELOC_NONE:
        default: return IMAGE_REL_AMD64_REL32;
    }
}

static rasm_status write_pe64(const asm_unit *unit, FILE *out, FILE *log) {
    (void)log;
    bin_writer bw = {0};
    VEC(uint8_t) strtab = {0};
    
    // String table starts with 4-byte size (filled later)
    VEC_PUSH(strtab, 0);
    VEC_PUSH(strtab, 0);
    VEC_PUSH(strtab, 0);
    VEC_PUSH(strtab, 0);
    
    // Count sections (text, data, bss - skip empty ones later)
    uint16_t section_count = 0;
    bool has_text = unit->text.len > 0;
    bool has_data = unit->data.len > 0;
    bool has_bss = unit->bss_size > 0;
    
    if (has_text) section_count++;
    if (has_data) section_count++;
    if (has_bss) section_count++;
    
    // Section indices for PE (1-based, 0 = undefined)
    int text_section = 0, data_section = 0, bss_section = 0;
    int sec_idx = 1;
    if (has_text) text_section = sec_idx++;
    if (has_data) data_section = sec_idx++;
    if (has_bss) bss_section = sec_idx++;
    
    // Build symbol table
    typedef struct { pe_symbol sym; char *name; } sym_entry;
    sym_entry *symbols = NULL;
    size_t sym_count = 0;
    size_t sym_cap = 0;
    
    // Add section symbols first
    if (has_text) {
        if (sym_count >= sym_cap) {
            sym_cap = sym_cap ? sym_cap * 2 : 64;
            symbols = xrealloc(symbols, sym_cap * sizeof(sym_entry));
        }
        pe_symbol s = {0};
        memcpy(s.N.ShortName, ".text", 6);
        s.Value = 0;
        s.SectionNumber = text_section;
        s.Type = 0;
        s.StorageClass = IMAGE_SYM_CLASS_STATIC;
        s.NumberOfAuxSymbols = 0;
        symbols[sym_count].sym = s;
        symbols[sym_count].name = NULL;
        sym_count++;
    }
    
    if (has_data) {
        if (sym_count >= sym_cap) {
            sym_cap = sym_cap ? sym_cap * 2 : 64;
            symbols = xrealloc(symbols, sym_cap * sizeof(sym_entry));
        }
        pe_symbol s = {0};
        memcpy(s.N.ShortName, ".data", 6);
        s.Value = 0;
        s.SectionNumber = data_section;
        s.Type = 0;
        s.StorageClass = IMAGE_SYM_CLASS_STATIC;
        s.NumberOfAuxSymbols = 0;
        symbols[sym_count].sym = s;
        symbols[sym_count].name = NULL;
        sym_count++;
    }
    
    if (has_bss) {
        if (sym_count >= sym_cap) {
            sym_cap = sym_cap ? sym_cap * 2 : 64;
            symbols = xrealloc(symbols, sym_cap * sizeof(sym_entry));
        }
        pe_symbol s = {0};
        memcpy(s.N.ShortName, ".bss", 5);
        s.Value = 0;
        s.SectionNumber = bss_section;
        s.Type = 0;
        s.StorageClass = IMAGE_SYM_CLASS_STATIC;
        s.NumberOfAuxSymbols = 0;
        symbols[sym_count].sym = s;
        symbols[sym_count].name = NULL;
        sym_count++;
    }
    
    // Track symbol indices for relocations
    size_t *sym_indices = NULL;
    if (unit->symbols.len) {
        sym_indices = calloc(unit->symbols.len, sizeof(size_t));
        if (!sym_indices) {
            free(symbols);
            return RASM_ERR_IO;
        }
    }
    
    // Add user symbols
    for (size_t i = 0; i < unit->symbols.len; ++i) {
        const symbol *usym = &unit->symbols.data[i];
        
        if (sym_count >= sym_cap) {
            sym_cap = sym_cap ? sym_cap * 2 : 64;
            symbols = xrealloc(symbols, sym_cap * sizeof(sym_entry));
        }
        
        pe_symbol s = {0};
        
        // Determine section number
        int16_t secnum = IMAGE_SYM_UNDEFINED;
        if (usym->is_defined) {
            if (usym->section == SEC_TEXT) secnum = text_section;
            else if (usym->section == SEC_DATA) secnum = data_section;
            else if (usym->section == SEC_BSS) secnum = bss_section;
        }
        
        // Set name (use string table if > 8 chars)
        size_t name_len = strlen(usym->name);
        if (name_len <= 8) {
            memcpy(s.N.ShortName, usym->name, name_len);
        } else {
            s.N.Name.Zeros = 0;
            s.N.Name.Offset = strtab.len;
            // Add to string table
            for (size_t j = 0; j < name_len; ++j) {
                VEC_PUSH(strtab, (uint8_t)usym->name[j]);
            }
            VEC_PUSH(strtab, 0);
        }
        
        s.Value = (uint32_t)usym->value;
        s.SectionNumber = secnum;
        s.Type = 0x20; // Function type for most symbols
        s.StorageClass = (usym->is_global || usym->is_extern) ? IMAGE_SYM_CLASS_EXTERNAL : IMAGE_SYM_CLASS_STATIC;
        s.NumberOfAuxSymbols = 0;
        
        sym_indices[i] = sym_count;
        symbols[sym_count].sym = s;
        symbols[sym_count].name = str_dup(usym->name);
        sym_count++;
    }
    
    // Build relocations
    typedef struct { pe_relocation rel; int section; } reloc_entry;
    reloc_entry *relocs = NULL;
    size_t reloc_count = 0;
    size_t reloc_cap = 0;
    
    // Text relocations
    for (size_t i = 0; i < unit->text_relocs.len; ++i) {
        relocation r = unit->text_relocs.data[i];
        
        if (reloc_count >= reloc_cap) {
            reloc_cap = reloc_cap ? reloc_cap * 2 : 64;
            relocs = xrealloc(relocs, reloc_cap * sizeof(reloc_entry));
        }
        
        // Find symbol index
        size_t sym_idx = 0;
        bool found = false;
        for (size_t j = 0; j < unit->symbols.len; ++j) {
            if (strcmp(unit->symbols.data[j].name, r.symbol) == 0) {
                sym_idx = sym_indices[j];
                found = true;
                break;
            }
        }
        
        if (!found) {
            // Add undefined external symbol
            if (sym_count >= sym_cap) {
                sym_cap = sym_cap ? sym_cap * 2 : 64;
                symbols = xrealloc(symbols, sym_cap * sizeof(sym_entry));
            }
            
            pe_symbol s = {0};
            size_t name_len = strlen(r.symbol);
            if (name_len <= 8) {
                memcpy(s.N.ShortName, r.symbol, name_len);
            } else {
                s.N.Name.Zeros = 0;
                s.N.Name.Offset = strtab.len;
                for (size_t j = 0; j < name_len; ++j) {
                    VEC_PUSH(strtab, (uint8_t)r.symbol[j]);
                }
                VEC_PUSH(strtab, 0);
            }
            s.Value = 0;
            s.SectionNumber = IMAGE_SYM_UNDEFINED;
            s.Type = 0x20;
            s.StorageClass = IMAGE_SYM_CLASS_EXTERNAL;
            s.NumberOfAuxSymbols = 0;
            
            symbols[sym_count].sym = s;
            symbols[sym_count].name = str_dup(r.symbol);
            sym_idx = sym_count;
            sym_count++;
        }
        
        pe_relocation pr = {0};
        pr.VirtualAddress = (uint32_t)r.offset;
        pr.SymbolTableIndex = (uint32_t)sym_idx;
        pr.Type = reloc_type_pe(r.kind);
        
        relocs[reloc_count].rel = pr;
        relocs[reloc_count].section = text_section;
        reloc_count++;
    }
    
    // Data relocations
    for (size_t i = 0; i < unit->data_relocs.len; ++i) {
        relocation r = unit->data_relocs.data[i];
        
        if (reloc_count >= reloc_cap) {
            reloc_cap = reloc_cap ? reloc_cap * 2 : 64;
            relocs = xrealloc(relocs, reloc_cap * sizeof(reloc_entry));
        }
        
        // Find symbol index
        size_t sym_idx = 0;
        bool found = false;
        for (size_t j = 0; j < unit->symbols.len; ++j) {
            if (strcmp(unit->symbols.data[j].name, r.symbol) == 0) {
                sym_idx = sym_indices[j];
                found = true;
                break;
            }
        }
        
        if (!found) {
            // Add undefined external symbol
            if (sym_count >= sym_cap) {
                sym_cap = sym_cap ? sym_cap * 2 : 64;
                symbols = xrealloc(symbols, sym_cap * sizeof(sym_entry));
            }
            
            pe_symbol s = {0};
            size_t name_len = strlen(r.symbol);
            if (name_len <= 8) {
                memcpy(s.N.ShortName, r.symbol, name_len);
            } else {
                s.N.Name.Zeros = 0;
                s.N.Name.Offset = strtab.len;
                for (size_t j = 0; j < name_len; ++j) {
                    VEC_PUSH(strtab, (uint8_t)r.symbol[j]);
                }
                VEC_PUSH(strtab, 0);
            }
            s.Value = 0;
            s.SectionNumber = IMAGE_SYM_UNDEFINED;
            s.Type = 0x20;
            s.StorageClass = IMAGE_SYM_CLASS_EXTERNAL;
            s.NumberOfAuxSymbols = 0;
            
            symbols[sym_count].sym = s;
            symbols[sym_count].name = str_dup(r.symbol);
            sym_idx = sym_count;
            sym_count++;
        }
        
        pe_relocation pr = {0};
        pr.VirtualAddress = (uint32_t)r.offset;
        pr.SymbolTableIndex = (uint32_t)sym_idx;
        pr.Type = reloc_type_pe(r.kind);
        
        relocs[reloc_count].rel = pr;
        relocs[reloc_count].section = data_section;
        reloc_count++;
    }
    
    // Write PE file header
    pe_file_header fh = {0};
    fh.Machine = IMAGE_FILE_MACHINE_AMD64;
    fh.NumberOfSections = section_count;
    fh.TimeDateStamp = 0; // Deterministic build
    fh.PointerToSymbolTable = 0; // Filled later
    fh.NumberOfSymbols = (uint32_t)sym_count;
    fh.SizeOfOptionalHeader = 0;
    fh.Characteristics = 0;
    
    bw_emit(&bw, &fh, sizeof(fh));
    
    // Reserve space for section headers
    size_t section_headers_offset = bw.buf.len;
    for (uint16_t i = 0; i < section_count; ++i) {
        pe_section_header sh = {0};
        bw_emit(&bw, &sh, sizeof(sh));
    }
    
    // Write section data and build section headers
    pe_section_header *section_headers = calloc(section_count, sizeof(pe_section_header));
    int sh_idx = 0;
    
    // .text section
    if (has_text) {
        bw_pad(&bw, 16);
        uint32_t text_offset = (uint32_t)bw.buf.len;
        bw_emit(&bw, unit->text.data, unit->text.len);
        
        // Text relocations
        uint32_t text_reloc_offset = 0;
        uint16_t text_reloc_count = 0;
        for (size_t i = 0; i < reloc_count; ++i) {
            if (relocs[i].section == text_section) {
                text_reloc_count++;
            }
        }
        
        if (text_reloc_count > 0) {
            bw_pad(&bw, 4);
            text_reloc_offset = (uint32_t)bw.buf.len;
            for (size_t i = 0; i < reloc_count; ++i) {
                if (relocs[i].section == text_section) {
                    bw_emit(&bw, &relocs[i].rel, sizeof(pe_relocation));
                }
            }
        }
        
        pe_section_header *sh = &section_headers[sh_idx++];
        memcpy(sh->Name, ".text", 6);
        sh->VirtualSize = 0;
        sh->VirtualAddress = 0;
        sh->SizeOfRawData = (uint32_t)unit->text.len;
        sh->PointerToRawData = text_offset;
        sh->PointerToRelocations = text_reloc_offset;
        sh->PointerToLinenumbers = 0;
        sh->NumberOfRelocations = text_reloc_count;
        sh->NumberOfLinenumbers = 0;
        sh->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_ALIGN_16BYTES;
    }
    
    // .data section
    if (has_data) {
        bw_pad(&bw, 8);
        uint32_t data_offset = (uint32_t)bw.buf.len;
        bw_emit(&bw, unit->data.data, unit->data.len);
        
        // Data relocations
        uint32_t data_reloc_offset = 0;
        uint16_t data_reloc_count = 0;
        for (size_t i = 0; i < reloc_count; ++i) {
            if (relocs[i].section == data_section) {
                data_reloc_count++;
            }
        }
        
        if (data_reloc_count > 0) {
            bw_pad(&bw, 4);
            data_reloc_offset = (uint32_t)bw.buf.len;
            for (size_t i = 0; i < reloc_count; ++i) {
                if (relocs[i].section == data_section) {
                    bw_emit(&bw, &relocs[i].rel, sizeof(pe_relocation));
                }
            }
        }
        
        pe_section_header *sh = &section_headers[sh_idx++];
        memcpy(sh->Name, ".data", 6);
        sh->VirtualSize = 0;
        sh->VirtualAddress = 0;
        sh->SizeOfRawData = (uint32_t)unit->data.len;
        sh->PointerToRawData = data_offset;
        sh->PointerToRelocations = data_reloc_offset;
        sh->PointerToLinenumbers = 0;
        sh->NumberOfRelocations = data_reloc_count;
        sh->NumberOfLinenumbers = 0;
        sh->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_ALIGN_8BYTES;
    }
    
    // .bss section
    if (has_bss) {
        pe_section_header *sh = &section_headers[sh_idx++];
        memcpy(sh->Name, ".bss", 5);
        sh->VirtualSize = (uint32_t)unit->bss_size;
        sh->VirtualAddress = 0;
        sh->SizeOfRawData = 0;
        sh->PointerToRawData = 0;
        sh->PointerToRelocations = 0;
        sh->PointerToLinenumbers = 0;
        sh->NumberOfRelocations = 0;
        sh->NumberOfLinenumbers = 0;
        sh->Characteristics = IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_ALIGN_8BYTES;
    }
    
    // Write symbol table
    bw_pad(&bw, 4);
    uint32_t symtab_offset = (uint32_t)bw.buf.len;
    for (size_t i = 0; i < sym_count; ++i) {
        bw_emit(&bw, &symbols[i].sym, sizeof(pe_symbol));
    }
    
    // Update string table size
    uint32_t strtab_size = (uint32_t)strtab.len;
    memcpy(strtab.data, &strtab_size, 4);
    
    // Write string table
    bw_emit(&bw, strtab.data, strtab.len);
    
    // Patch file header with symbol table offset
    memcpy(bw.buf.data + offsetof(pe_file_header, PointerToSymbolTable), &symtab_offset, 4);
    
    // Patch section headers
    memcpy(bw.buf.data + section_headers_offset, section_headers, section_count * sizeof(pe_section_header));
    
    // Write to file
    if (fwrite(bw.buf.data, 1, bw.buf.len, out) != bw.buf.len) {
        free(section_headers);
        free(relocs);
        for (size_t i = 0; i < sym_count; ++i) {
            if (symbols[i].name) free(symbols[i].name);
        }
        free(symbols);
        free(sym_indices);
        return RASM_ERR_IO;
    }
    
    // Cleanup
    free(section_headers);
    free(relocs);
    for (size_t i = 0; i < sym_count; ++i) {
        if (symbols[i].name) free(symbols[i].name);
    }
    free(symbols);
    free(sym_indices);
    return RASM_OK;
}

static uint16_t reloc_type_pe32(reloc_kind k) {
    switch (k) {
        case RELOC_PC32: return 0x14; // IMAGE_REL_I386_REL32
        case RELOC_ABS32: return 0x06; // IMAGE_REL_I386_DIR32
        case RELOC_ABS64: return 0x06; // No 64-bit in 32-bit mode
        case RELOC_PLT32: return 0x14; // IMAGE_REL_I386_REL32
        case RELOC_NONE:
        default: return 0x14;
    }
}

static rasm_status write_pe32(const asm_unit *unit, FILE *out, FILE *log) {
    // PE32 is almost identical to PE64, just use different machine type
    (void)log;
    bin_writer bw = {0};
    VEC(uint8_t) strtab = {0};
    
    // String table starts with 4-byte size
    VEC_PUSH(strtab, 0);
    VEC_PUSH(strtab, 0);
    VEC_PUSH(strtab, 0);
    VEC_PUSH(strtab, 0);
    
    // Count sections
    uint16_t section_count = 0;
    bool has_text = unit->text.len > 0;
    bool has_data = unit->data.len > 0;
    bool has_bss = unit->bss_size > 0;
    
    if (has_text) section_count++;
    if (has_data) section_count++;
    if (has_bss) section_count++;
    
    int text_section = 0, data_section = 0, bss_section = 0;
    int sec_idx = 1;
    if (has_text) text_section = sec_idx++;
    if (has_data) data_section = sec_idx++;
    if (has_bss) bss_section = sec_idx++;
    
    // Build symbol table
    typedef struct { pe_symbol sym; char *name; } sym_entry;
    sym_entry *symbols = NULL;
    size_t sym_count = 0;
    size_t sym_cap = 0;
    
    // Add section symbols
    if (has_text) {
        if (sym_count >= sym_cap) {
            sym_cap = 64;
            symbols = xrealloc(symbols, sym_cap * sizeof(sym_entry));
        }
        pe_symbol s = {0};
        memcpy(s.N.ShortName, ".text", 6);
        s.SectionNumber = text_section;
        s.StorageClass = IMAGE_SYM_CLASS_STATIC;
        symbols[sym_count].sym = s;
        symbols[sym_count].name = NULL;
        sym_count++;
    }
    
    if (has_data) {
        if (sym_count >= sym_cap) {
            sym_cap = sym_cap ? sym_cap * 2 : 64;
            symbols = xrealloc(symbols, sym_cap * sizeof(sym_entry));
        }
        pe_symbol s = {0};
        memcpy(s.N.ShortName, ".data", 6);
        s.SectionNumber = data_section;
        s.StorageClass = IMAGE_SYM_CLASS_STATIC;
        symbols[sym_count].sym = s;
        symbols[sym_count].name = NULL;
        sym_count++;
    }
    
    if (has_bss) {
        if (sym_count >= sym_cap) {
            sym_cap = sym_cap ? sym_cap * 2 : 64;
            symbols = xrealloc(symbols, sym_cap * sizeof(sym_entry));
        }
        pe_symbol s = {0};
        memcpy(s.N.ShortName, ".bss", 5);
        s.SectionNumber = bss_section;
        s.StorageClass = IMAGE_SYM_CLASS_STATIC;
        symbols[sym_count].sym = s;
        symbols[sym_count].name = NULL;
        sym_count++;
    }
    
    size_t *sym_indices = NULL;
    if (unit->symbols.len) {
        sym_indices = calloc(unit->symbols.len, sizeof(size_t));
        if (!sym_indices) {
            free(symbols);
            return RASM_ERR_IO;
        }
    }
    
    // Add user symbols
    for (size_t i = 0; i < unit->symbols.len; ++i) {
        const symbol *usym = &unit->symbols.data[i];
        
        if (sym_count >= sym_cap) {
            sym_cap = sym_cap ? sym_cap * 2 : 64;
            symbols = xrealloc(symbols, sym_cap * sizeof(sym_entry));
        }
        
        pe_symbol s = {0};
        int16_t secnum = IMAGE_SYM_UNDEFINED;
        if (usym->is_defined) {
            if (usym->section == SEC_TEXT) secnum = text_section;
            else if (usym->section == SEC_DATA) secnum = data_section;
            else if (usym->section == SEC_BSS) secnum = bss_section;
        }
        
        size_t name_len = strlen(usym->name);
        if (name_len <= 8) {
            memcpy(s.N.ShortName, usym->name, name_len);
        } else {
            s.N.Name.Zeros = 0;
            s.N.Name.Offset = strtab.len;
            for (size_t j = 0; j < name_len; ++j) {
                VEC_PUSH(strtab, (uint8_t)usym->name[j]);
            }
            VEC_PUSH(strtab, 0);
        }
        
        s.Value = (uint32_t)usym->value;
        s.SectionNumber = secnum;
        s.Type = 0x20;
        s.StorageClass = (usym->is_global || usym->is_extern) ? IMAGE_SYM_CLASS_EXTERNAL : IMAGE_SYM_CLASS_STATIC;
        
        sym_indices[i] = sym_count;
        symbols[sym_count].sym = s;
        symbols[sym_count].name = str_dup(usym->name);
        sym_count++;
    }
    
    // Build relocations (similar to PE64 but use pe32 relocation types)
    typedef struct { pe_relocation rel; int section; } reloc_entry;
    reloc_entry *relocs = NULL;
    size_t reloc_count = 0;
    size_t reloc_cap = 0;
    
    // Text relocations
    for (size_t i = 0; i < unit->text_relocs.len; ++i) {
        relocation r = unit->text_relocs.data[i];
        if (reloc_count >= reloc_cap) {
            reloc_cap = reloc_cap ? reloc_cap * 2 : 64;
            relocs = xrealloc(relocs, reloc_cap * sizeof(reloc_entry));
        }
        
        size_t sym_idx = 0;
        bool found = false;
        for (size_t j = 0; j < unit->symbols.len; ++j) {
            if (strcmp(unit->symbols.data[j].name, r.symbol) == 0) {
                sym_idx = sym_indices[j];
                found = true;
                break;
            }
        }
        
        if (!found) {
            if (sym_count >= sym_cap) {
                sym_cap = sym_cap ? sym_cap * 2 : 64;
                symbols = xrealloc(symbols, sym_cap * sizeof(sym_entry));
            }
            
            pe_symbol s = {0};
            size_t name_len = strlen(r.symbol);
            if (name_len <= 8) {
                memcpy(s.N.ShortName, r.symbol, name_len);
            } else {
                s.N.Name.Zeros = 0;
                s.N.Name.Offset = strtab.len;
                for (size_t j = 0; j < name_len; ++j) {
                    VEC_PUSH(strtab, (uint8_t)r.symbol[j]);
                }
                VEC_PUSH(strtab, 0);
            }
            s.SectionNumber = IMAGE_SYM_UNDEFINED;
            s.Type = 0x20;
            s.StorageClass = IMAGE_SYM_CLASS_EXTERNAL;
            
            symbols[sym_count].sym = s;
            symbols[sym_count].name = str_dup(r.symbol);
            sym_idx = sym_count;
            sym_count++;
        }
        
        pe_relocation pr = {0};
        pr.VirtualAddress = (uint32_t)r.offset;
        pr.SymbolTableIndex = (uint32_t)sym_idx;
        pr.Type = reloc_type_pe32(r.kind);
        
        relocs[reloc_count].rel = pr;
        relocs[reloc_count].section = text_section;
        reloc_count++;
    }
    
    // Data relocations (similar logic)
    for (size_t i = 0; i < unit->data_relocs.len; ++i) {
        relocation r = unit->data_relocs.data[i];
        if (reloc_count >= reloc_cap) {
            reloc_cap = reloc_cap ? reloc_cap * 2 : 64;
            relocs = xrealloc(relocs, reloc_cap * sizeof(reloc_entry));
        }
        
        size_t sym_idx = 0;
        bool found = false;
        for (size_t j = 0; j < unit->symbols.len; ++j) {
            if (strcmp(unit->symbols.data[j].name, r.symbol) == 0) {
                sym_idx = sym_indices[j];
                found = true;
                break;
            }
        }
        
        if (!found) {
            if (sym_count >= sym_cap) {
                sym_cap = sym_cap ? sym_cap * 2 : 64;
                symbols = xrealloc(symbols, sym_cap * sizeof(sym_entry));
            }
            
            pe_symbol s = {0};
            size_t name_len = strlen(r.symbol);
            if (name_len <= 8) {
                memcpy(s.N.ShortName, r.symbol, name_len);
            } else {
                s.N.Name.Zeros = 0;
                s.N.Name.Offset = strtab.len;
                for (size_t j = 0; j < name_len; ++j) {
                    VEC_PUSH(strtab, (uint8_t)r.symbol[j]);
                }
                VEC_PUSH(strtab, 0);
            }
            s.SectionNumber = IMAGE_SYM_UNDEFINED;
            s.Type = 0x20;
            s.StorageClass = IMAGE_SYM_CLASS_EXTERNAL;
            
            symbols[sym_count].sym = s;
            symbols[sym_count].name = str_dup(r.symbol);
            sym_idx = sym_count;
            sym_count++;
        }
        
        pe_relocation pr = {0};
        pr.VirtualAddress = (uint32_t)r.offset;
        pr.SymbolTableIndex = (uint32_t)sym_idx;
        pr.Type = reloc_type_pe32(r.kind);
        
        relocs[reloc_count].rel = pr;
        relocs[reloc_count].section = data_section;
        reloc_count++;
    }
    
    // Write PE file header (use I386 machine type)
    pe_file_header fh = {0};
    fh.Machine = IMAGE_FILE_MACHINE_I386;  // 32-bit x86
    fh.NumberOfSections = section_count;
    fh.TimeDateStamp = 0;
    fh.PointerToSymbolTable = 0;
    fh.NumberOfSymbols = (uint32_t)sym_count;
    fh.SizeOfOptionalHeader = 0;
    fh.Characteristics = 0;
    
    bw_emit(&bw, &fh, sizeof(fh));
    
    // Reserve space for section headers
    size_t section_headers_offset = bw.buf.len;
    for (uint16_t i = 0; i < section_count; ++i) {
        pe_section_header sh = {0};
        bw_emit(&bw, &sh, sizeof(sh));
    }
    
    // Write sections and build headers
    pe_section_header *section_headers = calloc(section_count, sizeof(pe_section_header));
    int sh_idx = 0;
    
    // .text section (similar to PE64)
    if (has_text) {
        bw_pad(&bw, 16);
        uint32_t text_offset = (uint32_t)bw.buf.len;
        bw_emit(&bw, unit->text.data, unit->text.len);
        
        uint32_t text_reloc_offset = 0;
        uint16_t text_reloc_count = 0;
        for (size_t i = 0; i < reloc_count; ++i) {
            if (relocs[i].section == text_section) text_reloc_count++;
        }
        
        if (text_reloc_count > 0) {
            bw_pad(&bw, 4);
            text_reloc_offset = (uint32_t)bw.buf.len;
            for (size_t i = 0; i < reloc_count; ++i) {
                if (relocs[i].section == text_section) {
                    bw_emit(&bw, &relocs[i].rel, sizeof(pe_relocation));
                }
            }
        }
        
        pe_section_header *sh = &section_headers[sh_idx++];
        memcpy(sh->Name, ".text", 6);
        sh->SizeOfRawData = (uint32_t)unit->text.len;
        sh->PointerToRawData = text_offset;
        sh->PointerToRelocations = text_reloc_offset;
        sh->NumberOfRelocations = text_reloc_count;
        sh->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_ALIGN_16BYTES;
    }
    
    // .data section
    if (has_data) {
        bw_pad(&bw, 4);
        uint32_t data_offset = (uint32_t)bw.buf.len;
        bw_emit(&bw, unit->data.data, unit->data.len);
        
        uint32_t data_reloc_offset = 0;
        uint16_t data_reloc_count = 0;
        for (size_t i = 0; i < reloc_count; ++i) {
            if (relocs[i].section == data_section) data_reloc_count++;
        }
        
        if (data_reloc_count > 0) {
            bw_pad(&bw, 4);
            data_reloc_offset = (uint32_t)bw.buf.len;
            for (size_t i = 0; i < reloc_count; ++i) {
                if (relocs[i].section == data_section) {
                    bw_emit(&bw, &relocs[i].rel, sizeof(pe_relocation));
                }
            }
        }
        
        pe_section_header *sh = &section_headers[sh_idx++];
        memcpy(sh->Name, ".data", 6);
        sh->SizeOfRawData = (uint32_t)unit->data.len;
        sh->PointerToRawData = data_offset;
        sh->PointerToRelocations = data_reloc_offset;
        sh->NumberOfRelocations = data_reloc_count;
        sh->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_ALIGN_8BYTES;
    }
    
    // .bss section
    if (has_bss) {
        pe_section_header *sh = &section_headers[sh_idx++];
        memcpy(sh->Name, ".bss", 5);
        sh->VirtualSize = (uint32_t)unit->bss_size;
        sh->SizeOfRawData = 0;
        sh->Characteristics = IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_ALIGN_8BYTES;
    }
    
    // Write symbol table
    bw_pad(&bw, 4);
    uint32_t symtab_offset = (uint32_t)bw.buf.len;
    for (size_t i = 0; i < sym_count; ++i) {
        bw_emit(&bw, &symbols[i].sym, sizeof(pe_symbol));
    }
    
    // Write string table
    uint32_t strtab_size = (uint32_t)strtab.len;
    memcpy(strtab.data, &strtab_size, 4);
    bw_emit(&bw, strtab.data, strtab.len);
    
    // Patch file header
    memcpy(bw.buf.data + offsetof(pe_file_header, PointerToSymbolTable), &symtab_offset, 4);
    memcpy(bw.buf.data + section_headers_offset, section_headers, section_count * sizeof(pe_section_header));
    
    // Write to file
    if (fwrite(bw.buf.data, 1, bw.buf.len, out) != bw.buf.len) {
        free(section_headers);
        free(relocs);
        for (size_t i = 0; i < sym_count; ++i) {
            if (symbols[i].name) free(symbols[i].name);
        }
        free(symbols);
        free(sym_indices);
        return RASM_ERR_IO;
    }
    
    free(section_headers);
    free(relocs);
    for (size_t i = 0; i < sym_count; ++i) {
        if (symbols[i].name) free(symbols[i].name);
    }
    free(symbols);
    free(sym_indices);
    return RASM_OK;
}

static rasm_status write_binary(const asm_unit *unit, FILE *out, FILE *log) {
    // Flat binary: just write .text and .data sections concatenated
    // For binary format, we need to resolve all relocations since there's no loader
    
    // Make a copy of the text and data sections so we can apply relocations
    vec_uint8_t text_copy = {0};
    vec_uint8_t data_copy = {0};
    
    if (unit->text.len > 0) {
        text_copy.data = malloc(unit->text.len);
        if (!text_copy.data) return RASM_ERR_IO;
        memcpy(text_copy.data, unit->text.data, unit->text.len);
        text_copy.len = unit->text.len;
        text_copy.cap = unit->text.len;
    }
    
    if (unit->data.len > 0) {
        data_copy.data = malloc(unit->data.len);
        if (!data_copy.data) {
            free(text_copy.data);
            return RASM_ERR_IO;
        }
        memcpy(data_copy.data, unit->data.data, unit->data.len);
        data_copy.len = unit->data.len;
        data_copy.cap = unit->data.len;
    }
    
    // Apply relocations for .text section
    for (size_t i = 0; i < unit->text_relocs.len; i++) {
        relocation *r = &unit->text_relocs.data[i];
        const symbol *sym = find_symbol(unit, r->symbol);
        if (!sym || !sym->is_defined) {
            if (log) fprintf(log, "error: undefined symbol '%s' in binary format\n", r->symbol);
            free(text_copy.data);
            free(data_copy.data);
            return RASM_ERR_INVALID_ARGUMENT;
        }
        if (sym->is_extern) {
            if (log) fprintf(log, "error: external symbol '%s' cannot be used in binary format\n", r->symbol);
            free(text_copy.data);
            free(data_copy.data);
            return RASM_ERR_INVALID_ARGUMENT;
        }
        
        // Calculate symbol value based on section
        uint64_t sym_val = sym->value + unit->origin;
        if (sym->section == SEC_DATA) {
            sym_val += unit->text.len;  // Data comes after text
        } else if (sym->section == SEC_BSS) {
            sym_val += unit->text.len + unit->data.len;
        }
        
        // Apply relocation
        uint64_t target_addr = r->offset;
        int64_t value = 0;
        
        // Detect relocation size based on architecture
        // In 16-bit mode with near jumps/calls, we use 2-byte displacements
        // In 32/64-bit mode, we use 4-byte displacements
        bool is_16bit_reloc = (unit->arch == ARCH_X86_16) && 
                              (r->kind == RELOC_PC32 || r->kind == RELOC_PLT32);
        
        if (r->kind == RELOC_PC32 || r->kind == RELOC_PLT32) {
            // PC-relative: target = S + A - P
            // where S = symbol value, A = addend, P = place (address after the displacement)
            uint64_t place = unit->origin + r->offset + (is_16bit_reloc ? 2 : 4);
            value = (int64_t)(sym_val + r->addend - place);
            if (is_16bit_reloc) {
                if (value < INT16_MIN || value > INT16_MAX) {
                    if (log) fprintf(log, "error: 16-bit relocation overflow for symbol '%s' (value=%lld)\n", r->symbol, (long long)value);
                    free(text_copy.data);
                    free(data_copy.data);
                    return RASM_ERR_INVALID_ARGUMENT;
                }
            } else {
                if (value < INT32_MIN || value > INT32_MAX) {
                    if (log) fprintf(log, "error: relocation overflow for symbol '%s'\n", r->symbol);
                    free(text_copy.data);
                    free(data_copy.data);
                    return RASM_ERR_INVALID_ARGUMENT;
                }
            }
        } else if (r->kind == RELOC_ABS32) {
            // Absolute 32-bit: target = S + A
            value = (int64_t)(sym_val + r->addend);
            if (value < 0 || value > UINT32_MAX) {
                if (log) fprintf(log, "error: relocation overflow for symbol '%s'\n", r->symbol);
                free(text_copy.data);
                free(data_copy.data);
                return RASM_ERR_INVALID_ARGUMENT;
            }
        } else if (r->kind == RELOC_ABS64) {
            // Absolute 64-bit: target = S + A
            value = (int64_t)(sym_val + r->addend);
        } else {
            if (log) fprintf(log, "error: unsupported relocation type %d\n", r->kind);
            free(text_copy.data);
            free(data_copy.data);
            return RASM_ERR_INVALID_ARGUMENT;
        }
        
        // Write the relocation value
        if (r->kind == RELOC_ABS64) {
            memcpy(text_copy.data + target_addr, &value, 8);
        } else if (is_16bit_reloc) {
            uint16_t val16 = (uint16_t)value;
            memcpy(text_copy.data + target_addr, &val16, 2);
        } else {
            uint32_t val32 = (uint32_t)value;
            memcpy(text_copy.data + target_addr, &val32, 4);
        }
    }
    
    // Apply relocations for .data section
    for (size_t i = 0; i < unit->data_relocs.len; i++) {
        relocation *r = &unit->data_relocs.data[i];
        const symbol *sym = find_symbol(unit, r->symbol);
        if (!sym || !sym->is_defined) {
            if (log) fprintf(log, "error: undefined symbol '%s' in binary format\n", r->symbol);
            free(text_copy.data);
            free(data_copy.data);
            return RASM_ERR_INVALID_ARGUMENT;
        }
        if (sym->is_extern) {
            if (log) fprintf(log, "error: external symbol '%s' cannot be used in binary format\n", r->symbol);
            free(text_copy.data);
            free(data_copy.data);
            return RASM_ERR_INVALID_ARGUMENT;
        }
        
        // Calculate symbol value based on section
        uint64_t sym_val = sym->value + unit->origin;
        if (sym->section == SEC_DATA) {
            sym_val += unit->text.len;
        } else if (sym->section == SEC_BSS) {
            sym_val += unit->text.len + unit->data.len;
        }
        
        // Apply relocation
        uint64_t target_addr = r->offset;
        int64_t value = 0;
        bool is_16bit_reloc = (r->addend == -2);  // 16-bit PC-relative has addend -2
        
        if (r->kind == RELOC_PC32 || r->kind == RELOC_PLT32) {
            uint64_t place = unit->origin + unit->text.len + r->offset + (is_16bit_reloc ? 2 : 4);
            value = (int64_t)(sym_val + r->addend - place);
            if (is_16bit_reloc) {
                if (value < INT16_MIN || value > INT16_MAX) {
                    if (log) fprintf(log, "error: 16-bit relocation overflow for symbol '%s'\n", r->symbol);
                    free(text_copy.data);
                    free(data_copy.data);
                    return RASM_ERR_INVALID_ARGUMENT;
                }
            } else {
                if (value < INT32_MIN || value > INT32_MAX) {
                    if (log) fprintf(log, "error: relocation overflow for symbol '%s'\n", r->symbol);
                    free(text_copy.data);
                    free(data_copy.data);
                    return RASM_ERR_INVALID_ARGUMENT;
                }
            }
        } else if (r->kind == RELOC_ABS32) {
            value = (int64_t)(sym_val + r->addend);
            if (value < 0 || value > UINT32_MAX) {
                if (log) fprintf(log, "error: relocation overflow for symbol '%s'\n", r->symbol);
                free(text_copy.data);
                free(data_copy.data);
                return RASM_ERR_INVALID_ARGUMENT;
            }
        } else if (r->kind == RELOC_ABS64) {
            value = (int64_t)(sym_val + r->addend);
        } else {
            if (log) fprintf(log, "error: unsupported relocation type %d\n", r->kind);
            free(text_copy.data);
            free(data_copy.data);
            return RASM_ERR_INVALID_ARGUMENT;
        }
        
        // Write the relocation value
        if (r->kind == RELOC_ABS64) {
            memcpy(data_copy.data + target_addr, &value, 8);
        } else if (is_16bit_reloc) {
            uint16_t val16 = (uint16_t)value;
            memcpy(data_copy.data + target_addr, &val16, 2);
        } else {
            uint32_t val32 = (uint32_t)value;
            memcpy(data_copy.data + target_addr, &val32, 4);
        }
    }
    
    // Write .text section
    if (text_copy.len > 0) {
        if (fwrite(text_copy.data, 1, text_copy.len, out) != text_copy.len) {
            free(text_copy.data);
            free(data_copy.data);
            return RASM_ERR_IO;
        }
    }
    
    // Write .data section
    if (data_copy.len > 0) {
        if (fwrite(data_copy.data, 1, data_copy.len, out) != data_copy.len) {
            free(text_copy.data);
            free(data_copy.data);
            return RASM_ERR_IO;
        }
    }
    
    // Clean up
    free(text_copy.data);
    free(data_copy.data);
    
    // .bss is uninitialized, not written to binary
    return RASM_OK;
}

static rasm_status write_com(const asm_unit *unit, FILE *out, FILE *log) {
    // COM format is basically flat binary that loads at 0x100 in DOS
    // Same as binary but with ORG 0x100 assumption
    if (unit->text_relocs.len > 0 || unit->data_relocs.len > 0) {
        fprintf(log ? log : stderr, "warning: COM format cannot contain relocations - output may not work\n");
    }
    
    size_t total_size = unit->text.len + unit->data.len;
    if (total_size > 65536 - 256) {
        fprintf(log ? log : stderr, "error: COM file too large (max 65280 bytes)\n");
        return RASM_ERR_INVALID_ARGUMENT;
    }
    
    // Write .text section
    if (unit->text.len > 0) {
        if (fwrite(unit->text.data, 1, unit->text.len, out) != unit->text.len) {
            return RASM_ERR_IO;
        }
    }
    
    // Write .data section
    if (unit->data.len > 0) {
        if (fwrite(unit->data.data, 1, unit->data.len, out) != unit->data.len) {
            return RASM_ERR_IO;
        }
    }
    
    return RASM_OK;
}

static void free_unit(asm_unit *unit) {
    for (size_t i = 0; i < unit->symbols.len; ++i) free((void*)unit->symbols.data[i].name);
    for (size_t i = 0; i < unit->stmts.len; ++i) {
        statement *st = &unit->stmts.data[i];
        switch (st->kind) {
            case STMT_LABEL:
                free((void*)st->v.label.name);
                break;
            case STMT_INSTR:
                for (size_t j = 0; j < st->v.instr.op_count; ++j) {
                    if (st->v.instr.ops[j].kind == OP_SYMBOL) free((void*)st->v.instr.ops[j].v.sym);
                }
                break;
            case STMT_DATA:
                if (st->v.data.value.kind == OP_SYMBOL) free((void*)st->v.data.value.v.sym);
                break;
            case STMT_RESERVE:
                break;
            case STMT_ALIGN:
                break;
            case STMT_TIMES:
                if (st->v.times.count_expr) expr_free(st->v.times.count_expr);
                if (st->v.times.kind == TIMES_DATA) {
                    if (st->v.times.u.data.value.kind == OP_SYMBOL) free((void*)st->v.times.u.data.value.v.sym);
                    if (st->v.times.u.data.value.kind == OP_EXPR) expr_free(st->v.times.u.data.value.v.expr);
                } else { // TIMES_INSTR
                    for (size_t j = 0; j < st->v.times.u.instr.op_count; ++j) {
                        if (st->v.times.u.instr.ops[j].kind == OP_SYMBOL) free((void*)st->v.times.u.instr.ops[j].v.sym);
                        if (st->v.times.u.instr.ops[j].kind == OP_EXPR) expr_free(st->v.times.u.instr.ops[j].v.expr);
                    }
                }
                break;
        }
    }
    free(unit->stmts.data);
    free(unit->symbols.data);
    free(unit->text_relocs.data);
    free(unit->data_relocs.data);
    free(unit->text.data);
    free(unit->data.data);
}

static void write_listing(const asm_unit *unit, const char *source, FILE *lst) {
    if (!lst || !unit || !source) return;
    
    // Split source into lines
    char **lines = NULL;
    size_t line_count = 0;
    size_t line_cap = 0;
    
    const char *line_start = source;
    const char *p = source;
    while (*p) {
        if (*p == '\n') {
            if (line_count >= line_cap) {
                line_cap = line_cap ? line_cap * 2 : 64;
                lines = xrealloc(lines, line_cap * sizeof(char *));
            }
            size_t len = (size_t)(p - line_start);
            lines[line_count] = malloc(len + 1);
            memcpy(lines[line_count], line_start, len);
            lines[line_count][len] = '\0';
            line_count++;
            line_start = p + 1;
        }
        p++;
    }
    // Add last line if not empty
    if (*line_start) {
        if (line_count >= line_cap) {
            line_cap = line_cap ? line_cap * 2 : 64;
            lines = xrealloc(lines, line_cap * sizeof(char *));
        }
        lines[line_count] = str_dup(line_start);
        line_count++;
    }
    
    fprintf(lst, "RASM Listing File\n");
    fprintf(lst, "=================\n\n");
    
    const char *section_names[] = {".text", ".data", ".bss"};
    uint64_t offsets[3] = {0, 0, 0};
    
    // Process each statement
    for (size_t i = 0; i < unit->stmts.len; ++i) {
        const statement *st = &unit->stmts.data[i];
        size_t lineno = 0;
        
        // Get line number from the appropriate statement type
        switch (st->kind) {
            case STMT_LABEL: lineno = st->v.label.line; break;
            case STMT_INSTR: lineno = st->v.instr.line; break;
            case STMT_DATA: lineno = st->v.data.line; break;
            case STMT_RESERVE: lineno = st->v.res.line; break;
            case STMT_ALIGN: lineno = st->v.align.line; break;
            case STMT_TIMES: lineno = st->v.times.line; break;
        }
        
        const char *line_text = (lineno > 0 && lineno <= line_count) ? lines[lineno - 1] : "";
        
        switch (st->kind) {
            case STMT_LABEL:
                fprintf(lst, "%04zX: %-8s %s:\n", (size_t)offsets[st->section], 
                        section_names[st->section], st->v.label.name);
                fprintf(lst, "              %s\n", line_text);
                break;
                
            case STMT_INSTR: {
                //Calculate instruction size from the encoded bytes
                size_t instr_start = offsets[st->section];
                
                // Find the encoded bytes
                const vec_uint8_t *sec_data = NULL;
                if (st->section == SEC_TEXT) sec_data = &unit->text;
                else if (st->section == SEC_DATA) sec_data = &unit->data;
                
                // Find next statement to determine size
                if (i + 1 < unit->stmts.len) {
                    // Find next statement in same section
                    for (size_t j = i + 1; j < unit->stmts.len; ++j) {
                        if (unit->stmts.data[j].section == st->section) {
                            // This is a simple approximation - just show the bytes until next statement
                            break;
                        }
                    }
                }
                
                // For now, try to show up to 15 bytes or until section end
                fprintf(lst, "%04zX: %-8s ", (size_t)instr_start, section_names[st->section]);
                
                // Print hex bytes (just show available bytes, limited display)
                if (sec_data && instr_start < sec_data->len) {
                    size_t max_show = (instr_start + 15 < sec_data->len) ? 15 : (sec_data->len - instr_start);
                    // Try to estimate actual instruction size by scanning for next offset change
                    for (size_t j = 0; j < max_show && j < 15; ++j) {
                        fprintf(lst, "%02X", sec_data->data[instr_start + j]);
                    }
                }
                
                fprintf(lst, "\n              %s\n", line_text);
                
                // Advance offset - need to calculate properly
                // For now, scan to find actual size
                size_t actual_size = 1;  // minimum
                if (i + 1 < unit->stmts.len) {
                    // Rough estimate by checking offsets
                    for (size_t j = i + 1; j < unit->stmts.len; ++j) {
                        const statement *next_st = &unit->stmts.data[j];
                        if (next_st->section == st->section && next_st->kind == STMT_INSTR) {
                            // Next instruction - difference is our size
                            // But we don't know next instruction's offset yet
                            break;
                        }
                    }
                }
                // For listing purposes, encode instruction size  
                // Use simple encoding to scratch buffer to get size
                asm_unit scratch = {0};
                scratch.symbols = unit->symbols; // share symbols
                scratch.current_section = st->section;
                vec_reserve_raw((void**)&scratch.text.data, &scratch.text.cap, sizeof(uint8_t), 16);
                if (encode_instr(&st->v.instr, &scratch) == RASM_OK) {
                    actual_size = scratch.text.len;
                }
                free(scratch.text.data);
                offsets[st->section] += actual_size;
                break;
            }
            
            case STMT_DATA: {
                fprintf(lst, "%04zX: %-8s ", (size_t)offsets[st->section], section_names[st->section]);
                const data_item *di = &st->v.data;
                
                // Determine size
                size_t item_size = 1;
                switch (di->width) {
                    case DATA_DB: item_size = 1; break;
                    case DATA_DW: item_size = 2; break;
                    case DATA_DD: item_size = 4; break;
                    case DATA_DQ: item_size = 8; break;
                }
                
                // Print hex data from the appropriate section
                const vec_uint8_t *sec_data = NULL;
                if (st->section == SEC_TEXT) sec_data = &unit->text;
                else if (st->section == SEC_DATA) sec_data = &unit->data;
                
                if (sec_data && offsets[st->section] + item_size <= sec_data->len) {
                    for (size_t j = 0; j < item_size; ++j) {
                        fprintf(lst, "%02X", sec_data->data[offsets[st->section] + j]);
                    }
                }
                
                fprintf(lst, "\n              %s\n", line_text);
                offsets[st->section] += item_size;
                break;
            }
            
            case STMT_RESERVE:
                fprintf(lst, "%04zX: %-8s [reserve %zd bytes]\n", 
                        (size_t)offsets[st->section], section_names[st->section], st->v.res.count);
                fprintf(lst, "              %s\n", line_text);
                offsets[st->section] += st->v.res.count;
                break;
                
            case STMT_ALIGN:
                fprintf(lst, "              [align %zd]\n", st->v.align.align);
                fprintf(lst, "              %s\n", line_text);
                // Calculate aligned offset
                size_t align = st->v.align.align;
                if (align > 0) {
                    uint64_t off = offsets[st->section];
                    uint64_t rem = off % align;
                    if (rem != 0) {
                        offsets[st->section] += (align - rem);
                    }
                }
                break;
                
            case STMT_TIMES: {
                // Evaluate expression to get count
                const char *unresolved = NULL;
                int64_t count_val = 0;
                if (eval_expression(st->v.times.count_expr, unit, &count_val, &unresolved)) {
                    fprintf(lst, "%04zX: %-8s [times %lld %s]\n", 
                            (size_t)offsets[st->section], section_names[st->section], 
                            (long long)count_val, 
                            st->v.times.kind == TIMES_DATA ? "data" : "instr");
                    size_t item_size;
                    if (st->v.times.kind == TIMES_DATA) {
                        item_size = width_bytes(st->v.times.u.data.width);
                    } else {
                        // For instructions, estimate size by encoding once
                        asm_unit scratch = *unit;
                        scratch.text = (vec_uint8_t){0};
                        scratch.text_relocs = (vec_relocation){0};
                        size_t start = scratch.text.len;
                        encode_instr(&st->v.times.u.instr, &scratch);
                        item_size = scratch.text.len - start;
                        free(scratch.text.data);
                        free(scratch.text_relocs.data);
                    }
                    offsets[st->section] += (size_t)count_val * item_size;
                } else {
                    fprintf(lst, "%04zX: %-8s [times <expr>]\n", 
                            (size_t)offsets[st->section], section_names[st->section]);
                }
                fprintf(lst, "              %s\n", line_text);
                break;
            }
        }
    }
    
    // Free lines
    for (size_t i = 0; i < line_count; ++i) {
        free(lines[i]);
    }
    free(lines);
}

static char *read_entire_file(FILE *f, size_t *out_size) {
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz < 0) return NULL;
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)sz + 1);
    if (!buf) return NULL;
    size_t rd = fread(buf, 1, (size_t)sz, f);
    buf[rd] = '\0';
    if (out_size) *out_size = rd;
    return buf;
}

rasm_status assemble_stream(FILE *in, FILE *out, FILE *listing, output_format format, target_arch arch, FILE *log) {
    size_t src_sz = 0;
    char *src = read_entire_file(in, &src_sz);
    if (!src) return RASM_ERR_IO;
    
    // Preprocess macros
    char *preprocessed = preprocess_macros(src, log);
    free(src);
    if (!preprocessed) {
        fprintf(log ? log : stderr, "error: macro preprocessing failed\n");
        return RASM_ERR_INVALID_ARGUMENT;
    }
    
    asm_unit unit = {0};
    unit.arch = arch;  // Set target architecture
    rasm_status st = parse_source(preprocessed, &unit, log);
    if (st != RASM_OK) { free(preprocessed); free_unit(&unit); return st; }
    st = first_pass_sizes(&unit, log);
    if (st != RASM_OK) { free(preprocessed); free_unit(&unit); return st; }
    st = second_pass_encode(&unit, log);
    if (st != RASM_OK) { free(preprocessed); free_unit(&unit); return st; }
    
    // Check for undefined symbols
    st = check_undefined_symbols(&unit, log ? log : stderr);
    if (st != RASM_OK) { free(preprocessed); free_unit(&unit); return st; }
    
    // Generate listing if requested
    if (listing) {
        write_listing(&unit, preprocessed, listing);
    }
    
    // Write output in requested format
    switch (format) {
        case FORMAT_ELF64:
            st = write_elf64(&unit, out, log);
            break;
        case FORMAT_ELF32:
            st = write_elf32(&unit, out, log);
            break;
        case FORMAT_PE64:
            st = write_pe64(&unit, out, log);
            break;
        case FORMAT_PE32:
            st = write_pe32(&unit, out, log);
            break;
        case FORMAT_BIN:
            st = write_binary(&unit, out, log);
            break;
        case FORMAT_COM:
            st = write_com(&unit, out, log);
            break;
        default:
            fprintf(log ? log : stderr, "error: unknown output format\n");
            st = RASM_ERR_INVALID_ARGUMENT;
            break;
    }
    
    free(preprocessed);
    free_unit(&unit);
    return st;
}

rasm_status assemble_file(const char *input_path, const char *output_path, const char *listing_path, output_format format, target_arch arch, FILE *log) {
    if (!input_path) {
        return RASM_ERR_INVALID_ARGUMENT;
    }

    FILE *in = fopen(input_path, "rb");
    if (!in) {
        fprintf(log ? log : stderr, "error: failed to open %s: %s\n", input_path, strerror(errno));
        return RASM_ERR_IO;
    }

    FILE *out = NULL;
    if (output_path) {
        out = fopen(output_path, "wb");
        if (!out) {
            fprintf(log ? log : stderr, "error: failed to open %s: %s\n", output_path, strerror(errno));
            fclose(in);
            return RASM_ERR_IO;
        }
    }

    FILE *listing = NULL;
    if (listing_path) {
        listing = fopen(listing_path, "w");
        if (!listing) {
            fprintf(log ? log : stderr, "error: failed to open %s: %s\n", listing_path, strerror(errno));
            fclose(in);
            if (out) fclose(out);
            return RASM_ERR_IO;
        }
    }

    rasm_status status = assemble_stream(in, out, listing, format, arch, log);

    if (listing) fclose(listing);
    if (out) fclose(out);
    fclose(in);
    return status;
}

const char *rasm_status_message(rasm_status status) {
    switch (status) {
        case RASM_OK: return "ok";
        case RASM_ERR_IO: return "i/o error";
        case RASM_ERR_INVALID_ARGUMENT: return "invalid argument";
        case RASM_ERR_NOT_IMPLEMENTED: return "not implemented";
        default: return "unknown error";
    }
}
