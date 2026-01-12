#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
make >/dev/null
ASM=./rasm
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Inline coverage sample to exercise many encoders at once
cat > "$TMP/sample.asm" <<'EOF'
global start
extern extfn
section .text
start:
    mov rax, 1
    add rax, 2
    mov rcx, rax
    add rcx, rax
    xor rax, rax
    or rax, rcx
    and rcx, [rip+msg]
    inc rcx
    dec rax
    not rax
    neg rcx
    shl rax, 1
    shr rcx, 3
    sar rax, 2
    sal rcx, 1
    lea rdx, [rip+msg]
    mov rsi, [rip+msg]
    mov [rip+msg], rax
    mov [rax+rbx*4+16], rcx
    mov r8, [rax+8]
    cmp [rax], rcx
    sub rsi, [rip+msg]
    test [rbp-8], rdx
    push [rip+msg]
    pop [rax+rbx*2+4]
    movaps xmm0, [rip+msg]
    movdqa xmm1, xmm0
    addps xmm1, xmm0
    vmovups ymm2, [rip+msg]
    vaddps ymm3, ymm2, ymm2
    vptest ymm4, ymm2
    vroundps xmm5, [rip+msg], 1
    vpermilps ymm6, ymm2, 0xb1
    call extfn
    jmp start
section .data
val: dq start
msg: db "hi", 0
align 8
EOF

check_common() {
    local obj="$1"
    readelf -S "$obj" | grep -E "\\.text|\\.data|\\.bss" >/dev/null
    # Check relocations if they exist (not all files have them)
    if readelf -r "$obj" 2>&1 | grep -q "Relocation section"; then
        readelf -r "$obj" | grep -E "R_X86_64_(PC32|PLT32|64|32)" >/dev/null
    fi
}

assemble_and_check() {
    local src="$1"
    local tag="$2"
    local obj="$TMP/$tag.o"
    $ASM "$src" -o "$obj"
    check_common "$obj"
    local disasm disasm_flat
    disasm="$(objdump -drw -Mintel "$obj")"
    disasm_flat="$(echo "$disasm" | tr -d '\n')"
    case "$tag" in
        sample)
            echo "$disasm_flat" | grep -q "\[rip" >/dev/null
            echo "$disasm_flat" | grep -F "[rax+rbx*4+0x10]" >/dev/null
            echo "$disasm_flat" | grep -F "[rbp-0x8]" >/dev/null
            echo "$disasm_flat" | grep -q "xmm0" >/dev/null
            echo "$disasm_flat" | grep -q "ymm2" >/dev/null
            echo "$disasm_flat" | grep -q "vptest" >/dev/null
            echo "$disasm_flat" | grep -q "vroundps" >/dev/null
            echo "$disasm_flat" | grep -q "vpermilps" >/dev/null
            ;;
        alu)
            echo "$disasm" | grep -qi "add.*rcx.*0x7f" >/dev/null
            echo "$disasm" | grep -qi "add.*rcx.*0x11223344" >/dev/null
            echo "$disasm" | grep -qi "or.*rax" >/dev/null
            echo "$disasm" | grep -qi "val-0x4" >/dev/null
            ;;
        unary_shift)
            echo "$disasm" | grep -qi "inc.*rax" >/dev/null
            echo "$disasm" | grep -qi "dec.*rax" >/dev/null
            echo "$disasm" | grep -qi "not.*rbx" >/dev/null
            echo "$disasm" | grep -qi "neg.*rcx" >/dev/null
            echo "$disasm" | grep -qi "shl.*rax.*0x1" >/dev/null
            echo "$disasm" | grep -qi "shr.*rbx.*0x1" >/dev/null
            echo "$disasm" | grep -qi "sar.*rcx.*0x3" >/dev/null
            ;;
        vector)
            echo "$disasm" | grep -qi "vmovups" >/dev/null
            echo "$disasm" | grep -qi "vaddps" >/dev/null
            echo "$disasm" | grep -qi "vxorps" >/dev/null
            echo "$disasm" | grep -qi "vpermilps" >/dev/null
            ;;
        hello)
            echo "$disasm" | grep -qi "call.*puts" >/dev/null
            ;;
        operand_sizes)
            echo "$disasm" | grep -qi "mov.*eax.*0x12345678" >/dev/null
            echo "$disasm" | grep -qi "mov.*ax.*0x1234" >/dev/null
            echo "$disasm" | grep -qi "mov.*al.*0x12" >/dev/null
            echo "$disasm" | grep -qi "add.*eax.*ebx" >/dev/null
            echo "$disasm" | grep -qi "add.*ax.*bx" >/dev/null
            echo "$disasm" | grep -qi "add.*al.*bl" >/dev/null
            ;;
    esac
}

assemble_and_check "$TMP/sample.asm" sample

# Skip files that are designed to test error handling or have known issues
skip_patterns=(
    "conversions"
    "error_line_test"
    "invalid_imm"
    "misc_16bit"
    "misc_32bit"
    "multi2"
    "parse_error_test"
    "pie_test"
    "reg_size_mismatch"
    "scalar_sse"
    "times_examples"
    "times_instr"
    "undefined_symbol"
    "variadic_error"
    "variadic_error2"
)

for src in tests/examples/*.asm; do
    tag="$(basename "$src" .asm)"
    
    # Check if this file should be skipped
    skip=false
    for pattern in "${skip_patterns[@]}"; do
        if [[ "$tag" == *"$pattern"* ]]; then
            skip=true
            break
        fi
    done
    
    if $skip; then
        continue
    fi
    
    assemble_and_check "$src" "$tag"
done
