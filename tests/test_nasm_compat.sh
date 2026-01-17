#!/usr/bin/env bash
# Test suite for NASM compatibility features
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "Testing NASM compatibility features..."
echo

tests_passed=0
tests_failed=0

test_file() {
    local file="$1"
    local desc="$2"
    echo -n "Testing $desc... "
    if ./rasm "$file" -f elf64 -o /tmp/test_nasm_compat.o 2>/dev/null; then
        echo "✓ PASS"
        tests_passed=$((tests_passed + 1))
    else
        echo "✗ FAIL"
        tests_failed=$((tests_failed + 1))
    fi
}

# Test individual features
test_file "tests/examples/nasm_compat_if_elif.asm" "%if/%elif expression conditionals"
test_file "tests/examples/nasm_compat_assign.asm" "%assign directive with expressions"
test_file "tests/examples/nasm_compat_rep.asm" "%rep/%endrep loops"
test_file "tests/examples/nasm_compat_rotate.asm" "%rotate directive"
test_file "tests/examples/nasm_compat_param_ops_simple.asm" "%0 and parameter operators"
test_file "tests/examples/nasm_compat_strings.asm" "String functions"
test_file "tests/examples/nasm_compat_comprehensive.asm" "Comprehensive feature test"

echo
echo "========================================="
echo "Tests passed: $tests_passed"
echo "Tests failed: $tests_failed"
echo "========================================="

if [ $tests_failed -eq 0 ]; then
    echo "All tests passed!"
    exit 0
else
    echo "Some tests failed."
    exit 1
fi
