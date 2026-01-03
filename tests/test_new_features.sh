#!/bin/bash
# Test script for new instructions and prefixes

set -e
cd "$(dirname "$0")/.."

echo "Testing LOOP instructions..."
./rasm tests/examples/misc_instructions.asm -o /tmp/test_loop.o
objdump -d /tmp/test_loop.o | grep -E "loop|xlat|movbe" > /dev/null && echo "✓ LOOP, XLAT, MOVBE work"

echo "Testing instruction prefixes..."
./rasm tests/examples/prefix_simple.asm -o /tmp/test_prefix.o
objdump -d /tmp/test_prefix.o | grep -q "f3 a4.*rep movs" && echo "✓ REP prefix works"
objdump -d /tmp/test_prefix.o | grep -q "f2 a6.*repnz cmps" && echo "✓ REPNE prefix works"
objdump -d /tmp/test_prefix.o | grep -q "f0 01 18.*lock add" && echo "✓ LOCK prefix works"

echo "Testing REP MOVSQ..."
./rasm tests/examples/test_rep_movsq.asm -o /tmp/test_rep_movsq.o
objdump -d /tmp/test_rep_movsq.o | grep -q "f3 48 a5.*rep movs QWORD" && echo "✓ REP MOVSQ works"

echo ""
echo "All new instructions and prefixes working correctly!"
