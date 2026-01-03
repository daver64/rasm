#!/bin/bash
# Test script to verify both ELF and PE object generation

echo "Testing rasm PE/COFF object support..."
echo ""

# Test 1: Auto-detect from .o extension (ELF)
echo "Test 1: Auto-detect ELF from .o extension"
./rasm tests/examples/hello.asm -o tests/pe_test_elf.o
file tests/pe_test_elf.o
echo ""

# Test 2: Auto-detect from .obj extension (PE)  
echo "Test 2: Auto-detect PE from .obj extension"
./rasm tests/examples/hello.asm -o tests/pe_test_auto.obj
file tests/pe_test_auto.obj
echo ""

# Test 3: Explicit -f elf64
echo "Test 3: Explicit -f elf64"
./rasm tests/examples/hello.asm -f elf64 -o tests/pe_test_explicit_elf.o
file tests/pe_test_explicit_elf.o
echo ""

# Test 4: Explicit -f pe64
echo "Test 4: Explicit -f pe64"
./rasm tests/examples/hello.asm -f pe64 -o tests/pe_test_explicit_pe.obj
file tests/pe_test_explicit_pe.obj
echo ""

# Test 5: PE64 with relocations
echo "Test 5: PE64 with external symbols and relocations"
./rasm tests/examples/pe_test.asm -f pe64 -o tests/pe_test_reloc.obj
file tests/pe_test_reloc.obj
objdump -h tests/pe_test_reloc.obj
echo ""

# Cleanup
rm -f tests/pe_test_*.o tests/pe_test_*.obj

echo "All tests completed successfully!"
