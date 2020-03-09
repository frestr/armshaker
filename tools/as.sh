#!/bin/bash

# Get the hexadecimal instruction encoding of the
# given (assembly) instruction

if [[ $# -eq 0 ]]; then
    echo "Usage: $(basename "$0") <asm_insn> [-t]"
fi

if [[ "$(uname -m)" = "aarch64" ]]; then
    fpu=""
else
    fpu="-mfpu=crypto-neon-fp-armv8"
fi

if [[ "$2" = "-t" ]]; then
    opts="-mthumb"
fi

file=$(mktemp)
out=$(echo "$1" | as -march=armv8.6-a -mcpu=all $fpu $opts -o "$file" 2>&1)

if [[ $? -eq 1 ]]; then
    echo "$out" | tail -n1 | cut -d' ' -f3-
    exit 1
fi

objdump -d "$file" | tail -n1 | awk '{print $2}'
rm $file
