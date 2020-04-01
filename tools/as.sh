#!/bin/bash

# Get the hexadecimal instruction encoding of the
# given (assembly) instruction

if [[ $# -eq 0 ]]; then
    echo "Usage: $(basename "$0") <asm_insn> [-t]"
fi

# ARCH can be 'aarch64' or 'arm'
if [[ $ARCH != "" ]]; then
    arch=$ARCH
else
    arch=$(uname -m)
fi

if [[ "$arch" = "aarch64" ]]; then
    fpu=""
else
    fpu="-mfpu=crypto-neon-fp-armv8"
fi

if [[ "$2" = "-t" ]]; then
    opts="-mthumb"
fi

file=$(mktemp)
out=$(echo "$1" | as -march=armv8-a -mcpu=all $fpu $opts -o "$file" 2>&1)

if [[ $? -eq 1 ]]; then
    echo "$out"
    exit 1
fi

objdump -d "$file" | tail -n1 | awk -F'\t' '{print $2}' | tr -d ' '
rm $file
