#!/bin/bash

# Disassembles the given instruction using both objdump (libopcodes)
# and capstone

if [[ $# -ne 1 || ! "$1" =~ ^(0x)?([0-9a-f]{8})$ ]]; then
    echo "Usage: $(basename "$0") <hex_insn>"
    exit 1
fi

insn=${BASH_REMATCH[2]}
bytes=("${insn:0:2}" "${insn:2:2}" "${insn:4:2}" "${insn:6:2}")

file=$(mktemp)
echo -ne "\x${bytes[3]}\x${bytes[2]}\x${bytes[1]}\x${bytes[0]}" > $file

ob=$(objdump -b binary -m arm -D $file \
     | tail -n1 \
     | awk '{$1=$2=""; print $0}' \
     | cut -c3-)
echo -e "ob:\t$ob"

cs=$(cstool arm "${bytes[3]} ${bytes[2]} ${bytes[1]} ${bytes[0]}" \
     | awk '{$1=$2=$3=$4=$5=""; print $0}' \
     | cut -c6-)

if [[ "$cs" = "" ]]; then
    cs="ERROR: invalid assembly code"
fi
echo -e "cs:\t$cs"

rm $file
