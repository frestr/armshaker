#!/bin/bash

# Disassembles the given instruction using both objdump (libopcodes)
# and capstone

if [[ $# -eq 0 || ! "$1" =~ ^(0x)?(([0-9a-f]{4}){1,2})$ ]]; then
    echo "Usage: $(basename "$0") <hex_insn> [-t]"
    exit 1
fi

insn=${BASH_REMATCH[2]}
bytes=("${insn:0:2}" "${insn:2:2}" "${insn:4:2}" "${insn:6:2}")

file=$(mktemp)
echo -ne "\x${bytes[3]}\x${bytes[2]}\x${bytes[1]}\x${bytes[0]}" > $file

if [[ "$(uname -m)" =~ "arm" ]]; then
    arch="arm"
    if [[ "$2" = "-t" ]]; then
        obj_thumb="--disassembler-options=force-thumb"
    fi
else
    arch="aarch64"
fi

ob=$(objdump -b binary -m $arch -D $file $obj_thumb \
     | tail -n1 \
     | awk '{$1=$2=""; print $0}' \
     | cut -c3-)
echo -e "ob:\t$ob"

if [[ "$arch" = "aarch64" ]]; then
    arch="arm64"
elif [[ "$2" = "-t" ]]; then
    arch="thumb"
fi

cs=$(cstool $arch "${bytes[3]} ${bytes[2]} ${bytes[1]} ${bytes[0]}")

if [[ "$cs" = "" || "$cs" =~ "ERROR" ]]; then
    cs="ERROR: invalid assembly code"
else
    if [[ "$arch" = "thumb" ]]; then
        cs=$(echo "$cs" \
             | awk '{$1=$2=$3=""; print $0}' \
             | cut -c4-)
    else
        cs=$(echo "$cs" \
             | awk '{$1=$2=$3=$4=$5=""; print $0}' \
             | cut -c6-)
    fi
fi

echo -e "cs:\t$cs"

rm $file
