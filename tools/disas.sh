#!/bin/bash

# Disassembles the given instruction using both objdump (libopcodes)
# and capstone

if [[ $# -eq 0 || ! "$1" =~ ^(0x)?(([0-9a-f]{4}){1,2})$ ]]; then
    echo "Usage: $(basename "$0") <hex_insn> [-t]"
    exit 1
fi

# ARCH should be 'aarch64', 'arm' or empty
if [[ $ARCH != "" ]]; then
    arch=$ARCH
else
    arch=$(uname -m)
fi

insn=${BASH_REMATCH[2]}

bytes=("${insn:0:2}" "${insn:2:2}" "${insn:4:2}" "${insn:6:2}")

if [[ "$2" = "-t" ]]; then
    if [[ ${bytes[2]} = "" ]]; then
        # We have a thumb (16-bit) insn
        bytestring="\x${bytes[1]}\x${bytes[0]}"
    else
        # Middle endian...
        bytestring="\x${bytes[1]}\x${bytes[0]}\x${bytes[3]}\x${bytes[2]}"
    fi
else
    bytestring="\x${bytes[3]}\x${bytes[2]}\x${bytes[1]}\x${bytes[0]}"
fi

file=$(mktemp)
echo -ne "$bytestring" > $file

if [[ "$arch" =~ "arm" ]]; then
    arch="arm"
    if [[ "$2" = "-t" ]]; then
        obj_thumb="--disassembler-options=force-thumb"
    fi
else
    arch="aarch64"
fi

ob=$(objdump -b binary -m $arch -D $file $obj_thumb \
     | grep '0:' \
     | awk -F'\t' '{$1=$2=""; print $0}' \
     | cut -c3- \
     | awk '{print $0}')
echo -e "ob:\t$ob"

if [[ "$arch" = "aarch64" ]]; then
    arch="arm64"
elif [[ "$2" = "-t" ]]; then
    arch="thumb"
fi

cs=$(cstool $arch "$bytestring")

if [[ "$cs" = "" || "$cs" =~ "ERROR" ]]; then
    cs="ERROR: invalid assembly code"
else
    if [[ "$arch" = "thumb" ]]; then
        cs=$(echo "$cs" \
             | awk -F'  ' '{$1=$2=""; print $0}' \
             | cut -c3-)
    else
        cs=$(echo "$cs" \
             | awk '{$1=$2=$3=$4=$5=""; print $0}' \
             | cut -c6-)
    fi
fi

echo -e "cs:\t$cs"

rm $file
