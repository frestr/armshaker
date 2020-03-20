#!/bin/sh

# Minimal shell replacement for the Python front-end, for cases where
# Python or curses is not available.
#
# Usage:
#   PROCS=n START=n END=n ./shell_frontend.sh <fuzzer_args>
#
# NB: Don't use the -s and -e options to set the search range.

quit() {
    echo "Aborting"
    killall fuzzer
    echo
    exit 0
}

trap quit 2  # SIGINT

if [ "$PROCS" = "" ] ; then
    procs=$(nproc)
else
    procs=$PROCS
fi

if [ "$START" = "" ] ; then
    range_start=0
else
    range_start=$((0x$START))
fi

if [ "$END" = "" ] ; then
    range_end=$((0xffffffff))
else
    range_end=$((0x$END))
fi

range_size=$(($(($range_end - $range_start + 1)) / $procs))
for i in $(seq 0 1 $(($procs-1))); do
    s=$(printf '%08x' $(($range_start + $(($range_size * $i)))))
    e=$(printf '%08x' $(($range_start + $(($range_size * $(($i+1)))) - 1)))
    ./fuzzer -l $i -s $s -e $e $* > "data/out$i" 2>&1 &
done

while [ $(pgrep fuzzer | wc -l) -gt 0 ]; do
    out=""
    for i in $(seq 0 1 $(($procs-1))); do
        file="data/out$i"
        status_line=$(cat "$file" | tr '\r' '\n' | tail -n1)

        truncate -s 0 "$file"
        echo "$status_line" > "$file"

        out="${out}${status_line}\n"
    done
    # Output the whole buffer at once to avoid visible delay
    # between updating lines
    clear
    /bin/echo -e "$out"
    sleep 1
done
echo "Done"
