#!/usr/bin/env python3

# Simple program for making it easier to read the individual
# bitfields in a hex-represented instruction

from sys import argv
from os.path import basename
import re

if len(argv) < 2:
    print('Usage: {} <hex>'.format(basename(argv[0])))
    exit(1)

res = re.fullmatch('(0x)?([0-9a-f]{1,8})', argv[1])
if res is None:
    print('Invalid argument')
    exit(1)

arg = res.group(2)
sep_char = '\u2502'  # Long vertical bar

binstr = bin(int(arg, 16))[2:].zfill(32)
print(binstr)
print()

binsepped = ''.join(binstr[i:i+4] + sep_char for i in range(0, len(binstr), 4))
hexstr = ''.join('{:>4}{}'.format(c, sep_char) for c in arg.zfill(8))

print(binsepped)
print(hexstr)
print()

binlabels = ''.join('{:2d}{}'.format(i, sep_char if i % 4 == 0 else ' ')
                    for i in range(31, -1, -1))
binseps = ''.join(' \u250a{}'.format(sep_char if i % 4 == 3 else ' ')
                  for i in range(len(binstr)))
binspaced = ''.join('{:>2}{}'.format(binstr[i], sep_char if i % 4 == 3 else ' ')
                    for i in range(len(binstr)))

print(binlabels)
print(binseps)
print(binspaced)
