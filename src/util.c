#include "util.h"

/*
 * Checks whether the supplied instruction is a 32-bit long
 * instruction (thumb2) or not.
 *
 * This can be deduced from the instruction prefix, which
 * is 0b11101 (0x1d), 0b11110 (0x1e) or 0b11111 (0x1f) in
 * those cases.
 */
bool is_thumb32(uint32_t insn)
{
    uint16_t upper = (insn >> 16) & 0xffff;
    uint8_t prefix = (upper >> 11) & 0x1f;
    return prefix >= 0x1d && prefix <= 0x1f;
}
