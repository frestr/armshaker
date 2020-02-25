#include "filter.h"
#include <stdio.h>

struct opcode
{
    uint32_t op_value;
    uint32_t op_mask;
    uint32_t sb_mask;
    const char *disassembly;
};

static const struct opcode arm_opcodes[] =
{
#ifdef __aarch64__
#else
    {0x00a00090, 0x0fa000f0, 0, "%22?sumlal%20's%c\t%12-15Ru, %16-19Ru, %0-3R, %8-11R"},
    {0x00800090, 0x0fa000f0, 0, "%22?sumull%20's%c\t%12-15Ru, %16-19Ru, %0-3R, %8-11R"},
    {0x07a00050, 0x0fa00070, 0, "%22?usbfx%c\t%12-15r, %0-3r, #%7-11d, #%16-20W"},
    {0x00a00010, 0x0fe00090, 0, "adc%20's%c\t%12-15R, %16-19R, %o"},
    {0x00a00000, 0x0fe00010, 0, "adc%20's%c\t%12-15r, %16-19r, %o"},
    {0x02a00000, 0x0fe00000, 0, "adc%20's%c\t%12-15r, %16-19r, %o"},
    {0x00800010, 0x0fe00090, 0, "add%20's%c\t%12-15R, %16-19R, %o"},
    {0x00800000, 0x0fe00010, 0, "add%20's%c\t%12-15r, %16-19r, %o"},
    {0x02800000, 0x0fe00000, 0, "add%20's%c\t%12-15r, %16-19r, %o"},
    {0x00000010, 0x0fe00090, 0, "and%20's%c\t%12-15R, %16-19R, %o"},
    {0x00000000, 0x0fe00010, 0, "and%20's%c\t%12-15r, %16-19r, %o"},
    {0x02000000, 0x0fe00000, 0, "and%20's%c\t%12-15r, %16-19r, %o"},
    {0x01a00040, 0x0def0060, 0x000f0000, "asr%20's%c\t%12-15R, %q"},
    {0x0a000000, 0x0e000000, 0, "b%24'l%c\t%b"},
    {0x07c0001f, 0x0fe0007f, 0, "bfc%c\t%12-15R, %E"},
    {0x07c00010, 0x0fe00070, 0, "bfi%c\t%12-15R, %0-3r, %E"},
    {0x01c00010, 0x0fe00090, 0, "bic%20's%c\t%12-15R, %16-19R, %o"},
    {0x01c00000, 0x0fe00010, 0, "bic%20's%c\t%12-15r, %16-19r, %o"},
    {0x03c00000, 0x0fe00000, 0, "bic%20's%c\t%12-15r, %16-19r, %o"},
    {0xe1200070, 0xfff000f0, 0, "bkpt\t0x%16-19X%12-15X%8-11X%0-3X"},
    {0x012fff30, 0x0ffffff0, 0x000fff00, "blx%c\t%0-3R"},
    {0xfa000000, 0xfe000000, 0, "blx\t%B"},
    {0x012fff10, 0x0ffffff0, 0x000fff00, "bx%c\t%0-3r"},
    {0x012fff20, 0x0ffffff0, 0x000fff00, "bxj%c\t%0-3R"},
    {0xf57ff01f, 0xffffffff, 0x000fff0f, "clrex"},
    {0x016f0f10, 0x0fff0ff0, 0x000f0f00, "clz%c\t%12-15R, %0-3R"},
    {0x01600010, 0x0fe00090, 0x0000f000, "cmn%p%c\t%16-19R, %o"},
    {0x01600000, 0x0fe00010, 0x0000f000, "cmn%p%c\t%16-19r, %o"},
    {0x03600000, 0x0fe00000, 0x0000f000, "cmn%p%c\t%16-19r, %o"},
    {0x01400010, 0x0fe00090, 0x0000f000, "cmp%p%c\t%16-19R, %o"},
    {0x01400000, 0x0fe00010, 0x0000f000, "cmp%p%c\t%16-19r, %o"},
    {0x03400000, 0x0fe00000, 0x0000f000, "cmp%p%c\t%16-19r, %o"},
    {0xf1000000, 0xfff1fe20, 0x0000fe00, "cps\t#%0-4d"},
    {0xf10c0000, 0xfffffe3f, 0x0000fe00, "cpsid\t%8'a%7'i%6'f"},
    {0xf10e0000, 0xfffffe20, 0x0000fe00, "cpsid\t%8'a%7'i%6'f,#%0-4d"},
    {0xf1080000, 0xfffffe3f, 0x0000fe00, "cpsie\t%8'a%7'i%6'f"},
    {0xf10a0000, 0xfffffe20, 0x0000fe00, "cpsie\t%8'a%7'i%6'f,#%0-4d"},
    {0xe1000040, 0xfff00ff0, 0x00000d00, "crc32b\t%12-15R, %16-19R, %0-3R"},
    {0xe1000240, 0xfff00ff0, 0x00000d00, "crc32cb\t%12-15R, %16-19R, %0-3R"},
    {0xe1200240, 0xfff00ff0, 0x00000d00, "crc32ch\t%12-15R, %16-19R, %0-3R"},
    {0xe1400240, 0xfff00ff0, 0x00000d00, "crc32cw\t%12-15R, %16-19R, %0-3R"},
    {0xe1200040, 0xfff00ff0, 0x00000d00, "crc32h\t%12-15R, %16-19R, %0-3R"},
    {0xe1400040, 0xfff00ff0, 0x00000d00, "crc32w\t%12-15R, %16-19R, %0-3R"},
    {0xe320f014, 0xffffffff, 0x0000ff00, "csdb"},
    {0x0320f0f0, 0x0ffffff0, 0x0000ff00, "dbg%c\t#%0-3d"},
    {0xf57ff050, 0xfffffff0, 0x000fff00, "dmb\t%U"},
    {0xf57ff051, 0xfffffff3, 0x000fff00, "dmb\t%U"},
    {0xf57ff040, 0xfffffff0, 0x000fff00, "dsb\t%U"},
    {0xf57ff041, 0xfffffff3, 0x000fff00, "dsb\t%U"},
    {0x00200010, 0x0fe00090, 0, "eor%20's%c\t%12-15R, %16-19R, %o"},
    {0x00200000, 0x0fe00010, 0, "eor%20's%c\t%12-15r, %16-19r, %o"},
    {0x02200000, 0x0fe00000, 0, "eor%20's%c\t%12-15r, %16-19r, %o"},
    {0x0160006e, 0x0fffffff, 0x000fff0f, "eret%c"},
    {0xe320f010, 0xffffffff, 0x0000ff00, "esb"},
    {0xe1000070, 0xfff000f0, 0, "hlt\t0x%16-19X%12-15X%8-11X%0-3X"},
    {0x01400070, 0x0ff000f0, 0, "hvc%c\t%e"},
    {0xf57ff060, 0xfffffff0, 0x000fff00, "isb\t%U"},
    {0x01900c9f, 0x0ff00fff, 0x00000c0f, "lda%c\t%12-15r, [%16-19R]"},
    {0x01d00c9f, 0x0ff00fff, 0x00000c0f, "ldab%c\t%12-15r, [%16-19R]"},
    {0x01900e9f, 0x0ff00fff, 0x00000c0f, "ldaex%c\t%12-15r, [%16-19R]"},
    {0x01d00e9f, 0x0ff00fff, 0x00000c0f, "ldaexb%c\t%12-15r, [%16-19R]"},
    {0x01b00e9f, 0x0ff00fff, 0x00000c0f, "ldaexd%c\t%12-15r, %12-15T, [%16-19R]"},
    {0x01f00e9f, 0x0ff00fff, 0x00000c0f, "ldaexh%c\t%12-15r, [%16-19R]"},
    {0x01f00c9f, 0x0ff00fff, 0x00000c0f, "ldah%c\t%12-15r, [%16-19R]"},
    {0x08100000, 0x0e100000, 0, "ldm%23?id%24?ba%c\t%16-19R%21'!, %m%22'^"},
    {0x08900000, 0x0f900000, 0, "ldm%c\t%16-19R%21'!, %m%22'^"},
    // NOTE: 'LDM (User registers)' (p. 4230) not included here (?)
    {0x08bd0001, 0x0fffffff, 0, "ldmfd%c\t%16-19R!, %m"},
    {0x08bd0002, 0x0fffffff, 0, "ldmfd%c\t%16-19R!, %m"},
    {0x08bd0004, 0x0fffffff, 0, "ldmfd%c\t%16-19R!, %m"},
    {0x08bd0008, 0x0fffffff, 0, "ldmfd%c\t%16-19R!, %m"},
    {0x08bd0010, 0x0fffffff, 0, "ldmfd%c\t%16-19R!, %m"},
    {0x08bd0020, 0x0fffffff, 0, "ldmfd%c\t%16-19R!, %m"},
    {0x08bd0040, 0x0fffffff, 0, "ldmfd%c\t%16-19R!, %m"},
    {0x08bd0080, 0x0fffffff, 0, "ldmfd%c\t%16-19R!, %m"},
    {0x08bd0100, 0x0fffffff, 0, "ldmfd%c\t%16-19R!, %m"},
    {0x08bd0200, 0x0fffffff, 0, "ldmfd%c\t%16-19R!, %m"},
    {0x08bd0400, 0x0fffffff, 0, "ldmfd%c\t%16-19R!, %m"},
    {0x08bd0800, 0x0fffffff, 0, "ldmfd%c\t%16-19R!, %m"},
    {0x08bd1000, 0x0fffffff, 0, "ldmfd%c\t%16-19R!, %m"},
    {0x08bd2000, 0x0fffffff, 0, "ldmfd%c\t%16-19R!, %m"},
    {0x08bd4000, 0x0fffffff, 0, "ldmfd%c\t%16-19R!, %m"},
    {0x08bd8000, 0x0fffffff, 0, "ldmfd%c\t%16-19R!, %m"},
    {0x00100090, 0x0e500f90, 0, "ldr%6's%5?hb%c\t%12-15R, %s"},
    {0x00500090, 0x0e500090, 0, "ldr%6's%5?hb%c\t%12-15R, %s"},
    {0x00300090, 0x0f300090, 0, "ldr%6's%5?hbt%c\t%12-15R, %S"},
    {0x04100000, 0x0c500000, 0, "ldr%c\t%12-15r, %a"},
    {0x04500000, 0x0c500000, 0, "ldrb%t%c\t%12-15R, %a"},
    // NOTE: 'LDRD (literal)' (p. 4264) not differentiated? (Assuming reg version)
    {0x000000d0, 0x0e1000f0, 0x00000f00, "ldrd%c\t%12-15r, %s"},
    {0x01900f9f, 0x0ff00fff, 0x00000c0f, "ldrex%c\tr%12-15d, [%16-19R]"},
    {0x01d00f9f, 0x0ff00fff, 0x00000c0f, "ldrexb%c\t%12-15R, [%16-19R]"},
    {0x01b00f9f, 0x0ff00fff, 0x00000c0f, "ldrexd%c\t%12-15r, [%16-19R]"},
    {0x01f00f9f, 0x0ff00fff, 0x00000c0f, "ldrexh%c\t%12-15R, [%16-19R]"},
    // LDRH (register), LDRSB (register), LDRSH (register) ?
    {0x04300000, 0x0d700000, 0, "ldrt%c\t%12-15R, %a"},
    {0x01a00000, 0x0def0060, 0x000f0000, "lsl%20's%c\t%12-15R, %q"},
    {0x01a00020, 0x0def0060, 0x000f0000, "lsr%20's%c\t%12-15R, %q"},
    {0x00200090, 0x0fe000f0, 0, "mla%20's%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
    {0x00600090, 0x0ff000f0, 0, "mls%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
    {0x01a00000, 0x0def0ff0, 0x000f0000, "mov%20's%c\t%12-15r, %0-3r"},
    {0x03a00000, 0x0fef0000, 0x000f0000, "mov%20's%c\t%12-15r, %o"},
    {0x03400000, 0x0ff00000, 0, "movt%c\t%12-15R, %V"},
    // MOVW not in manual?
    {0x03000000, 0x0ff00000, 0, "movw%c\t%12-15R, %V"},
    // MRS here doesn't distinguish between MRS and MRS (Banked)
    {0x01000000, 0x0fb00cff, 0x000f0d0f, "mrs%c\t%12-15R, %R"},
    // Only MSR (banked), not (register)?
    {0x0120f200, 0x0fb0f200, 0x0000fc00, "msr%c\t%C, %0-3r"},
    {0x0120f000, 0x0db0f000, 0x0000f000, "msr%c\t%C, %o"},
    {0x00000090, 0x0fe000f0, 0x0000f000, "mul%20's%c\t%16-19R, %0-3R, %8-11R"},
    {0x01e00010, 0x0fe00090, 0x000f0000, "mvn%20's%c\t%12-15R, %o"},
    {0x01e00000, 0x0fe00010, 0x000f0000, "mvn%20's%c\t%12-15r, %o"},
    {0x03e00000, 0x0fe00000, 0x000f0000, "mvn%20's%c\t%12-15r, %o"},
    {0x03200000, 0x0fff00ff, 0x0000ff00, "nop%c\t{%0-7d}"},
    {0x0320f000, 0x0fffff00, 0x0000ff00, "nop%c\t{%0-7d}"},
    {0x0320f000, 0x0fffffff, 0x0000ff00, "nop%c\t{%0-7d}"},
    {0xe1a00000, 0xffffffff, 0, "nop\t\t\t; (mov r0, r0)"},
    {0x01800010, 0x0fe00090, 0, "orr%20's%c\t%12-15R, %16-19R, %o"},
    {0x01800000, 0x0fe00010, 0, "orr%20's%c\t%12-15r, %16-19r, %o"},
    {0x03800000, 0x0fe00000, 0, "orr%20's%c\t%12-15r, %16-19r, %o"},
    {0x06800010, 0x0ff00ff0, 0, "pkhbt%c\t%12-15R, %16-19R, %0-3R"},
    {0x06800010, 0x0ff00070, 0, "pkhbt%c\t%12-15R, %16-19R, %0-3R, lsl #%7-11d"},
    {0x06800050, 0x0ff00070, 0, "pkhtb%c\t%12-15R, %16-19R, %0-3R, asr #%7-11d"},
    {0x06800050, 0x0ff00ff0, 0, "pkhtb%c\t%12-15R, %16-19R, %0-3R, asr #32"},
    {0xf450f000, 0xfc70f000, 0x0000f000, "pld\t%a"},
    {0xf410f000, 0xfc70f000, 0x0000f000, "pldw\t%a"},
    {0xf450f000, 0xfd70f000, 0x0000f000, "pli\t%P"},
    {0x08bd0000, 0x0fff0000, 0, "pop%c\t%m"},
    {0x049d0004, 0x0fff0fff, 0, "pop%c\t{%12-15r}\t\t; (ldr%c %12-15r, %a)"},
    {0xf57ff044, 0xffffffff, 0x000fff00, "pssbb"},
    {0x092d0000, 0x0fff0000, 0, "push%c\t%m"},
    {0x052d0004, 0x0fff0fff, 0, "push%c\t{%12-15r}\t\t; (str%c %12-15r, %a)"},
    {0x01000050, 0x0ff00ff0, 0x00000f00, "qadd%c\t%12-15R, %0-3R, %16-19R"},
    {0x06200f10, 0x0ff00ff0, 0x00000f00, "qadd16%c\t%12-15R, %16-19R, %0-3R"},
    {0x06200f90, 0x0ff00ff0, 0x00000f00, "qadd8%c\t%12-15R, %16-19R, %0-3R"},
    {0x06200f30, 0x0ff00ff0, 0x00000f00, "qasx%c\t%12-15R, %16-19R, %0-3R"},
    {0x01400050, 0x0ff00ff0, 0x00000f00, "qdadd%c\t%12-15R, %0-3R, %16-19R"},
    {0x01600050, 0x0ff00ff0, 0x00000f00, "qdsub%c\t%12-15R, %0-3R, %16-19R"},
    {0x06200f50, 0x0ff00ff0, 0x00000f00, "qsax%c\t%12-15R, %16-19R, %0-3R"},
    {0x01200050, 0x0ff00ff0, 0x00000f00, "qsub%c\t%12-15R, %0-3R, %16-19R"},
    {0x06200f70, 0x0ff00ff0, 0x00000f00, "qsub16%c\t%12-15R, %16-19R, %0-3R"},
    {0x06200ff0, 0x0ff00ff0, 0x00000f00, "qsub8%c\t%12-15R, %16-19R, %0-3R"},
    {0x06ff0f30, 0x0fff0ff0, 0x000f0f00, "rbit%c\t%12-15R, %0-3R"},
    {0x06bf0f30, 0x0fff0ff0, 0x000f0f00, "rev%c\t%12-15R, %0-3R"},
    {0x06bf0fb0, 0x0fff0ff0, 0x000f0f00, "rev16%c\t%12-15R, %0-3R"},
    {0x06ff0fb0, 0x0fff0ff0, 0x000f0f00, "revsh%c\t%12-15R, %0-3R"},
    {0xf8100a00, 0xfe50ffff, 0x0000ffff, "rfe%23?id%24?ba\t%16-19r%21'!"},
    {0x01a00060, 0x0def0060, 0x000f0000, "ror%20's%c\t%12-15R, %q"},
    {0x01a00060, 0x0def0ff0, 0x000f0000, "rrx%20's%c\t%12-15r, %0-3r"},
    {0x00600010, 0x0fe00090, 0, "rsb%20's%c\t%12-15R, %16-19R, %o"},
    {0x00600000, 0x0fe00010, 0, "rsb%20's%c\t%12-15r, %16-19r, %o"},
    {0x02600000, 0x0fe00000, 0, "rsb%20's%c\t%12-15r, %16-19r, %o"},
    {0x00e00010, 0x0fe00090, 0, "rsc%20's%c\t%12-15R, %16-19R, %o"},
    {0x00e00000, 0x0fe00010, 0, "rsc%20's%c\t%12-15r, %16-19r, %o"},
    {0x02e00000, 0x0fe00000, 0, "rsc%20's%c\t%12-15r, %16-19r, %o"},
    {0x06100f10, 0x0ff00ff0, 0x00000f00, "sadd16%c\t%12-15R, %16-19R, %0-3R"},
    {0x06100f90, 0x0ff00ff0, 0x00000f00, "sadd8%c\t%12-15R, %16-19R, %0-3R"},
    {0x06100f30, 0x0ff00ff0, 0x00000f00, "sasx%c\t%12-15R, %16-19R, %0-3R"},
    {0xf57ff070, 0xffffffff, 0x000fff0f, "sb"},
    {0x00c00010, 0x0fe00090, 0, "sbc%20's%c\t%12-15R, %16-19R, %o"},
    {0x00c00000, 0x0fe00010, 0, "sbc%20's%c\t%12-15r, %16-19r, %o"},
    {0x02c00000, 0x0fe00000, 0, "sbc%20's%c\t%12-15r, %16-19r, %o"},
    {0x0710f010, 0x0ff0f0f0, 0x0000f000, "sdiv%c\t%16-19r, %0-3r, %8-11r"},
    {0x06800fb0, 0x0ff00ff0, 0x00000f00, "sel%c\t%12-15R, %16-19R, %0-3R"},
    {0xf1010000, 0xfffffc00, 0x000efd0f, "setend\t%9?ble"},
    {0xf1100000, 0xfffffdff, 0x000ffd0f, "setpan\t#%9-9d"},
    {0x0320f004, 0x0fffffff, 0, "sev%c"},
    {0x0320f005, 0x0fffffff, 0, "sevl"},
    {0x06300f10, 0x0ff00ff0, 0, "shadd16%c\t%12-15R, %16-19R, %0-3R"},
    {0x06300f90, 0x0ff00ff0, 0, "shadd8%c\t%12-15R, %16-19R, %0-3R"},
    {0x06300f30, 0x0ff00ff0, 0, "shasx%c\t%12-15R, %16-19R, %0-3R"},
    {0x06300f50, 0x0ff00ff0, 0, "shsax%c\t%12-15R, %16-19R, %0-3R"},
    {0x06300f70, 0x0ff00ff0, 0, "shsub16%c\t%12-15R, %16-19R, %0-3R"},
    {0x06300ff0, 0x0ff00ff0, 0, "shsub8%c\t%12-15R, %16-19R, %0-3R"},
    {0x01600070, 0x0ff000f0, 0, "smc%c\t%e"},
    {0x01000080, 0x0ff000f0, 0, "smlabb%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
    {0x010000c0, 0x0ff000f0, 0, "smlabt%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
    {0x07000010, 0x0ff000d0, 0, "smlad%5'x%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
    {0x01400080, 0x0ff000f0, 0, "smlalbb%c\t%12-15Ru, %16-19Ru, %0-3R, %8-11R"},
    {0x014000c0, 0x0ff000f0, 0, "smlalbt%c\t%12-15Ru, %16-19Ru, %0-3R, %8-11R"},
    {0x07400010, 0x0ff000d0, 0, "smlald%5'x%c\t%12-15Ru, %16-19Ru, %0-3R, %8-11R"},
    {0x014000a0, 0x0ff000f0, 0, "smlaltb%c\t%12-15Ru, %16-19Ru, %0-3R, %8-11R"},
    {0x014000e0, 0x0ff000f0, 0, "smlaltt%c\t%12-15Ru, %16-19Ru, %0-3R, %8-11R"},
    {0x010000a0, 0x0ff000f0, 0, "smlatb%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
    {0x010000e0, 0x0ff000f0, 0, "smlatt%c\t%16-19r, %0-3r, %8-11R, %12-15R"},
    {0x01200080, 0x0ff000f0, 0, "smlawb%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
    {0x012000c0, 0x0ff000f0, 0, "smlawt%c\t%16-19R, %0-3r, %8-11R, %12-15R"},
    {0x07000050, 0x0ff000d0, 0, "smlsd%5'x%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
    {0x07400050, 0x0ff000d0, 0, "smlsld%5'x%c\t%12-15Ru, %16-19Ru, %0-3R, %8-11R"},
    {0x07500010, 0x0ff000d0, 0, "smmla%5'r%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
    {0x075000d0, 0x0ff000d0, 0, "smmls%5'r%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
    {0x0750f010, 0x0ff0f0d0, 0, "smmul%5'r%c\t%16-19R, %0-3R, %8-11R"},
    {0x0700f010, 0x0ff0f0d0, 0, "smuad%5'x%c\t%16-19R, %0-3R, %8-11R"},
    {0x01600080, 0x0ff0f0f0, 0, "smulbb%c\t%16-19R, %0-3R, %8-11R"},
    {0x016000c0, 0x0ff0f0f0, 0, "smulbt%c\t%16-19R, %0-3R, %8-11R"},
    {0x016000a0, 0x0ff0f0f0, 0, "smultb%c\t%16-19R, %0-3R, %8-11R"},
    {0x016000e0, 0x0ff0f0f0, 0, "smultt%c\t%16-19R, %0-3R, %8-11R"},
    {0x012000a0, 0x0ff0f0f0, 0, "smulwb%c\t%16-19R, %0-3R, %8-11R"},
    {0x012000e0, 0x0ff0f0f0, 0, "smulwt%c\t%16-19R, %0-3R, %8-11R"},
    {0x0700f050, 0x0ff0f0d0, 0, "smusd%5'x%c\t%16-19R, %0-3R, %8-11R"},
    {0xf84d0500, 0xfe5fffe0, 0, "srs%23?id%24?ba\t%16-19r%21'!, #%0-4d"},
    {0x06a00010, 0x0fe00ff0, 0, "ssat%c\t%12-15R, #%16-20W, %0-3R"},
    {0x06a00050, 0x0fe00070, 0, "ssat%c\t%12-15R, #%16-20W, %0-3R, asr #%7-11d"},
    {0x06a00010, 0x0fe00070, 0, "ssat%c\t%12-15R, #%16-20W, %0-3R, lsl #%7-11d"},
    {0x06a00f30, 0x0ff00ff0, 0, "ssat16%c\t%12-15r, #%16-19W, %0-3r"},
    {0x06100f50, 0x0ff00ff0, 0, "ssax%c\t%12-15R, %16-19R, %0-3R"},
    {0xf57ff040, 0xffffffff, 0, "ssbb"},
    {0x06100f70, 0x0ff00ff0, 0, "ssub16%c\t%12-15R, %16-19R, %0-3R"},
    {0x06100ff0, 0x0ff00ff0, 0, "ssub8%c\t%12-15R, %16-19R, %0-3R"},
    {0x0180fc90, 0x0ff0fff0, 0, "stl%c\t%0-3r, [%16-19R]"},
    {0x01c0fc90, 0x0ff0fff0, 0, "stlb%c\t%0-3r, [%16-19R]"},
    {0x01800e90, 0x0ff00ff0, 0, "stlex%c\t%12-15r, %0-3r, [%16-19R]"},
    {0x01c00e90, 0x0ff00ff0, 0, "stlexb%c\t%12-15r, %0-3r, [%16-19R]"},
    {0x01a00e90, 0x0ff00ff0, 0, "stlexd%c\t%12-15r, %0-3r, %0-3T, [%16-19R]"},
    {0x01e00e90, 0x0ff00ff0, 0, "stlexh%c\t%12-15r, %0-3r, [%16-19R]"},
    {0x01e0fc90, 0x0ff0fff0, 0, "stlh%c\t%0-3r, [%16-19R]"},
    {0x08000000, 0x0e100000, 0, "stm%23?id%24?ba%c\t%16-19R%21'!, %m%22'^"},
    {0x08800000, 0x0ff00000, 0, "stm%c\t%16-19R%21'!, %m%22'^"},
    {0x092d0001, 0x0fffffff, 0, "stmfd%c\t%16-19R!, %m"},
    {0x092d0002, 0x0fffffff, 0, "stmfd%c\t%16-19R!, %m"},
    {0x092d0004, 0x0fffffff, 0, "stmfd%c\t%16-19R!, %m"},
    {0x092d0008, 0x0fffffff, 0, "stmfd%c\t%16-19R!, %m"},
    {0x092d0010, 0x0fffffff, 0, "stmfd%c\t%16-19R!, %m"},
    {0x092d0020, 0x0fffffff, 0, "stmfd%c\t%16-19R!, %m"},
    {0x092d0040, 0x0fffffff, 0, "stmfd%c\t%16-19R!, %m"},
    {0x092d0080, 0x0fffffff, 0, "stmfd%c\t%16-19R!, %m"},
    {0x092d0100, 0x0fffffff, 0, "stmfd%c\t%16-19R!, %m"},
    {0x092d0200, 0x0fffffff, 0, "stmfd%c\t%16-19R!, %m"},
    {0x092d0400, 0x0fffffff, 0, "stmfd%c\t%16-19R!, %m"},
    {0x092d0800, 0x0fffffff, 0, "stmfd%c\t%16-19R!, %m"},
    {0x092d1000, 0x0fffffff, 0, "stmfd%c\t%16-19R!, %m"},
    {0x092d2000, 0x0fffffff, 0, "stmfd%c\t%16-19R!, %m"},
    {0x092d4000, 0x0fffffff, 0, "stmfd%c\t%16-19R!, %m"},
    {0x092d8000, 0x0fffffff, 0, "stmfd%c\t%16-19R!, %m"},
    {0x04000000, 0x0c500010, 0, "str%t%c\t%12-15r, %a"},
    {0x04000000, 0x0e500000, 0, "str%t%c\t%12-15r, %a"},
    {0x06000000, 0x0e500ff0, 0, "str%t%c\t%12-15r, %a"},
    {0x04400000, 0x0e500000, 0, "strb%c\t%12-15R, %a"},
    {0x06400000, 0x0e500010, 0, "strb%c\t%12-15R, %a"},
    {0x04400000, 0x0c500010, 0, "strb%t%c\t%12-15R, %a"},
    {0x04400000, 0x0e500000, 0, "strb%t%c\t%12-15R, %a"},
    {0x06400000, 0x0e500ff0, 0, "strb%t%c\t%12-15R, %a"},
    {0x000000f0, 0x0e1000f0, 0, "strd%c\t%12-15r, %s"},
    {0x01800f90, 0x0ff00ff0, 0, "strex%c\t%12-15R, %0-3R, [%16-19R]"},
    {0x01c00f90, 0x0ff00ff0, 0, "strexb%c\t%12-15R, %0-3R, [%16-19R]"},
    {0x01a00f90, 0x0ff00ff0, 0, "strexd%c\t%12-15R, %0-3r, [%16-19R]"},
    {0x01e00f90, 0x0ff00ff0, 0, "strexh%c\t%12-15R, %0-3R, [%16-19R]"},
    {0x000000b0, 0x0e500ff0, 0, "strh%c\t%12-15R, %s"},
    {0x004000b0, 0x0e5000f0, 0, "strh%c\t%12-15R, %s"},
    {0x002000b0, 0x0f3000f0, 0, "strht%c\t%12-15R, %S"},
    {0x00400010, 0x0fe00090, 0, "sub%20's%c\t%12-15R, %16-19R, %o"},
    {0x00400000, 0x0fe00010, 0, "sub%20's%c\t%12-15r, %16-19r, %o"},
    {0x02400000, 0x0fe00000, 0, "sub%20's%c\t%12-15r, %16-19r, %o"},
    {0x0f000000, 0x0f000000, 0, "svc%c\t%0-23x"},
    {0x01000090, 0x0fb00ff0, 0, "swp%22'b%c\t%12-15RU, %0-3Ru, [%16-19RuU]"},
    {0x06a00070, 0x0ff00ff0, 0, "sxtab%c\t%12-15R, %16-19r, %0-3R"},
    {0x06a00870, 0x0ff00ff0, 0, "sxtab%c\t%12-15R, %16-19r, %0-3R, ror #16"},
    {0x06a00c70, 0x0ff00ff0, 0, "sxtab%c\t%12-15R, %16-19r, %0-3R, ror #24"},
    {0x06a00470, 0x0ff00ff0, 0, "sxtab%c\t%12-15R, %16-19r, %0-3R, ror #8"},
    {0x06800070, 0x0ff00ff0, 0, "sxtab16%c\t%12-15R, %16-19r, %0-3R"},
    {0x06800870, 0x0ff00ff0, 0, "sxtab16%c\t%12-15R, %16-19r, %0-3R, ror #16"},
    {0x06800c70, 0x0ff00ff0, 0, "sxtab16%c\t%12-15R, %16-19r, %0-3R, ror #24"},
    {0x06800470, 0x0ff00ff0, 0, "sxtab16%c\t%12-15R, %16-19r, %0-3R, ror #8"},
    {0x06b00070, 0x0ff00ff0, 0, "sxtah%c\t%12-15R, %16-19r, %0-3R"},
    {0x06b00870, 0x0ff00ff0, 0, "sxtah%c\t%12-15R, %16-19r, %0-3R, ror #16"},
    {0x06b00c70, 0x0ff00ff0, 0, "sxtah%c\t%12-15R, %16-19r, %0-3R, ror #24"},
    {0x06b00470, 0x0ff00ff0, 0, "sxtah%c\t%12-15R, %16-19r, %0-3R, ror #8"},
    {0x06af0070, 0x0fff0ff0, 0, "sxtb%c\t%12-15R, %0-3R"},
    {0x06af0870, 0x0fff0ff0, 0, "sxtb%c\t%12-15R, %0-3R, ror #16"},
    {0x06af0c70, 0x0fff0ff0, 0, "sxtb%c\t%12-15R, %0-3R, ror #24"},
    {0x06af0470, 0x0fff0ff0, 0, "sxtb%c\t%12-15R, %0-3R, ror #8"},
    {0x068f0070, 0x0fff0ff0, 0, "sxtb16%c\t%12-15R, %0-3R"},
    {0x068f0870, 0x0fff0ff0, 0, "sxtb16%c\t%12-15R, %0-3R, ror #16"},
    {0x068f0c70, 0x0fff0ff0, 0, "sxtb16%c\t%12-15R, %0-3R, ror #24"},
    {0x068f0470, 0x0fff0ff0, 0, "sxtb16%c\t%12-15R, %0-3R, ror #8"},
    {0x06bf0070, 0x0fff0ff0, 0, "sxth%c\t%12-15R, %0-3R"},
    {0x06bf0870, 0x0fff0ff0, 0, "sxth%c\t%12-15R, %0-3R, ror #16"},
    {0x06bf0c70, 0x0fff0ff0, 0, "sxth%c\t%12-15R, %0-3R, ror #24"},
    {0x06bf0470, 0x0fff0ff0, 0, "sxth%c\t%12-15R, %0-3R, ror #8"},
    {0x01300010, 0x0ff00010, 0, "teq%p%c\t%16-19R, %o"},
    {0x01300000, 0x0ff00010, 0, "teq%p%c\t%16-19r, %o"},
    {0x03300000, 0x0ff00000, 0, "teq%p%c\t%16-19r, %o"},
    {0x01000010, 0x0fe00090, 0, "tst%p%c\t%16-19R, %o"},
    {0x01000000, 0x0fe00010, 0, "tst%p%c\t%16-19r, %o"},
    {0x03000000, 0x0fe00000, 0, "tst%p%c\t%16-19r, %o"},
    {0x06500f10, 0x0ff00ff0, 0, "uadd16%c\t%12-15R, %16-19R, %0-3R"},
    {0x06500f90, 0x0ff00ff0, 0, "uadd8%c\t%12-15R, %16-19R, %0-3R"},
    {0x06500f30, 0x0ff00ff0, 0, "uasx%c\t%12-15R, %16-19R, %0-3R"},
    {0xe7f000f0, 0xfff000f0, 0, "udf\t#%e"},
    {0x0730f010, 0x0ff0f0f0, 0, "udiv%c\t%16-19r, %0-3r, %8-11r"},
    {0x06700f10, 0x0ff00ff0, 0, "uhadd16%c\t%12-15R, %16-19R, %0-3R"},
    {0x06700f90, 0x0ff00ff0, 0, "uhadd8%c\t%12-15R, %16-19R, %0-3R"},
    {0x06700f30, 0x0ff00ff0, 0, "uhasx%c\t%12-15R, %16-19R, %0-3R"},
    {0x06700f50, 0x0ff00ff0, 0, "uhsax%c\t%12-15R, %16-19R, %0-3R"},
    {0x06700f70, 0x0ff00ff0, 0, "uhsub16%c\t%12-15R, %16-19R, %0-3R"},
    {0x06700ff0, 0x0ff00ff0, 0, "uhsub8%c\t%12-15R, %16-19R, %0-3R"},
    {0x00400090, 0x0ff000f0, 0, "umaal%c\t%12-15R, %16-19R, %0-3R, %8-11R"},
    {0x06600f10, 0x0ff00ff0, 0, "uqadd16%c\t%12-15R, %16-19R, %0-3R"},
    {0x06600f90, 0x0ff00ff0, 0, "uqadd8%c\t%12-15R, %16-19R, %0-3R"},
    {0x06600f30, 0x0ff00ff0, 0, "uqasx%c\t%12-15R, %16-19R, %0-3R"},
    {0x06600f50, 0x0ff00ff0, 0, "uqsax%c\t%12-15R, %16-19R, %0-3R"},
    {0x06600f70, 0x0ff00ff0, 0, "uqsub16%c\t%12-15R, %16-19R, %0-3R"},
    {0x06600ff0, 0x0ff00ff0, 0, "uqsub8%c\t%12-15R, %16-19R, %0-3R"},
    {0x0780f010, 0x0ff0f0f0, 0, "usad8%c\t%16-19R, %0-3R, %8-11R"},
    {0x07800010, 0x0ff000f0, 0, "usada8%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
    {0x06e00010, 0x0fe00ff0, 0, "usat%c\t%12-15R, #%16-20d, %0-3R"},
    {0x06e00050, 0x0fe00070, 0, "usat%c\t%12-15R, #%16-20d, %0-3R, asr #%7-11d"},
    {0x06e00010, 0x0fe00070, 0, "usat%c\t%12-15R, #%16-20d, %0-3R, lsl #%7-11d"},
    {0x06e00f30, 0x0ff00ff0, 0, "usat16%c\t%12-15R, #%16-19d, %0-3R"},
    {0x06500f50, 0x0ff00ff0, 0, "usax%c\t%12-15R, %16-19R, %0-3R"},
    {0x06500f70, 0x0ff00ff0, 0, "usub16%c\t%12-15R, %16-19R, %0-3R"},
    {0x06500ff0, 0x0ff00ff0, 0, "usub8%c\t%12-15R, %16-19R, %0-3R"},
    {0x06e00070, 0x0ff00ff0, 0, "uxtab%c\t%12-15R, %16-19r, %0-3R"},
    {0x06e00870, 0x0ff00ff0, 0, "uxtab%c\t%12-15R, %16-19r, %0-3R, ror #16"},
    {0x06e00c70, 0x0ff00ff0, 0, "uxtab%c\t%12-15R, %16-19r, %0-3R, ror #24"},
    {0x06e00470, 0x0ff00ff0, 0, "uxtab%c\t%12-15R, %16-19r, %0-3R, ror #8"},
    {0x06c00070, 0x0ff00ff0, 0, "uxtab16%c\t%12-15R, %16-19r, %0-3R"},
    {0x06c00c70, 0x0ff00ff0, 0, "uxtab16%c\t%12-15R, %16-19r, %0-3R, ROR #24"},
    {0x06c00870, 0x0ff00ff0, 0, "uxtab16%c\t%12-15R, %16-19r, %0-3R, ror #16"},
    {0x06c00470, 0x0ff00ff0, 0, "uxtab16%c\t%12-15R, %16-19r, %0-3R, ror #8"},
    {0x06f00070, 0x0ff00ff0, 0, "uxtah%c\t%12-15R, %16-19r, %0-3R"},
    {0x06f00870, 0x0ff00ff0, 0, "uxtah%c\t%12-15R, %16-19r, %0-3R, ror #16"},
    {0x06f00c70, 0x0ff00ff0, 0, "uxtah%c\t%12-15R, %16-19r, %0-3R, ror #24"},
    {0x06f00470, 0x0ff00ff0, 0, "uxtah%c\t%12-15R, %16-19r, %0-3R, ror #8"},
    {0x06ef0070, 0x0fff0ff0, 0, "uxtb%c\t%12-15R, %0-3R"},
    {0x06ef0870, 0x0fff0ff0, 0, "uxtb%c\t%12-15R, %0-3R, ror #16"},
    {0x06ef0c70, 0x0fff0ff0, 0, "uxtb%c\t%12-15R, %0-3R, ror #24"},
    {0x06ef0470, 0x0fff0ff0, 0, "uxtb%c\t%12-15R, %0-3R, ror #8"},
    {0x06cf0070, 0x0fff0ff0, 0, "uxtb16%c\t%12-15R, %0-3R"},
    {0x06cf0870, 0x0fff0ff0, 0, "uxtb16%c\t%12-15R, %0-3R, ror #16"},
    {0x06cf0c70, 0x0fff0ff0, 0, "uxtb16%c\t%12-15R, %0-3R, ror #24"},
    {0x06cf0470, 0x0fff0ff0, 0, "uxtb16%c\t%12-15R, %0-3R, ror #8"},
    {0x06ff0070, 0x0fff0ff0, 0, "uxth%c\t%12-15R, %0-3R"},
    {0x06ff0870, 0x0fff0ff0, 0, "uxth%c\t%12-15R, %0-3R, ror #16"},
    {0x06ff0c70, 0x0fff0ff0, 0, "uxth%c\t%12-15R, %0-3R, ror #24"},
    {0x06ff0470, 0x0fff0ff0, 0, "uxth%c\t%12-15R, %0-3R, ror #8"},
    {0x0320f002, 0x0fffffff, 0, "wfe%c"},
    {0x0320f003, 0x0fffffff, 0, "wfi%c"},
    {0x0320f001, 0x0fffffff, 0, "yield%c"},

    {0x00300090, 0x0f3000f0, 0, "UNDEFINED" },
    {0x00000000, 0x00000000, 0, "UNDEFINED"},
    {0x00100090, 0x0e500ff0, 0, "UNDEFINED"},
    {0x00500090, 0x0e5000f0, 0, "UNDEFINED"},
    {0x06000010, 0x0e000010, 0, "UNDEFINED"},
    {0x00000000, 0x00000000, 0, 0}
#endif
};

/*
 * Checks whether insn is a legal/defined instruction that has
 * incorrect should-be-one/should-be-zero bits set. libopcodes
 * often recognizes such instructions as undefined, when they
 * should be constrained unpredictable according to the manual.
 *
 * Without this filter, these instructions will often be marked as
 * hidden, generating a lot of false positives.
 */
static bool has_incorrect_sb_bits(uint32_t insn)
{
    const struct opcode *curr_op;
    for (curr_op = arm_opcodes; curr_op->disassembly; ++curr_op) {
        uint32_t masked_insn = (insn & curr_op->op_mask);
        uint32_t sb_masked_insn = masked_insn & ~(curr_op->sb_mask);
        uint32_t sb_masked_value = curr_op->op_value & ~(curr_op->sb_mask);

        if (sb_masked_insn == sb_masked_value) {
            if (masked_insn != curr_op->op_value) {
                return true;
            } else {
                return false;
            }
        }
    }
    return false;
}

#ifdef __aarch64__
/*
 * Mostly taken from binutils/opcodes/aarch64-opc.c
 * In essence, this checks whether the ldpsw verifier in libopcodes
 * would (incorrectly) mark the instruction as undefined or not.
 */
static bool is_unpredictable_ldpsw(uint32_t insn)
{
#define BIT(INSN,BT)     (((INSN) >> (BT)) & 1)
#define BITS(INSN,HI,LO) (((INSN) >> (LO)) & ((1 << (((HI) - (LO)) + 1)) - 1))

    // Is an LDPSW insn?
    if ((insn & 0xfec00000) != 0x68c00000 && (insn & 0xffc00000) != 0x69400000) {
        return false;
    }

    // Is it unpredictable?
    uint32_t t = BITS(insn, 4, 0);
    uint32_t n = BITS(insn, 9, 5);
    uint32_t t2 = BITS(insn, 14, 10);

    if (BIT(insn, 23)) {
        // Writeback
        if ((t == n || t2 == n) && n != 31) {
            return true;
        }
    }

    if (BIT(insn, 22)) {
        // Load
        if (t == t2) {
            return true;
        }
    }

    return false;
}
#endif

bool filter_instruction(uint32_t insn)
{
#ifdef __aarch64__
    if (is_unpredictable_ldpsw(insn))
        return true;
#endif

    if (has_incorrect_sb_bits(insn))
        return true;

    return false;
}

