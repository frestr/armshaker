#include <stdio.h>
#include <inttypes.h>

#include <capstone/capstone.h>

// This is the "Reserved range", ref. p. 252
#define INSN_RANGE_START 0
#define INSN_RANGE_END (1<<25)

int main(void)
{
	csh handle;
	cs_insn *insn;
	size_t count;

	if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN, &handle) != CS_ERR_OK)
		return -1;

    uint8_t code[4];

    uint64_t errors = 0;
    for (uint64_t i = INSN_RANGE_START; i < INSN_RANGE_END; ++i) {
        code[0] = i & 0xff;
        code[1] = (i >>  8) & 0xff;
        code[2] = (i >> 16) & 0xff;
        code[3] = (i >> 24) & 0xff;

        count = cs_disasm(handle, code, sizeof(code), 0, 0, &insn);
        if (count > 0) {
            size_t j;
            for (j = 0; j < count; j++) {
                if (i % 0x1000000 == 0) {
                    printf("0x%08"PRIx64":\t%s\t\t%s\n", i, insn[j].mnemonic,
                            insn[j].op_str);
                }
            }

            cs_free(insn, count);
        } else {
            if (i % 0x1000000 == 0)
                printf("0x%08"PRIx64": ERROR\n", i);
            ++errors;
        }
    }
    printf("Errors: 0x%" PRIx64 "\n", errors);
	cs_close(&handle);

    return 0;
}
