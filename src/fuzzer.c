#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
/* #include <time.h> */

#include <capstone/capstone.h>

// This is the "Reserved range", ref. p. 252
#define INSN_RANGE_START 0
#define INSN_RANGE_END (1<<25)

void *insn_buffer;
long page_size;

void signal_handler(int sig_num, siginfo_t *sig_info, void *c_ptr)
{
    ucontext_t* context = (ucontext_t*) c_ptr;
    printf("%d, %d\n", sig_num, sig_num == SIGILL);

    // Ugly encoding of ret instruction...
    ((uint8_t*)insn_buffer)[0] = 0xc0;
    ((uint8_t*)insn_buffer)[1] = 0x03;
    ((uint8_t*)insn_buffer)[2] = 0x5f;
    ((uint8_t*)insn_buffer)[3] = 0xd6;
    /* sleep(1); */
}

void setup_signal_handler(void (*handler)(int, siginfo_t*, void*))
{
    struct sigaction s;

    s.sa_sigaction = handler;
    /* s.sa_flags = SA_SIGINFO|SA_ONSTACK; */
    s.sa_flags = SA_SIGINFO;

    sigfillset(&s.sa_mask);

    sigaction(SIGILL,  &s, NULL);
    /* sigaction(SIGSEGV, &s, NULL); */
    /* sigaction(SIGFPE,  &s, NULL); */
    /* sigaction(SIGBUS,  &s, NULL); */
    /* sigaction(SIGTRAP, &s, NULL); */
}

int main(void)
{
	csh handle;
	cs_insn *insn;
	size_t count;

	if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN, &handle) != CS_ERR_OK) {
        fprintf(stderr, "ERROR: Unable to load capstone\n");
		return -1;
    }


    page_size = sysconf(_SC_PAGE_SIZE);

    // Allocate an executable page / memory region
    insn_buffer = mmap(NULL, page_size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (insn_buffer == MAP_FAILED) {
        perror("insn_buffer mmap failed");
        return -1;
    }

    setup_signal_handler(signal_handler);

    /* uint8_t *code = calloc(4, sizeof(uint8_t)); */
    uint8_t code[8] = {0, 0, 0, 0, 0xc0, 0x03, 0x5f, 0xd6};

    uint64_t errors = 0;
    for (uint64_t i = INSN_RANGE_START; i < INSN_RANGE_END; ++i) {
        code[0] = i & 0xff;
        code[1] = (i >>  8) & 0xff;
        code[2] = (i >> 16) & 0xff;
        code[3] = (i >> 24) & 0xff;

        ((uint8_t*)insn_buffer)[0] = code[0];
        ((uint8_t*)insn_buffer)[1] = code[1];
        ((uint8_t*)insn_buffer)[2] = code[2];
        ((uint8_t*)insn_buffer)[3] = code[3];

        void (*f)() = (void(*)()) insn_buffer;
        f();

        break;
/*         asm("br %[insn_addr]" */
/*             : */
/*             : [insn_addr] "m" (code)); */

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

    /* free(insn_buffer); */
    munmap(insn_buffer, page_size);

	cs_close(&handle);

    return 0;
}
