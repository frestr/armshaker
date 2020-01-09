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

#define A64_RET 0xd65f03c0

void *insn_buffer;
long page_size;
bool last_insn_illegal;

void signal_handler(int sig_num, siginfo_t *sig_info, void *uc_ptr)
{
    ucontext_t* uc = (ucontext_t*) uc_ptr;

    if (sig_num == SIGILL)
        last_insn_illegal = true;

    // Jump to the next instruction (i.e. skip the illegal insn)
    uc->uc_mcontext.pc = (long long unsigned int)(insn_buffer) + 4;
}

void init_signal_handler(void (*handler)(int, siginfo_t*, void*))
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

    init_signal_handler(signal_handler);

    page_size = sysconf(_SC_PAGE_SIZE);

    // Allocate an executable page / memory region
    insn_buffer = mmap(NULL, page_size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (insn_buffer == MAP_FAILED) {
        perror("insn_buffer mmap failed");
        exit(-1);
    }

    // Set the SECOND instruction to be a ret
    *((uint32_t*)insn_buffer+1) = A64_RET;

    // Jumps to the instruction buffer
    void (*execute_insn_buffer)() = (void(*)()) insn_buffer;

    uint32_t curr_insn;

    for (uint64_t i = INSN_RANGE_START; i < INSN_RANGE_END; ++i) {
        curr_insn = i & 0xffffffff;

        // Update the first instruction in the instruction buffer
        *((uint32_t*)insn_buffer) = curr_insn;

        last_insn_illegal = false;
        execute_insn_buffer();

        if (i % 10000 == 0)
            printf("%" PRIu64 "\n", i);

        count = cs_disasm(handle, (uint8_t*)&curr_insn, sizeof(curr_insn), 0, 0, &insn);

        // If count == 0 but last_insn_illegal == false: hidden instruction

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
        }
    }
    munmap(insn_buffer, page_size);

	cs_close(&handle);

    return 0;
}
