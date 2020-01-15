#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <ucontext.h>
#include <time.h>
#include <assert.h>
#include <stdlib.h>
#include <malloc.h>

#include <capstone/capstone.h>

// This is the "Reserved range", ref. p. 252
#define INSN_RANGE_START 0
#define INSN_RANGE_END (1<<25)

#define A64_RET 0xd65f03c0
#define A64_NOP 0xd503201f

void *insn_buffer;
long page_size;
volatile sig_atomic_t last_insn_illegal = 0;
volatile sig_atomic_t errors = 0;

extern char resume;

void signal_handler(int, siginfo_t*, void*);
void init_signal_handler(void (*handler)(int, siginfo_t*, void*));

typedef struct {
    uint64_t gen_regs[31];
    uint64_t sp;
    uint64_t pc;
    // Note: in reality V0-V31 are 128 bits. We only store the first half here
    uint64_t vec_regs[32];
    uint64_t fpcr;          // Floating point control reg
    uint64_t fpsr;          // Floating point status reg
    uint64_t pstate_nzcv;   // Condition flags
    uint64_t pstate_daif;   // Exception masking
} state_t;

state_t base_state = {
    .gen_regs = {0},
    .sp = 0,
    .pc = 0,
    .vec_regs = {0},
    .fpcr = 0,
    .fpsr = 0,
    .pstate_nzcv = 0,
    .pstate_daif = 0,
};

void signal_handler(int sig_num, siginfo_t *sig_info, void *uc_ptr)
{
    // Suppress unused warning
    (void)sig_info;

    ucontext_t* uc = (ucontext_t*) uc_ptr;

    if (sig_num == SIGILL)
        last_insn_illegal = 1;

    errors++;

    // Jump to the next instruction (i.e. skip the illegal insn)
    uc->uc_mcontext.pc = (uintptr_t)(insn_buffer) + 4;
    /* uc->uc_mcontext.pc = (uintptr_t)&resume; */
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

    /* insn_buffer = aligned_alloc(page_size, page_size); */
    /* assert(!mprotect(insn_buffer, page_size, PROT_READ|PROT_WRITE|PROT_EXEC)); */

    // Set the SECOND instruction to be a ret
    *((uint32_t*)insn_buffer+1) = A64_RET;

    // Jumps to the instruction buffer
    void (*execute_insn_buffer)() = (void(*)()) insn_buffer;

    uint32_t curr_insn;

    for (uint64_t i = INSN_RANGE_START; i < INSN_RANGE_END; ++i) {
        curr_insn = i & 0xffffffff;

        if (i % 0x4000 == 0)
            curr_insn = A64_NOP;

        // Update the first instruction in the instruction buffer
        *((uint32_t*)insn_buffer) = curr_insn;

        if (i % 0x1000 == 0)
            printf("0x%08x: fuzzing...\n", curr_insn);

        last_insn_illegal = 0;

        // Invalide the insn_addr in the data and instruction caches
        // (Some instructions might be skipped otherwise.)
        asm volatile("\
                dc civac, %[insn_buffer]    \n\
                ic ivau, %[insn_buffer]     \n\
                "
                :
                : [insn_buffer] "r" (insn_buffer)
            );

        execute_insn_buffer();

/*         asm volatile("\ */
/*                 dc civac, %[last]   \n\ */
/*                 " : : [last] "r" (&last_insn_illegal) */
/*             ); */

        /* ucontext_t pre_context; */
        /* getcontext(&pre_context); */

/*         asm volatile("br %[buffer]" : : [buffer] "r" (insn_buffer)); */

        count = cs_disasm(handle, (uint8_t*)&curr_insn, sizeof(curr_insn), 0, 0, &insn);

        if (count > 0) {
            if (last_insn_illegal) {
                for (size_t j = 0; j < count; j++) {
                    printf("0x%08x: Unavailable instruction (from EL0): %s\t\t%s\n",
                           curr_insn, insn[j].mnemonic, insn[j].op_str);
                }
            }
            cs_free(insn, count);
        } else {
            if (!last_insn_illegal) {
                printf("0x%08x: Hidden instruction!\n", curr_insn);
            }
        }

    }

    printf("Tested: %" PRIu64 ". Errors: %" PRIu64 "\n", (uint64_t)(INSN_RANGE_END - INSN_RANGE_START), (uint64_t)errors);

    munmap(insn_buffer, page_size);
    /* free(insn_buffer); */

	cs_close(&handle);

    return 0;
}
