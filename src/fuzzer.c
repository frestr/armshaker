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
#include <time.h>

#include <capstone/capstone.h>

#define INSN_RANGE_START 0
#define INSN_RANGE_END 0x100000000 // 1<<32

#define STATUSLINE_UPDATE_RATE 0x345

/*
 * Found by disassemblying every instruction in the instruction space
 * and checking whether it is undefined or not.
 *      TODO: Add an option to calculate this number
 */
#define UNDEFINED_INSTRUCTIONS_TOTAL 3004263502

#define A64_RET 0xd65f03c0

void *insn_buffer;
long page_size;
volatile sig_atomic_t last_insn_illegal = 0;

void signal_handler(int, siginfo_t*, void*);
void init_signal_handler(void (*handler)(int, siginfo_t*, void*));

void signal_handler(int sig_num, siginfo_t *sig_info, void *uc_ptr)
{
    // Suppress unused warning
    (void)sig_info;

    ucontext_t* uc = (ucontext_t*) uc_ptr;

    if (sig_num == SIGILL)
        last_insn_illegal = 1;

    // Jump to the next instruction (i.e. skip the illegal insn)
    uc->uc_mcontext.pc = (uintptr_t)(insn_buffer) + 4;
}

void init_signal_handler(void (*handler)(int, siginfo_t*, void*))
{
    struct sigaction s;

    s.sa_sigaction = handler;
    s.sa_flags = SA_SIGINFO;

    sigfillset(&s.sa_mask);

    sigaction(SIGILL,  &s, NULL);
}

static uint64_t get_nano_timestamp(void) {
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    return (uint64_t)ts.tv_sec * 1000000000L + ts.tv_nsec;
}

int main(void)
{
	csh handle;
	cs_insn *insn;
	size_t count;

	if (cs_open(CS_ARCH_ARM64,
                CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN,
                &handle) != CS_ERR_OK) {
        fprintf(stderr, "ERROR: Unable to load capstone\n");
		return 1;
    }

    init_signal_handler(signal_handler);

    page_size = sysconf(_SC_PAGE_SIZE);

    // Allocate an executable page / memory region
    insn_buffer = mmap(NULL,
                       page_size,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS,
                       -1,
                       0);

    if (insn_buffer == MAP_FAILED) {
        perror("insn_buffer mmap failed");
        return 1;
    }

    // Set the SECOND instruction to be a ret
    *((uint32_t*)insn_buffer+1) = A64_RET;

    // Jumps to the instruction buffer
    void (*execute_insn_buffer)() = (void(*)()) insn_buffer;

    // Clear/create log file
    FILE *log_fp = fopen("log.txt", "w");
    if (log_fp == NULL) {
        fprintf(stderr, "Error opening logfile - will print to stdout instead.\n");
    } else {
        fclose(log_fp);
    }

    uint32_t curr_insn;
    uint64_t instructions_checked = 0;
    uint32_t hidden_instructions_found = 0;

    uint64_t last_time = get_nano_timestamp();
    uint32_t instructions_per_sec = 0;

    for (uint64_t i = INSN_RANGE_START; i < INSN_RANGE_END; ++i) {
        curr_insn = i & 0xffffffff;

        // Update the statusline every now and then
        if (i % STATUSLINE_UPDATE_RATE == 0) {
            if (i != 0) {
                uint64_t curr_time = get_nano_timestamp();
                instructions_per_sec = STATUSLINE_UPDATE_RATE / (double)((curr_time - last_time) / 1e9);
                last_time = curr_time;
            }

            printf("\rinsn: 0x%08" PRIx32 ", "
                   "checked: %" PRIu64 ", "
                   "found: %" PRIu32 ", "
                   "ips: %" PRIu32 ", "
                   "prog: %.4f%%, "
                   "eta: %.1fhrs   ",
                   curr_insn,
                   instructions_checked,
                   hidden_instructions_found,
                   instructions_per_sec,
                   (instructions_checked / (float)UNDEFINED_INSTRUCTIONS_TOTAL) * 100,
                   (UNDEFINED_INSTRUCTIONS_TOTAL - instructions_checked) / (double)(60*60*instructions_per_sec)
                );

            fflush(stdout);
        }

        count = cs_disasm(handle, (uint8_t*)&curr_insn, sizeof(curr_insn), 0, 0, &insn);

        // Only test instructions that the disassembler thinks are undefined
        if (count > 0) {
            cs_free(insn, count);
            continue;
        }

        // Update the first instruction in the instruction buffer
        *((uint32_t*)insn_buffer) = curr_insn;

        last_insn_illegal = 0;

        /*
         * Invalidate insn_buffer in the d- and icache and force the changes
         * (Some instructions might be skipped otherwise.)
         *      dc civac = clean and invalidate data cache at addr
         *      ic ivau  = invalidate instruction cache at addr
         *      dsb sy   = memory barrier
         *      isb      = flush instruction pipeline
         */
        asm volatile(
                "dc civac, %[insn_buffer]    \n"
                "ic ivau, %[insn_buffer]     \n"
                "dsb sy                      \n"
                "isb                         \n"
                :
                : [insn_buffer] "r" (insn_buffer)
            );

        // Jump to the instruction to be tested (and execute it)
        execute_insn_buffer();

        if (!last_insn_illegal) {
            log_fp = fopen("log.txt", "a");

            if (log_fp == NULL) {
                fprintf(stderr, "\nError opening logfile - printing to stdout instead:\n");
                printf("Hidden instruction found: 0x%08" PRIx32 "\n", curr_insn);
            } else {
                fprintf(log_fp, "Hidden instruction found: 0x%08" PRIx32 "\n", curr_insn);
                fclose(log_fp);
            }

            ++hidden_instructions_found;
        }

        ++instructions_checked;
    }

    // Compensate for the status line not having a linebreak
    printf("\n");

    munmap(insn_buffer, page_size);

    cs_close(&handle);

    return 0;
}
