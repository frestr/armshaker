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
#include <sys/stat.h>
#include <string.h>

#include <capstone/capstone.h>

/* #define PACKAGE */
/* #define PACKAGE_VERSION */
/* #include <dis-asm.h> */

#define STATUSLINE_UPDATE_RATE 0x1000

/*
 * Found by disassemblying every instruction in the instruction space
 * and checking whether it is undefined or not.
 *      TODO: Add an option to calculate this number
 */
#define UNDEFINED_INSTRUCTIONS_TOTAL 3004263502

#define A64_RET 0xd65f03c0

#define INSN_RANGE_MIN 0x00000000
#define INSN_RANGE_MAX 0xffffffff

void *insn_buffer;
long page_size;
volatile sig_atomic_t last_insn_illegal = 0;

void signal_handler(int, siginfo_t*, void*);
void init_signal_handler(void (*handler)(int, siginfo_t*, void*));
void print_help(char*);
int objdump_disassemble(uint32_t, char*, size_t);

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

int objdump_disassemble(uint32_t insn, char *disas_str, size_t disas_str_size)
{
#define OBJDUMP_BUFFER_SIZE 10000
#define OBJDUMP_STRING_SIZE 80

    static char disas_buffer[OBJDUMP_BUFFER_SIZE][OBJDUMP_STRING_SIZE] = {0};
    static uint32_t last_insn = 0;

    if (last_insn != 0
            && insn >= last_insn
            && (insn - last_insn) < OBJDUMP_BUFFER_SIZE) {
        // Retrieve diassembly from buffer
        uint32_t offset = insn - last_insn;
        assert(offset < OBJDUMP_BUFFER_SIZE);
        strncpy(disas_str, disas_buffer[offset], disas_str_size > 80 ? 80 : disas_str_size);
        return 0;
    }

    FILE *insn_fp = fopen("logs/insn_range", "wb");
    if (insn_fp == NULL) {
        fprintf(stderr, "Error opening insn_range.\n");
        return 1;
    }

    uint32_t insns_written = 0;
    // Fill the temp file with consecutive instructions
    for (uint64_t i = insn; i < insn + OBJDUMP_BUFFER_SIZE; ++i) {
        if (i <= INSN_RANGE_MAX) {
            fwrite(&i, 4, 1, insn_fp);
            ++insns_written;
        }
    }

    fflush(insn_fp);

    // Run objdump on the generated file, and prepare the output a little
    FILE *disas_fp = popen("/home/ubuntu/binutils-gdb/binutils/objdump -D -b binary -m aarch64 logs/insn_range"
                           " | awk 'NR>7{$1=$2=\"\"; print}'"
                           " | cut -c3-", "r");

    if (disas_fp == NULL) {
        fprintf(stderr, "Failed to disassemble insn_range with objdump");
        return 1;
    }

    // Read the output from objdump
    char line[80] = {0};
    for (uint32_t i = 0; i < insns_written; ++i) {
        if (fgets(line, sizeof(line), disas_fp) == NULL) {
            fprintf(stderr, "Error reading objdump output\n");
            return 1;
        }
        line[strcspn(line, "\n")] = '\0'; // Remove the newline at the end
        strncpy(disas_buffer[i], line, 80);
    }

    fclose(insn_fp);
    fclose(disas_fp);

    last_insn = insn;

    strncpy(disas_str, disas_buffer[0], disas_str_size > 80 ? 80 : disas_str_size);
    return 0;
}

void print_help(char *cmd_name)
{
    printf("Usage: %s [option(s)]\n", cmd_name);
    printf("\nOptions:\n");
    printf("\t-h\t\tPrint help information\n");
    printf("\t-s <insn>\tStart of instruction search range (in hex) [default: 0x00000000]\n");
    printf("\t-e <insn>\tEnd of instruction search range, inclusive (in hex) [default: 0xffffffff]\n");
    printf("\t-t\t\tCalculate the total amount of undefined instructions, without executing them\n");
}

int main(int argc, char **argv)
{
    uint32_t insn_range_start = INSN_RANGE_MIN;
    uint32_t insn_range_end = INSN_RANGE_MAX; // 2^32 - 1
    bool no_exec = false;

    char *endptr;
    int c;
    while ((c = getopt(argc, argv, "hs:e:t")) != -1) {
        switch (c) {
            case 'h':
                print_help(argv[0]);
                return 1;
            case 's':
                insn_range_start = strtol(optarg, &endptr, 16);
                if (*endptr != '\0') {
                    fprintf(stderr, "ERROR: Unable to read instruction range start\n");
                    return 1;
                }
                break;
            case 'e':
                insn_range_end = strtol(optarg, &endptr, 16);
                if (*endptr != '\0') {
                    fprintf(stderr, "ERROR: Unable to read instruction range end\n");
                    return 1;
                }
                break;
            case 't':
                no_exec = true;
                break;
            default:
                print_help(argv[0]);
                return 1;
        }
    }

    if (insn_range_end < insn_range_start) {
        fprintf(stderr, "ERROR: Instruction range start > instruction range end\n");
        return 1;
    }

	csh handle;
	cs_insn *capstone_insn;

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

    struct stat st = {0};

    // Create log file directory
    if (stat("logs", &st) == -1) {
        if (mkdir("logs", 0755) == -1) {
            perror("Unable to make logs directory");
            return 1;
        }
    }

    // Clear/create log file
    FILE *log_fp = fopen("logs/log.txt", "w");
    if (log_fp == NULL) {
        fprintf(stderr, "Error opening logfile - will print to stdout instead.\n");
    } else {
        fclose(log_fp);
    }

    uint64_t instructions_checked = 0;
    uint64_t instructions_skipped = 0;
    uint32_t hidden_instructions_found = 0;

    uint64_t last_time = get_nano_timestamp();
    uint32_t instructions_per_sec = 0;

    for (uint64_t i = insn_range_start; i <= insn_range_end; ++i) {
        uint32_t curr_insn = i & 0xffffffff;

        // Update the statusline every now and then
        if (i % STATUSLINE_UPDATE_RATE == 0 || i == insn_range_end) {
            if (i != 0) {
                uint64_t curr_time = get_nano_timestamp();
                instructions_per_sec = STATUSLINE_UPDATE_RATE / (double)((curr_time - last_time) / 1e9);
                last_time = curr_time;
            }

            printf("\rinsn: 0x%08" PRIx32 ", "
                   "checked: %" PRIu64 ", "
                   "skipped: %" PRIu64 ", "
                   "found: %" PRIu32 ", "
                   "ips: %" PRIu32 ", "
                   "prog: %.4f%%, "
                   "eta: %.1fhrs   ",
                   curr_insn,
                   instructions_checked,
                   instructions_skipped,
                   hidden_instructions_found,
                   instructions_per_sec,
                   (instructions_checked / (float)UNDEFINED_INSTRUCTIONS_TOTAL) * 100,
                   (UNDEFINED_INSTRUCTIONS_TOTAL - instructions_checked) / (double)(60*60*instructions_per_sec)
                );

            fflush(stdout);
        }


        // Check if capstone thinks the instruction is undefined
        size_t capstone_count = cs_disasm(handle, (uint8_t*)&curr_insn, sizeof(curr_insn), 0, 0, &capstone_insn);

        bool capstone_undefined = (capstone_count == 0);

        // Now check what objdump thinks
        char objdump_str[80];
        int objdump_ret = objdump_disassemble(curr_insn, objdump_str, 80);
        if (objdump_ret != 0) {
            fprintf(stderr, "objdump disassembly failed on insns 0x%08" PRIx32 "\n", curr_insn);
            return 1;
        }
        bool objdump_undefined = (strstr(objdump_str, "undefined") != NULL);

        // Just count the undefined instruction and continue if we're not
        // going to execute it anyway (because of the no_exec flag)
        if (no_exec) {
            if (objdump_undefined && capstone_undefined)
                ++instructions_checked;
            else
                ++instructions_skipped;
            if (capstone_count > 0)
                cs_free(capstone_insn, capstone_count);
            continue;
        }

        /* Only test instructions that both capstone and objdump think are
         * undefined, but report inconsistencies, as they might indicate
         * bugs in either of the disassemblers.
         *
         * The primary reason for this double check is that capstone incorrectly
         * reports instructions defined in Arm ARM as CONSTRAINED UNPREDICTRABLE
         * as errors, leading to lots of false positives.
         *
         * Objdump does not appear to make the same mistake, but might have
         * other issues, so better use both. The performance loss is negligible
         * because of the buffering in the objdump_disas function.
         */
        if (!capstone_undefined || !objdump_undefined) {
            // Write to log if one of the disassemblers thinks the instruction
            // is undefined, but not the other one
            if (capstone_undefined || objdump_undefined) {
                char cs_str[256];
                if (capstone_count > 0) {
                    snprintf(cs_str, sizeof(cs_str), "%s\t%s", capstone_insn[0].mnemonic, capstone_insn[0].op_str);
                } else {
                    strcpy(cs_str, "error");
                }

                log_fp = fopen("logs/log.txt", "a");

                if (log_fp == NULL) {
                    fprintf(stderr, "\nError opening logfile - printing to stdout instead:\n");
                    printf("0x%08" PRIx32 ": cs/objdump inconsistency | cs[%s] / objdump[%s]\n", curr_insn, cs_str, objdump_str);
                } else {
                    fprintf(log_fp, "0x%08" PRIx32 ": cs/objdump inconsistency | cs[%s] / objdump[%s]\n", curr_insn, cs_str, objdump_str);
                    fclose(log_fp);
                }
            }

            if (capstone_count > 0)
                cs_free(capstone_insn, capstone_count);

            ++instructions_skipped;
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
            log_fp = fopen("logs/log.txt", "a");

            if (log_fp == NULL) {
                fprintf(stderr, "\nError opening logfile - printing to stdout instead:\n");
                printf("0x%08" PRIx32 ": Hidden instruction!\n", curr_insn);
            } else {
                fprintf(log_fp, "0x%08" PRIx32 ": Hidden instruction!\n", curr_insn);
                fclose(log_fp);
            }

            ++hidden_instructions_found;
        }

        ++instructions_checked;
    }

    // Compensate for the status line not having a linebreak
    printf("\n");

    if (no_exec)
        printf("Total undefined: %" PRIu64 "\n", instructions_checked);

    munmap(insn_buffer, page_size);

    cs_close(&handle);

    return 0;
}
