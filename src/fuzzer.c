#define _GNU_SOURCE
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
#include <getopt.h>
#include <libgen.h>
#include <sys/file.h>

#include <capstone/capstone.h>

/*
 * Defines needed for bfd "bug":
 * https://github.com/mlpack/mlpack/issues/574
 */
#define PACKAGE
#define PACKAGE_VERSION
#include <dis-asm.h>

#define STATUS_UPDATE_RATE 0x200

// According to capstone+libopcodes (constrained unpredictable excluded)
#define UNDEFINED_INSTRUCTIONS_TOTAL 2757385481

// According to capstone
/* #define UNDEFINED_INSTRUCTIONS_TOTAL 3004263502 */

#define INSN_RANGE_MIN 0x00000000
#define INSN_RANGE_MAX 0xffffffff

#define PAGE_SIZE 4096

typedef struct {
    uint32_t curr_insn;
    char cs_disas[256];
    char libopcodes_disas[256];
    uint64_t instructions_checked;
    uint64_t instructions_skipped;
    uint64_t hidden_instructions_found;
    uint64_t disas_discrepancies;
    uint64_t instructions_per_sec;
} search_status;

void *insn_buffer;
void *null_pages;
volatile sig_atomic_t last_insn_illegal = 0;
uint32_t insn_offset = 0;

void signal_handler(int, siginfo_t*, void*);
void init_signal_handler(void (*handler)(int, siginfo_t*, void*));
void execution_boilerplate(void);
uint64_t get_nano_timestamp(void);
int disas_sprintf(void*, const char*, ...);
int libopcodes_disassemble(uint32_t, char*, size_t);
void print_statusline(search_status*);
int write_statusfile(char*, search_status*);
void print_help(char*);

extern char boilerplate_start, boilerplate_end, insn_location;

void signal_handler(int sig_num, siginfo_t *sig_info, void *uc_ptr)
{
    // Suppress unused warning
    (void)sig_info;

    ucontext_t* uc = (ucontext_t*) uc_ptr;

    if (sig_num == SIGILL)
        last_insn_illegal = 1;

    // Jump to the next instruction (i.e. skip the illegal insn)
    uc->uc_mcontext.pc = (uintptr_t)(insn_buffer) + (insn_offset+1)*4;
}

void init_signal_handler(void (*handler)(int, siginfo_t*, void*))
{
    struct sigaction s;

    s.sa_sigaction = handler;
    s.sa_flags = SA_SIGINFO;

    sigfillset(&s.sa_mask);

    sigaction(SIGILL,  &s, NULL);
}

/*
 * State management when testing instructions.
 *
 * Used to prevent instructions with side-effects to corrupt the program
 * state, in addition to saving register values for analysis.
 */
void execution_boilerplate(void)
{
    asm volatile(
            ".global boilerplate_start  \n"
            "boilerplate_start:         \n"

            // Store all gregs
            "stp x0, x1, [sp, #-16]!    \n"
            "stp x2, x3, [sp, #-16]!    \n"
            "stp x4, x5, [sp, #-16]!    \n"
            "stp x6, x7, [sp, #-16]!    \n"
            "stp x8, x9, [sp, #-16]!    \n"
            "stp x10, x11, [sp, #-16]!  \n"
            "stp x12, x13, [sp, #-16]!  \n"
            "stp x14, x15, [sp, #-16]!  \n"
            "stp x16, x17, [sp, #-16]!  \n"
            "stp x18, x19, [sp, #-16]!  \n"
            "stp x20, x21, [sp, #-16]!  \n"
            "stp x22, x23, [sp, #-16]!  \n"
            "stp x24, x25, [sp, #-16]!  \n"
            "stp x26, x27, [sp, #-16]!  \n"
            "stp x28, x29, [sp, #-16]!  \n"
            "stp x30, xzr, [sp, #-16]!  \n"

            // Reset the regs to make insn execution deterministic
            // and avoid program corruption
            "mov x0, #%[reg_init]       \n"
            "mov x1, #%[reg_init]       \n"
            "mov x2, #%[reg_init]       \n"
            "mov x3, #%[reg_init]       \n"
            "mov x4, #%[reg_init]       \n"
            "mov x5, #%[reg_init]       \n"
            "mov x6, #%[reg_init]       \n"
            "mov x7, #%[reg_init]       \n"
            "mov x8, #%[reg_init]       \n"
            "mov x9, #%[reg_init]       \n"
            "mov x10, #%[reg_init]      \n"
            "mov x11, #%[reg_init]      \n"
            "mov x12, #%[reg_init]      \n"
            "mov x13, #%[reg_init]      \n"
            "mov x14, #%[reg_init]      \n"
            "mov x15, #%[reg_init]      \n"
            "mov x16, #%[reg_init]      \n"
            "mov x17, #%[reg_init]      \n"
            "mov x18, #%[reg_init]      \n"
            "mov x19, #%[reg_init]      \n"
            "mov x20, #%[reg_init]      \n"
            "mov x21, #%[reg_init]      \n"
            "mov x22, #%[reg_init]      \n"
            "mov x23, #%[reg_init]      \n"
            "mov x24, #%[reg_init]      \n"
            "mov x25, #%[reg_init]      \n"
            "mov x26, #%[reg_init]      \n"
            "mov x27, #%[reg_init]      \n"
            "mov x28, #%[reg_init]      \n"
            "mov x29, #%[reg_init]      \n"
            "mov x30, #%[reg_init]      \n"

            ".global insn_location      \n"
            "insn_location:             \n"

            // This instruction will be replaced with the one to be tested
            "nop                        \n"

            // Restore all gregs
            "ldp x30, xzr, [sp], #16    \n"
            "ldp x28, x29, [sp], #16    \n"
            "ldp x26, x27, [sp], #16    \n"
            "ldp x24, x25, [sp], #16    \n"
            "ldp x22, x23, [sp], #16    \n"
            "ldp x20, x21, [sp], #16    \n"
            "ldp x18, x19, [sp], #16    \n"
            "ldp x16, x17, [sp], #16    \n"
            "ldp x14, x15, [sp], #16    \n"
            "ldp x12, x13, [sp], #16    \n"
            "ldp x10, x11, [sp], #16    \n"
            "ldp x8, x9, [sp], #16      \n"
            "ldp x6, x7, [sp], #16      \n"
            "ldp x4, x5, [sp], #16      \n"
            "ldp x2, x3, [sp], #16      \n"
            "ldp x0, x1, [sp], #16      \n"

            "ret                        \n"
            ".global boilerplate_end    \n"
            "boilerplate_end:           \n"
            :
            : [reg_init] "n" (PAGE_SIZE)
            );
}

uint64_t get_nano_timestamp(void) {
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    return (uint64_t)ts.tv_sec * 1000000000L + ts.tv_nsec;
}

typedef struct {
  char *buffer;
  bool reenter;
} stream_state;

/*
 * From
 *  https://blog.yossarian.net/2019/05/18/Basic-disassembly-with-libopcodes
 * Thanks
 */
int disas_sprintf(void *stream, const char *fmt, ...) {
    stream_state *ss = (stream_state *)stream;

    size_t n;
    va_list arg;
    va_start(arg, fmt);

    if (!ss->reenter) {
        n = vasprintf(&ss->buffer, fmt, arg);
        ss->reenter = true;
    } else {
        char *tmp;
        n = vasprintf(&tmp, fmt, arg);

        char *tmp2;
        n = asprintf(&tmp2, "%s%s", ss->buffer, tmp);
        free(ss->buffer);
        free(tmp);
        ss->buffer = tmp2;
    }
    va_end(arg);

    // ugh...
    (void)n;

    return 0;
}

int libopcodes_disassemble(uint32_t insn, char *disas_str, size_t disas_str_size) {
    stream_state ss = {};

    // Set up the disassembler
    disassemble_info disasm_info = {};
    init_disassemble_info(&disasm_info, &ss, (fprintf_ftype) disas_sprintf);
    disasm_info.arch = bfd_arch_aarch64;
    disasm_info.mach = bfd_mach_aarch64;
    disasm_info.read_memory_func = buffer_read_memory;
    disasm_info.buffer = (uint8_t*)&insn;
    disasm_info.buffer_vma = 0;
    disasm_info.buffer_length = 4;
    disassemble_init_for_target(&disasm_info);

    disassembler_ftype disasm;
    disasm = disassembler(bfd_arch_aarch64, false, bfd_mach_aarch64, NULL);

    // Actually do the disassembly
    size_t insn_size = disasm(0, &disasm_info);
    assert(insn_size == 4);

    // Store the resulting stsring
    snprintf(disas_str, disas_str_size, "%s", ss.buffer);

    ss.reenter = false;
    free(ss.buffer);

    return 0;
}

void print_statusline(search_status *status)
{
    printf("\rinsn: 0x%08" PRIx32 ", "
           "checked: %" PRIu64 ", "
           "skipped: %" PRIu64 ", "
           "hidden: %" PRIu64 ", "
           "discreps: %" PRIu64 ", "
           "ips: %" PRIu64 "   ",
           status->curr_insn,
           status->instructions_checked,
           status->instructions_skipped,
           status->hidden_instructions_found,
           status->disas_discrepancies,
           status->instructions_per_sec
        );

    fflush(stdout);
}

int write_statusfile(char *filepath, search_status *status)
{
    FILE *fp = fopen(filepath, "w");
    if (fp == NULL) {
        return -1;
    }

    if (flock(fileno(fp), LOCK_EX) == -1) {
        perror("Locking statusfile failed");
        return -1;
    }

    fprintf(fp,
            "curr_insn:%08" PRIx32 "\n"
            "cs_disas:%s\n"
            "libopcodes_disas:%s\n"
            "instructions_checked:%" PRIu64 "\n"
            "instructions_skipped:%" PRIu64 "\n"
            "hidden_instructions_found:%" PRIu64 "\n"
            "disas_discrepancies:%" PRIu64 "\n"
            "instructions_per_sec:%" PRIu64 "\n",
            status->curr_insn,
            status->cs_disas,
            status->libopcodes_disas,
            status->instructions_checked,
            status->instructions_skipped,
            status->hidden_instructions_found,
            status->disas_discrepancies,
            status->instructions_per_sec
        );

    if (flock(fileno(fp), LOCK_UN) == -1) {
        perror("Unlocking statusfile failed");
        return -1;
    }

    fclose(fp);
    return 0;
}

struct option long_options[] = {
    {"help",            no_argument,        NULL, 'h'},
    {"start",           required_argument,  NULL, 's'},
    {"end",             required_argument,  NULL, 'e'},
    {"no-exec",         no_argument,        NULL, 'n'},
    {"disable-null",    no_argument,        NULL, 'd'},
    {"log-suffix",      required_argument,  NULL, 'l'},
    {"quiet",           required_argument,  NULL, 'q'},
    {"discreps",        no_argument,        NULL, 'c'}
};

void print_help(char *cmd_name)
{
    printf("Usage: %s [option(s)]\n", cmd_name);
    printf("\nOptions:\n");
    printf("\t-h, --help\t\tPrint help information\n");
    printf("\t-s, --start <insn>\tStart of instruction search range (in hex) [default: 0x00000000]\n");
    printf("\t-e, --end <insn>\tEnd of instruction search range, inclusive (in hex) [default: 0xffffffff]\n");
    printf("\t-n, --no-exec\t\tCalculate the total amount of undefined instructions, without executing them\n");
    printf("\t-d, --disable-null\tDisable null page allocation. This might lead to segfaults for certain instructions.\n");
    printf("\t-l, --log-suffix\tAdd a suffix to the log and status file.\n");
    printf("\t-q, --quiet\tDon't print the status line.\n");
    printf("\t-c, --discreps\tLog disassembler discrepancies.\n");
}

int main(int argc, char **argv)
{
    uint32_t insn_range_start = INSN_RANGE_MIN;
    uint32_t insn_range_end = INSN_RANGE_MAX; // 2^32 - 1
    bool no_exec = false;
    bool allocate_null_pages = true;
    bool quiet = false;
    bool log_discreps = false;

    char *file_suffix = NULL;
    char *endptr;
    int c;
    while ((c = getopt_long(argc, argv, "hs:e:tdl:qc", long_options, NULL)) != -1) {
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
            case 'n':
                no_exec = true;
                break;
            case 'd':
                allocate_null_pages = false;
                break;
            case 'l':
                if (asprintf(&file_suffix, "%s", optarg) == -1) {
                    fprintf(stderr, "ERROR: asprintf with file_suffix failed\n");
                    return 1;
                }
                break;
            case 'q':
                quiet = true;
                break;
            case 'c':
                log_discreps = true;
                break;
            default:
                print_help(argv[0]);
                return 1;
        }
    }

    char *log_path;
    if (asprintf(&log_path, "%s%s", "data/log", file_suffix == NULL ? "" : file_suffix) == -1) {
        fprintf(stderr, "ERROR: asprintf with log_path failed\n");
        return 1;
    }

    char *statusfile_path;
    if (asprintf(&statusfile_path, "%s%s", "data/status", file_suffix == NULL ? "" : file_suffix) == -1) {
        fprintf(stderr, "ERROR: asprintf with statusfile_path failed\n");
        return 1;
    }
    if (file_suffix != NULL)
        free(file_suffix);

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

    /* page_size = sysconf(_SC_PAGE_SIZE); */

    // Allocate an executable page / memory region
    insn_buffer = mmap(NULL,
                       PAGE_SIZE,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS,
                       -1,
                       0);

    if (insn_buffer == MAP_FAILED) {
        perror("insn_buffer mmap failed");
        return 1;
    }

    uint32_t boilerplate_length = (&boilerplate_end - &boilerplate_start) / 4;

    // Load the boilerplate assembly
    for (uint32_t i = 0; i < boilerplate_length; ++i)
        ((uint32_t*)insn_buffer)[i] = ((uint32_t*)&boilerplate_start)[i];

    insn_offset = (&insn_location - &boilerplate_start) / 4;

    // Jumps to the instruction buffer
    void (*execute_insn_buffer)() = (void(*)()) insn_buffer;

    if (allocate_null_pages) {
        /*
         * Allocate two pages starting at address 0.
         * This is to prevent segfaults when running insns like [x0] when x0 is 0.
         *
         * If I read Arm ARM correctly, the max offset for register loads are
         * 12 bits, so one page (4096 bytes) should be enough. The reason for
         * allocating two pages is to allow for negative address offsets.
         */
        null_pages = mmap(0,
                          PAGE_SIZE * 2,
                          PROT_READ | PROT_WRITE,
                          MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
                          -1,
                          0);

        if (null_pages == MAP_FAILED) {
            perror("null_pages mmap failed (no root?)");
            printf("If you really want to run without allocating null pages, run with -d\n");
            return 1;
        }
    }

    struct stat st = {0};

    // Create data directory
    if (stat("data", &st) == -1) {
        if (mkdir("data", 0755) == -1) {
            perror("Unable to make data directory");
            return 1;
        }
    }

    // Clear/create log file
    FILE *log_fp = fopen(log_path, "w");
    if (log_fp == NULL) {
        fprintf(stderr, "Error opening logfile - will print to stdout instead.\n");
    } else {
        fclose(log_fp);
    }

    uint64_t instructions_checked = 0;
    uint64_t instructions_skipped = 0;
    uint64_t hidden_instructions_found = 0;
    uint64_t disas_discreps_found = 0;
    uint64_t last_timestamp = get_nano_timestamp();

    search_status curr_status = {0};

    for (uint64_t i = insn_range_start; i <= insn_range_end; ++i) {
        uint32_t curr_insn = i & 0xffffffff;

        // Check if capstone thinks the instruction is undefined
        size_t capstone_count = cs_disasm(handle, (uint8_t*)&curr_insn, sizeof(curr_insn), 0, 0, &capstone_insn);
        bool capstone_undefined = (capstone_count == 0);
        char cs_str[256] = {0};
        if (capstone_count > 0) {
            snprintf(cs_str,
                     sizeof(cs_str),
                     "%s\t%s", capstone_insn[0].mnemonic, capstone_insn[0].op_str);
        } else {
            strcpy(cs_str, "invalid assembly code");
        }

        // Now check what libopcodes thinks
        char libopcodes_str[265] = {0};
        int libopcodes_ret = libopcodes_disassemble(curr_insn, libopcodes_str, sizeof(libopcodes_str));
        if (libopcodes_ret != 0) {
            fprintf(stderr, "libopcodes disassembly failed on insn 0x%08" PRIx32 "\n", curr_insn);
            return 1;
        }

        // Write the current search status to the statusfile now and then
        if (i % STATUS_UPDATE_RATE == 0 || i == insn_range_end) {
            curr_status.curr_insn = curr_insn;
            strncpy(curr_status.cs_disas, cs_str, sizeof(curr_status.cs_disas));
            strncpy(curr_status.libopcodes_disas,
                    libopcodes_str,
                    sizeof(curr_status.libopcodes_disas));
            curr_status.instructions_checked = instructions_checked;
            curr_status.instructions_skipped = instructions_skipped;
            curr_status.disas_discrepancies = disas_discreps_found;
            curr_status.hidden_instructions_found = hidden_instructions_found;

            uint64_t curr_timestamp = get_nano_timestamp();
            curr_status.instructions_per_sec =
                STATUS_UPDATE_RATE / (double)((curr_timestamp - last_timestamp) / 1e9);
            last_timestamp = curr_timestamp;

            if (write_statusfile(statusfile_path, &curr_status) == -1) {
                fprintf(stderr, "ERROR: Failed to write to statusfile\n");
            }

            if (!quiet)
                print_statusline(&curr_status);
        }

        bool libopcodes_undefined = (strstr(libopcodes_str, "undefined") != NULL
                                  || strstr(libopcodes_str, "NYI") != NULL);

        /*
         * TODO: Also check for (constrained) unpredictable instructions.
         * Proper recovery after executing instructions with side effects
         * need to be in place first though.
         */

        // Just count the undefined instruction and continue if we're not
        // going to execute it anyway (because of the no_exec flag)
        if (no_exec) {
            if (libopcodes_undefined && capstone_undefined)
                ++instructions_checked;
            else
                ++instructions_skipped;
            if (capstone_count > 0)
                cs_free(capstone_insn, capstone_count);
            continue;
        }

        /* Only test instructions that both capstone and libopcodes think are
         * undefined, but report inconsistencies, as they might indicate
         * bugs in either of the disassemblers.
         *
         * The primary reason for this double check is that capstone apparently
         * generates a lot of false positives.
         *
         * libopcodes does not appear to make the same mistake, but might have
         * other issues, so better use both. libopcodes is a bit slower, but
         * actually executing the insns takes so long anyway.
         */
        if (!capstone_undefined || !libopcodes_undefined) {
            // Write to log if one of the disassemblers thinks the instruction
            // is undefined, but not the other one
            if (capstone_undefined || libopcodes_undefined) {
                if (log_discreps) {
                        log_fp = fopen(log_path, "a");

                        if (log_fp == NULL) {
                            printf("0x%08" PRIx32 " | discrepancy: cs{%s} / libopc{%s}\n", curr_insn, cs_str, libopcodes_str);
                        } else {
                            fprintf(log_fp, "0x%08" PRIx32 " | discrepancy: cs{%s} / libopc{%s}\n", curr_insn, cs_str, libopcodes_str);
                            fclose(log_fp);
                        }
                }
                ++disas_discreps_found;
            }

            if (capstone_count > 0)
                cs_free(capstone_insn, capstone_count);

            ++instructions_skipped;
            continue;
        }

        // Update the first instruction in the instruction buffer
        /* *((uint32_t*)insn_buffer) = curr_insn; */
        ((uint32_t*)insn_buffer)[insn_offset] = curr_insn;

        last_insn_illegal = 0;

        /*
         * Invalidate insn_buffer (at the insn to be tested)
         * in the d- and icache and force the changes
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
                : [insn_buffer] "r" (insn_buffer + insn_offset*4)
            );

        // Jump to the instruction to be tested (and execute it)
        execute_insn_buffer();

        if (!last_insn_illegal) {
            log_fp = fopen(log_path, "a");

            if (log_fp == NULL) {
                printf("0x%08" PRIx32 " | Hidden instruction!\n", curr_insn);
            } else {
                fprintf(log_fp, "0x%08" PRIx32 " | Hidden instruction!\n", curr_insn);
                fclose(log_fp);
            }

            ++hidden_instructions_found;
        }

        ++instructions_checked;
    }

    // Print the statusline one last time to capture the result of the last insn
    curr_status.instructions_checked = instructions_checked;
    curr_status.instructions_skipped = instructions_skipped;
    curr_status.hidden_instructions_found = hidden_instructions_found;
    curr_status.disas_discrepancies = disas_discreps_found;

    print_statusline(&curr_status);
    write_statusfile(statusfile_path, &curr_status);

    // Compensate for the statusline not having a linebreak
    printf("\n");

    if (no_exec)
        printf("Total undefined: %" PRIu64 "\n", instructions_checked);

    munmap(insn_buffer, PAGE_SIZE);
    munmap(null_pages, PAGE_SIZE*2);
    cs_close(&handle);
    free(log_path);

    return 0;
}
