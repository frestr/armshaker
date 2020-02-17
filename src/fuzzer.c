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
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <elf.h>

#include <capstone/capstone.h>

/*
 * Defines needed for bfd "bug":
 * https://github.com/mlpack/mlpack/issues/574
 */
#define PACKAGE
#define PACKAGE_VERSION
#include <dis-asm.h>

#define STATUS_UPDATE_RATE 0x100

#define INSN_RANGE_MIN 0x00000000
#define INSN_RANGE_MAX 0xffffffff

#define PAGE_SIZE 4096

#ifdef __aarch64__
    #define CAPSTONE_ARCH CS_ARCH_ARM64
#else
    #define CAPSTONE_ARCH CS_ARCH_ARM
#endif

#ifdef __aarch64__
#define USER_REGS_TYPE user_regs_struct
#define UREG_COUNT 31
#else
#define USER_REGS_TYPE user_regs

#define ARM_r0      0
#define ARM_r1      1
#define ARM_r2      2
#define ARM_r3      3
#define ARM_r4      4
#define ARM_r5      5
#define ARM_r6      6
#define ARM_r7      7
#define ARM_r8      8
#define ARM_r9      9
#define ARM_r10     10
#define ARM_fp      11
#define ARM_ip      12
#define ARM_sp      13
#define ARM_lr      14
#define ARM_pc      15
#define ARM_cpsr    16
#define ARM_ORIG_r0 17
#define UREG_COUNT  18
#endif

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

typedef struct {
    struct USER_REGS_TYPE regs_before;
    struct USER_REGS_TYPE regs_after;

    uint32_t insn;
    uint32_t signal;
    bool died;
} execution_result;

void *insn_buffer;
volatile sig_atomic_t last_insn_illegal = 0;
volatile sig_atomic_t last_insn_segfault = 0;
volatile sig_atomic_t executing_insn = 0;
uint32_t insn_offset = 0;

void sigill_handler(int, siginfo_t*, void*);
void sigsegv_handler(int, siginfo_t*, void*);
void init_signal_handler(void (*handler)(int, siginfo_t*, void*), int);
void execution_boilerplate(void);
uint64_t get_nano_timestamp(void);
int disas_sprintf(void*, const char*, ...);
int libopcodes_disassemble(uint32_t, char*, size_t);
void print_statusline(search_status*);
int write_statusfile(char*, search_status*);
void slave_loop(void);
pid_t spawn_slave(void);
int custom_ptrace_getregs(pid_t, struct USER_REGS_TYPE*);
int custom_ptrace_setregs(pid_t, struct USER_REGS_TYPE*);
void execute_insn_slave(pid_t*, uint32_t, execution_result*);
void print_execution_result(execution_result*);
void print_help(char*);

extern char boilerplate_start, boilerplate_end, insn_location;

void sigill_handler(int sig_num, siginfo_t *sig_info, void *uc_ptr)
{
    // Suppress unused warning
    (void)sig_info;

    ucontext_t* uc = (ucontext_t*) uc_ptr;

    assert(sig_num == SIGILL);
    last_insn_illegal = 1;

    // Jump to the next instruction (i.e. skip the illegal insn)
    uintptr_t insn_skip = (uintptr_t)(insn_buffer) + (insn_offset+1)*4;

#ifdef __aarch64__
    uc->uc_mcontext.pc = insn_skip;
#else
    uc->uc_mcontext.arm_pc = insn_skip;
#endif
}

void sigsegv_handler(int sig_num, siginfo_t *sig_info, void *uc_ptr)
{
    // Suppress unused warning
    (void)sig_info;

    if (executing_insn == 0) {
        // Something other than a hidden insn execution caused the segfault,
        // so quit
        fprintf(stderr, "Segmentation fault.");
        exit(1);
    }

    ucontext_t* uc = (ucontext_t*) uc_ptr;

    /* assert(sig_num == SIGSEGV); */
    last_insn_segfault = 1;

    uintptr_t insn_skip = (uintptr_t)(insn_buffer) + (insn_offset+1)*4;

#ifdef __aarch64__
    uc->uc_mcontext.pc = insn_skip;
#else
    uc->uc_mcontext.arm_pc = insn_skip;
#endif
}

void init_signal_handler(void (*handler)(int, siginfo_t*, void*), int signum)
{
    struct sigaction s;

    s.sa_sigaction = handler;
    s.sa_flags = SA_SIGINFO;

    sigfillset(&s.sa_mask);

    sigaction(signum,  &s, NULL);
}

/*
 * State management when testing instructions.
 *
 * Used to prevent instructions with side-effects to corrupt the program
 * state, in addition to saving register values for analysis.
 */
void execution_boilerplate(void)
{
#ifdef __aarch64__
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

            /*
             * Reset the regs to make insn execution deterministic
             * and avoid program corruption.
             *
             * If I read Arm ARM correctly, the max offset for register loads are
             * 12 bits, which equals one page (4096 bytes). Because of negative
             * offsets, the mem acces range from 1 to 2*4096, if the regs are
             * initalized to 4096. This makes it easier to distinguish segfaults
             * caused by hidden instructions from other segfaults.
             */
            "mov x0, %[reg_init]        \n"
            "mov x1, %[reg_init]        \n"
            "mov x2, %[reg_init]        \n"
            "mov x3, %[reg_init]        \n"
            "mov x4, %[reg_init]        \n"
            "mov x5, %[reg_init]        \n"
            "mov x6, %[reg_init]        \n"
            "mov x7, %[reg_init]        \n"
            "mov x8, %[reg_init]        \n"
            "mov x9, %[reg_init]        \n"
            "mov x10, %[reg_init]       \n"
            "mov x11, %[reg_init]       \n"
            "mov x12, %[reg_init]       \n"
            "mov x13, %[reg_init]       \n"
            "mov x14, %[reg_init]       \n"
            "mov x15, %[reg_init]       \n"
            "mov x16, %[reg_init]       \n"
            "mov x17, %[reg_init]       \n"
            "mov x18, %[reg_init]       \n"
            "mov x19, %[reg_init]       \n"
            "mov x20, %[reg_init]       \n"
            "mov x21, %[reg_init]       \n"
            "mov x22, %[reg_init]       \n"
            "mov x23, %[reg_init]       \n"
            "mov x24, %[reg_init]       \n"
            "mov x25, %[reg_init]       \n"
            "mov x26, %[reg_init]       \n"
            "mov x27, %[reg_init]       \n"
            "mov x28, %[reg_init]       \n"
            "mov x29, %[reg_init]       \n"
            "mov x30, %[reg_init]       \n"

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
#else
    asm volatile(
            ".global boilerplate_start  \n"
            "boilerplate_start:         \n"

            // Store all gregs
            "push {r0-r12, lr}          \n"

            "vmov s0, sp                \n"

            // Reset the regs to make insn execution deterministic
            // and avoid program corruption
            "mov r0, %[reg_init]        \n"
            "mov r1, %[reg_init]        \n"
            "mov r2, %[reg_init]        \n"
            "mov r3, %[reg_init]        \n"
            "mov r4, %[reg_init]        \n"
            "mov r5, %[reg_init]        \n"
            "mov r6, %[reg_init]        \n"
            "mov r7, %[reg_init]        \n"
            "mov r8, %[reg_init]        \n"
            "mov r9, %[reg_init]        \n"
            "mov r10, %[reg_init]       \n"
            "mov r11, %[reg_init]       \n"
            "mov r12, %[reg_init]       \n"
            "mov lr, %[reg_init]        \n"
            /* "mov sp, %[reg_init]        \n" */
            "msr cpsr_cxsf, #0x10            \n"

            ".global insn_location      \n"
            "insn_location:             \n"

            // This instruction will be replaced with the one to be tested
            "nop                        \n"

            "msr cpsr_cxsf, #0x10            \n"
            "vmov sp, s0                \n"

            // Restore all gregs
            "pop {r0-r12, lr}           \n"

            "bx lr                      \n"
            ".global boilerplate_end    \n"
            "boilerplate_end:           \n"
            :
            : [reg_init] "n" (0)
            );
#endif
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

#ifdef __aarch64__
    disasm_info.arch = bfd_arch_aarch64;
    disasm_info.mach = bfd_mach_aarch64;
#else
    disasm_info.arch = bfd_arch_arm;
    disasm_info.mach = bfd_mach_arm_8;
#endif

    disasm_info.read_memory_func = buffer_read_memory;
    disasm_info.buffer = (uint8_t*)&insn;
    disasm_info.buffer_vma = 0;
    disasm_info.buffer_length = 4;
    disassemble_init_for_target(&disasm_info);

    disassembler_ftype disasm;
    disasm = disassembler(disasm_info.arch, false, disasm_info.mach, NULL);

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

void slave_loop(void)
{
#ifdef __aarch64__
    asm volatile(
            "loop:      \n"
            "   brk #0  \n"
            "   nop     \n"
            "   b loop  \n"
            );
#else
    asm volatile(
            "loop:      \n"
            "   bkpt    \n"
            "   nop     \n"
            "   b loop  \n"
            );
#endif

}

pid_t spawn_slave(void)
{
    pid_t slave_pid = fork();
    if (slave_pid == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        slave_loop();
    }
    int status;
    waitpid(slave_pid, &status, 0);
    return slave_pid;
}

int custom_ptrace_getregs(pid_t pid, struct USER_REGS_TYPE *regs)
{
#ifdef __aarch64__
    struct iovec iovec = { regs, sizeof(*regs) };
    return ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iovec);
#else
    return ptrace(PTRACE_GETREGS, pid, NULL, regs);
#endif
}

int custom_ptrace_setregs(pid_t pid, struct USER_REGS_TYPE *regs)
{
#ifdef __aarch64__
    struct iovec iovec = { regs, sizeof(*regs) };
    return ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iovec);
#else
    return ptrace(PTRACE_SETREGS, pid, NULL, regs);
#endif
}

void execute_insn_slave(pid_t *slave_pid_ptr, uint32_t insn, execution_result *result)
{
    int status;

    pid_t slave_pid = *slave_pid_ptr;

    // Set regs etc.
    struct USER_REGS_TYPE regs;

    if (custom_ptrace_getregs(slave_pid, &regs) == -1) {
        perror("getregs failed");
    }

#ifdef __aarch64__
    static unsigned long long insn_loc = 0;
    static unsigned long long sp_loc = 0;
    unsigned long long *sp_reg = &regs.sp;
    unsigned long long *pc_reg = &regs.pc;
    unsigned long long *regs_ptr = regs.regs;
#else
    static unsigned long insn_loc = 0;
    static unsigned long sp_loc = 0;
    unsigned long *sp_reg = &regs.uregs[ARM_sp];
    unsigned long *pc_reg = &regs.uregs[ARM_pc];
    unsigned long *regs_ptr = regs.uregs;
#endif

    if (insn_loc == 0)
        insn_loc = *pc_reg + 4;

    if (sp_loc == 0)
        sp_loc = *sp_reg;

    if (ptrace(PTRACE_POKETEXT, slave_pid, insn_loc, insn) == -1) {
        perror("poketext failed");
    }
    result->insn = insn;

    // Reset all regs
    memset(regs_ptr, 0, UREG_COUNT * sizeof(regs_ptr[0]));
    *sp_reg = sp_loc;
    *pc_reg = insn_loc;
#ifdef __aarch64__
    // Set pstate
#else
    regs.uregs[ARM_cpsr] = 0x10;  // user mode
#endif
    if (custom_ptrace_setregs(slave_pid, &regs) == -1) {
        perror("setregs failed");
    }

    memcpy(&result->regs_before, &regs, sizeof(regs));

    // Execute the instruction
    ptrace(PTRACE_CONT, slave_pid, NULL, NULL);
    waitpid(slave_pid, &status, 0);

    // Store results
    if (custom_ptrace_getregs(slave_pid, &regs) == -1) {
        perror("getregs2 failed");
    }
    memcpy(&result->regs_after, &regs, sizeof(regs));

    siginfo_t siginfo;
    if (ptrace(PTRACE_GETSIGINFO, slave_pid, NULL, &siginfo) == -1) {
        perror("getsiginfo failed");
    }

    int signo = siginfo.si_signo;
    result->signal = (signo == SIGTRAP) ? 0 : signo;

    // TODO: Need to check if the slave died, and restart it if so
    result->died = false;

    // Fix the pc if the exception prevented the pc from advancing
    if (*pc_reg == insn_loc) {
        // Check whether a trap signal was caused by the executed instruction
        // (as opposed to the bkpt)
        if (signo == SIGTRAP) {
            result->signal = signo;
        }
        *pc_reg = insn_loc - 4;
        if (custom_ptrace_setregs(slave_pid, &regs) == -1) {
            perror("setregs1 failed");
        }
        ptrace(PTRACE_CONT, slave_pid, NULL, NULL);
        waitpid(slave_pid, &status, 0);
    } else {
        /* ptrace(PTRACE_DETACH, slave_pid, NULL, NULL); */
        /* if (kill(slave_pid, SIGKILL) == -1) { */
        /*     fprintf(stderr, "worker %d failed to kill slave %d", worker_pid, slave_pid); */
        /*     perror("errno:"); */
        /* } */
        /* /1* printf("worker %d killed slave %d\n", worker_pid, slave_pid); *1/ */
        /* slave_pid = fork(); */
        /* if (slave_pid == 0) { */
        /*     ptrace(PTRACE_TRACEME, 0, NULL, NULL); */
        /*     execv("slave", NULL); */
        /* } else { */
        /*     waitpid(slave_pid, &status, 0); */
        /*     /1* printf("worker %d started new slave %d\n", worker_pid, slave_pid); *1/ */
        /* } */
    }
}

void print_execution_result(execution_result *result)
{
#ifdef __aarch64__
        printf("\n"
               "r0: %016llx\t%016llx\n"
               "r1: %016llx\t%016llx\n"
               "r2: %016llx\t%016llx\n"
               "sp: %016llx\t%016llx\n"
               "pc: %016llx\t%016llx\n"
               "pstate: %016llx\t%016llx\n",
               result->uregs_before[0], result->uregs_after[0],
               result->uregs_before[1], result->uregs_after[1],
               result->uregs_before[2], result->uregs_after[2],
               result->sp_before, result->sp_after,
               result->pc_before, result->pc_after,
               result->pstate_before, result->pstate_after);
        printf("signal: %d\n", result->signal);
#else
        printf("\n"
               "r0: %08lx\t%08lx\n"
               "r1: %08lx\t%08lx\n"
               "r2: %08lx\t%08lx\n"
               "r3: %08lx\t%08lx\n"
               "r4: %08lx\t%08lx\n"
               "r5: %08lx\t%08lx\n"
               "r6: %08lx\t%08lx\n"
               "r7: %08lx\t%08lx\n"
               "r8: %08lx\t%08lx\n"
               "r9: %08lx\t%08lx\n"
               "r10:%08lx\t%08lx\n"
               "fp: %08lx\t%08lx\n"
               "ip: %08lx\t%08lx\n"
               "sp: %08lx\t%08lx\n"
               "lr: %08lx\t%08lx\n"
               "pc: %08lx\t%08lx\n"
               "cpsr: %08lx\t%08lx\n"
               "orig_r0: %08lx\t%08lx\n",
               result->regs_before.uregs[0], result->regs_after.uregs[0],
               result->regs_before.uregs[1], result->regs_after.uregs[1],
               result->regs_before.uregs[2], result->regs_after.uregs[2],
               result->regs_before.uregs[3], result->regs_after.uregs[3],
               result->regs_before.uregs[4], result->regs_after.uregs[4],
               result->regs_before.uregs[5], result->regs_after.uregs[5],
               result->regs_before.uregs[6], result->regs_after.uregs[6],
               result->regs_before.uregs[7], result->regs_after.uregs[7],
               result->regs_before.uregs[8], result->regs_after.uregs[8],
               result->regs_before.uregs[9], result->regs_after.uregs[9],
               result->regs_before.uregs[10], result->regs_after.uregs[10],
               result->regs_before.uregs[11], result->regs_after.uregs[11],
               result->regs_before.uregs[12], result->regs_after.uregs[12],
               result->regs_before.uregs[13], result->regs_after.uregs[13],
               result->regs_before.uregs[14], result->regs_after.uregs[14],
               result->regs_before.uregs[15], result->regs_after.uregs[15],
               result->regs_before.uregs[16], result->regs_after.uregs[16],
               result->regs_before.uregs[17], result->regs_after.uregs[17]);
        printf("signal: %d\n", result->signal);
#endif
}

struct option long_options[] = {
    {"help",            no_argument,        NULL, 'h'},
    {"start",           required_argument,  NULL, 's'},
    {"end",             required_argument,  NULL, 'e'},
    {"no-exec",         no_argument,        NULL, 'n'},
    {"log-suffix",      required_argument,  NULL, 'l'},
    {"quiet",           required_argument,  NULL, 'q'},
    {"discreps",        no_argument,        NULL, 'c'},
    {"ptrace",          no_argument,        NULL, 'p'}
};

void print_help(char *cmd_name)
{
    printf("Usage: %s [option(s)]\n", cmd_name);
    printf("\n\
Options:\n\
        -h, --help              Print help information\n\
        -s, --start <insn>      Start of instruction search range (in hex)\n\
                                [default: 0x00000000]\n\
        -e, --end <insn>        End of instruction search range, inclusive (in hex)\n\
                                [default: 0xffffffff]\n\
        -n, --no-exec           Calculate the total amount of undefined instructions,\n\
                                without executing them\n\
        -l, --log-suffix        Add a suffix to the log and status file.\n\
        -q, --quiet             Don't print the status line.\n\
        -c, --discreps          Log disassembler discrepancies.\n\
        -p, --ptrace            Execute instructions on a separate process using ptrace.\n"
    );
}

int main(int argc, char **argv)
{
    uint32_t insn_range_start = INSN_RANGE_MIN;
    uint32_t insn_range_end = INSN_RANGE_MAX; // 2^32 - 1
    bool no_exec = false;
    bool quiet = false;
    bool log_discreps = false;
    bool use_ptrace = false;

    char *file_suffix = NULL;
    char *endptr;
    int c;
    while ((c = getopt_long(argc, argv, "hs:e:nl:qcp", long_options, NULL)) != -1) {
        switch (c) {
            case 'h':
                print_help(argv[0]);
                return 1;
            case 's':
                insn_range_start = strtoll(optarg, &endptr, 16);
                if (*endptr != '\0') {
                    fprintf(stderr, "ERROR: Unable to read instruction range start\n");
                    return 1;
                }
                break;
            case 'e':
                insn_range_end = strtoll(optarg, &endptr, 16);
                if (*endptr != '\0') {
                    fprintf(stderr, "ERROR: Unable to read instruction range end\n");
                    return 1;
                }
                break;
            case 'n':
                no_exec = true;
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
            case 'p':
                use_ptrace = true;
                break;
            default:
                print_help(argv[0]);
                return 1;
        }
    }

    pid_t slave_pid = 0;
    if (use_ptrace)
        slave_pid = spawn_slave();

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

	if (cs_open(CAPSTONE_ARCH,
                CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN,
                &handle) != CS_ERR_OK) {
        fprintf(stderr, "ERROR: Unable to load capstone\n");
		return 1;
    }

    init_signal_handler(sigill_handler, SIGILL);
    init_signal_handler(sigsegv_handler, SIGSEGV);
    init_signal_handler(sigsegv_handler, SIGTRAP);

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
        char libopcodes_str[256] = {0};
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
                                  || strstr(libopcodes_str, "NYI") != NULL
                                  || strstr(libopcodes_str, "UNDEFINED") != NULL);

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

        if (use_ptrace) {
            execution_result result = {0};
            execute_insn_slave(&slave_pid, curr_insn, &result);

            last_insn_illegal = (result.signal == SIGILL);
            last_insn_segfault = (result.signal == SIGSEGV);
            print_execution_result(&result);
        } else {
            // Update the first instruction in the instruction buffer
            /* *((uint32_t*)insn_buffer) = curr_insn; */
            ((uint32_t*)insn_buffer)[insn_offset] = curr_insn;

            last_insn_illegal = 0;
            last_insn_segfault = 0;

            /*
             * Clear insn_buffer (at the insn to be tested)
             * in the d- and icache
             * (some instructions might be skipped otherwise.)
             */
            __clear_cache(insn_buffer + insn_offset * 4,
                          insn_buffer + insn_offset * 4 + sizeof(curr_insn));

            executing_insn = 1;

            // Jump to the instruction to be tested (and execute it)
            execute_insn_buffer();

            executing_insn = 0;
        }

        if (!last_insn_illegal) {
            log_fp = fopen(log_path, "a");

            if (log_fp == NULL) {
                printf("0x%08" PRIx32 " | Hidden instruction! Segfault: %s\n",
                       curr_insn, last_insn_segfault ? "yes" : "no");
            } else {
                fprintf(log_fp, "0x%08" PRIx32 " | Hidden instruction! Segfault: %s\n",
                        curr_insn, last_insn_segfault ? "yes" : "no");
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
    cs_close(&handle);
    free(log_path);

    return 0;
}
