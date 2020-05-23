#include "logging.h"
#include <stdio.h>
#include <sys/file.h>

#ifndef __aarch64__
static const char *REG_STR[] = {
    [0] = "r0",
    [1] = "r1",
    [2] = "r2",
    [3] = "r3",
    [4] = "r4",
    [5] = "r5",
    [6] = "r6",
    [7] = "r7",
    [8] = "r8",
    [9] = "r9",
    [10] = "r10",
    [11] = "fp",
    [12] = "ip",
    [13] = "sp",
    [14] = "lr",
    [15] = "pc",
    [16] = "cpsr",
    [17] = "orig_r0"
};
#endif

void print_statusline(search_status *status)
{
    printf("\rinsn: 0x%08" PRIx32 ", "
           "checked: %" PRIu64 ", "
           "skipped: %" PRIu64 ", "
           "filtered: %" PRIu64 ", "
           "hidden: %" PRIu64 ", "
           "ips: %" PRIu64 "   ",
           status->insn,
           status->instructions_checked,
           status->instructions_skipped,
           status->instructions_filtered,
           status->hidden_instructions_found,
           status->instructions_per_sec
        );

    fflush(stdout);
}

void print_execution_result(execution_result *result, bool include_vector_regs)
{
    printf("\ninsn: %08" PRIx32 "\n", result->insn);
#ifdef __aarch64__
    for (uint32_t i = 0; i < UREG_COUNT; ++i)
        printf("x%" PRIu32 ":\t%016llx\t%016llx\n",
                i, result->regs_before.regs[i], result->regs_after.regs[i]);

    printf("sp:     %016llx\t%016llx\n"
           "pc:     %016llx\t%016llx\n"
           "pstate: %016llx\t%016llx\n",
           result->regs_before.sp, result->regs_after.sp,
           result->regs_before.pc, result->regs_after.pc,
           result->regs_before.pstate, result->regs_after.pstate);

    if (include_vector_regs) {
        for (uint32_t i = 0; i < VFPREG_COUNT; ++i) {
            uint64_t upper_bef = result->vfp_regs_before.vregs[i] >> 64;
            uint64_t lower_bef = (uint64_t)result->vfp_regs_before.vregs[i];
            uint64_t upper_aft = result->vfp_regs_after.vregs[i] >> 64;
            uint64_t lower_aft = (uint64_t)result->vfp_regs_after.vregs[i];
            printf("v%" PRIu32 ":\t%016" PRIx64 "%016" PRIx64 "\t"
                    "%016" PRIx64 "%016" PRIx64"\n",
                    i, upper_bef, lower_bef, upper_aft, lower_aft);
        }
        printf("fpsr:\t%016x\n"
               "fpcr:\t%016x\n",
               result->vfp_regs_before.fpsr,
               result->vfp_regs_after.fpcr);
    }
#else
    for (uint32_t i = 0; i < UREG_COUNT; ++i) {
        if (i != A32_ORIG_r0)
            printf("%s:\t%08lx  %08lx\n", REG_STR[i],
                    result->regs_before.uregs[i], result->regs_after.uregs[i]);
    }

    if (include_vector_regs) {
        for (uint32_t i = 0; i < VFPREG_COUNT; ++i)
            printf("d%" PRIu32 ":\t%016llx\t%016llx\n",
                    i, result->vfp_regs_before.fpregs[i],
                    result->vfp_regs_after.fpregs[i]);
        printf("fpscr:\t\t%08lx\t\t%08lx\n",
               result->vfp_regs_before.fpscr,
               result->vfp_regs_after.fpscr);
    }
#endif
    printf("signal: %d\n", result->signal);
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
            "insn:%08" PRIx32 "\n"
            "cs_disas:%s\n"
            "libopcodes_disas:%s\n"
            "instructions_checked:%" PRIu64 "\n"
            "instructions_skipped:%" PRIu64 "\n"
            "instructions_filtered:%" PRIu64 "\n"
            "hidden_instructions_found:%" PRIu64 "\n"
            "instructions_per_sec:%" PRIu64 "\n",
            status->insn,
            status->cs_disas,
            status->libopcodes_disas,
            status->instructions_checked,
            status->instructions_skipped,
            status->instructions_filtered,
            status->hidden_instructions_found,
            status->instructions_per_sec
        );

    if (flock(fileno(fp), LOCK_UN) == -1) {
        perror("Unlocking statusfile failed");
        return -1;
    }

    fclose(fp);
    return 0;
}

int write_logfile(char *filepath, execution_result *exec_result, bool write_regs, bool only_reg_changes, bool include_vector_regs)
{
    FILE *log_fp = fopen(filepath, "a");

    if (log_fp == NULL)
        return -1;

    fprintf(log_fp, "%08" PRIx32 ",hidden,%d",
            exec_result->insn, exec_result->signal);

    if (write_regs) {
#ifdef __aarch64__
        for (uint32_t i = 0; i < UREG_COUNT; ++i) {
            if (only_reg_changes) {
                if (exec_result->regs_before.regs[i] != exec_result->regs_after.regs[i])
                    fprintf(log_fp, ",x%" PRIu32 ":%llx-%llx",
                            i, exec_result->regs_before.regs[i],
                            exec_result->regs_after.regs[i]);
            } else {
                fprintf(log_fp, ",%llx-%llx", exec_result->regs_before.regs[i],
                        exec_result->regs_after.regs[i]);
            }
        }

        if (only_reg_changes) {
            if (exec_result->regs_before.sp != exec_result->regs_after.sp) {
                fprintf(log_fp, ",sp:%llx-%llx",
                        exec_result->regs_before.sp, exec_result->regs_after.sp);
            }
            if (exec_result->regs_before.pc != exec_result->regs_after.pc) {
                fprintf(log_fp, ",pc:%llx-%llx",
                        exec_result->regs_before.pc, exec_result->regs_after.pc);
            }
            if (exec_result->regs_before.pstate != exec_result->regs_after.pstate) {
                fprintf(log_fp, ",pstate:%llx-%llx",
                        exec_result->regs_before.pstate, exec_result->regs_after.pstate);
            }
        } else {
            fprintf(log_fp, ",%llx-%llx,%llx-%llx,%llx-%llx",
                            exec_result->regs_before.sp, exec_result->regs_after.sp,
                            exec_result->regs_before.pc, exec_result->regs_after.pc,
                            exec_result->regs_before.pstate, exec_result->regs_after.pstate);
        }

        if (include_vector_regs) {
            for (uint32_t i = 0; i < VFPREG_COUNT; ++i) {
                uint64_t upper_bef = exec_result->vfp_regs_before.vregs[i] >> 64;
                uint64_t lower_bef = (uint64_t)exec_result->vfp_regs_before.vregs[i];
                uint64_t upper_aft = exec_result->vfp_regs_after.vregs[i] >> 64;
                uint64_t lower_aft = (uint64_t)exec_result->vfp_regs_after.vregs[i];

                if (only_reg_changes) {
                    if (exec_result->vfp_regs_before.vregs[i]
                            != exec_result->vfp_regs_after.vregs[i]) {
                        fprintf(log_fp, ",v%" PRIu32 ":%016" PRIx64 "%016" PRIx64 "-"
                                "%016" PRIx64 "%016" PRIx64 "",
                                i, upper_bef, lower_bef, upper_aft, lower_aft);
                    }
                } else {
                    fprintf(log_fp, ",%016" PRIx64 "%016" PRIx64 "-"
                            "%016" PRIx64 "%016" PRIx64 "",
                            upper_bef, lower_bef, upper_aft, lower_aft);
                }
            }
            if (only_reg_changes) {
                if (exec_result->vfp_regs_before.fpsr
                        != exec_result->vfp_regs_after.fpsr) {
                    printf(",fpsr:%x-%x",
                           exec_result->vfp_regs_before.fpsr,
                           exec_result->vfp_regs_after.fpsr);
                }
                if (exec_result->vfp_regs_before.fpcr
                        != exec_result->vfp_regs_after.fpcr) {
                    printf(",fpcr:%x-%x",
                           exec_result->vfp_regs_before.fpcr,
                           exec_result->vfp_regs_after.fpcr);
                }
            } else {
                printf(",%x-%x,%x-%x",
                       exec_result->vfp_regs_before.fpsr,
                       exec_result->vfp_regs_after.fpsr,
                       exec_result->vfp_regs_before.fpcr,
                       exec_result->vfp_regs_after.fpcr);
            }
        }
#else
        for (uint32_t i = 0; i < UREG_COUNT; ++i) {
            if (i != A32_ORIG_r0) {
                if (only_reg_changes) {
                    if (exec_result->regs_before.uregs[i]
                            != exec_result->regs_after.uregs[i])
                        fprintf(log_fp, ",%s:%lx-%lx", REG_STR[i],
                                exec_result->regs_before.uregs[i],
                                exec_result->regs_after.uregs[i]);
                } else {
                    fprintf(log_fp, ",%lx-%lx", exec_result->regs_before.uregs[i],
                            exec_result->regs_after.uregs[i]);
                }
            }
        }

        if (include_vector_regs) {
            for (uint32_t i = 0; i < VFPREG_COUNT; ++i) {
                if (only_reg_changes) {
                    if (exec_result->vfp_regs_before.fpregs[i]
                            != exec_result->vfp_regs_after.fpregs[i]) {
                        fprintf(log_fp,",d%" PRIu32 ":%llx-%llx", i,
                                exec_result->vfp_regs_before.fpregs[i],
                                exec_result->vfp_regs_after.fpregs[i]);
                    }
                } else {
                    fprintf(log_fp,",%llx-%llx",
                            exec_result->vfp_regs_before.fpregs[i],
                            exec_result->vfp_regs_after.fpregs[i]);
                }
            }
            if (only_reg_changes) {
                if (exec_result->vfp_regs_before.fpscr
                        != exec_result->vfp_regs_after.fpscr) {
                    fprintf(log_fp, ",fpscr:%lx-%lx",
                            exec_result->vfp_regs_before.fpscr,
                            exec_result->vfp_regs_after.fpscr);
                }
            } else {
                fprintf(log_fp, ",%lx-%lx",
                        exec_result->vfp_regs_before.fpscr,
                        exec_result->vfp_regs_after.fpscr);
            }
        }
#endif
    }
    fprintf(log_fp, "\n");
    fclose(log_fp);
    return 0;
}
