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
           "discreps: %" PRIu64 ", "
           "ips: %" PRIu64 "   ",
           status->insn,
           status->instructions_checked,
           status->instructions_skipped,
           status->instructions_filtered,
           status->hidden_instructions_found,
           status->disas_discrepancies,
           status->instructions_per_sec
        );

    fflush(stdout);
}

void print_execution_result(execution_result *result)
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
           result->regs_before.pstate, result->regs_before.pstate);
#else
    for (uint32_t i = 0; i < UREG_COUNT; ++i) {
        if (i != A32_ORIG_r0)
            printf("%s:\t%08lx  %08lx\n", REG_STR[i],
                    result->regs_before.uregs[i], result->regs_after.uregs[i]);
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
            "disas_discrepancies:%" PRIu64 "\n"
            "instructions_per_sec:%" PRIu64 "\n",
            status->insn,
            status->cs_disas,
            status->libopcodes_disas,
            status->instructions_checked,
            status->instructions_skipped,
            status->instructions_filtered,
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

int write_logfile(char *filepath, execution_result *exec_result, bool write_regs, bool only_reg_changes)
{
    FILE *log_fp = fopen(filepath, "a");

    if (log_fp == NULL)
        return -1;

    fprintf(log_fp, "%08" PRIx32 ",hidden,%d",
            exec_result->insn, exec_result->signal);

    if (write_regs) {
#ifdef __aarch64__
        unsigned long long *regs0 = exec_result->regs_before.regs;
        unsigned long long *regs1 = exec_result->regs_after.regs;

        for (uint32_t i = 0; i < UREG_COUNT; ++i) {
            if (only_reg_changes) {
                if (regs0[i] != regs1[i])
                    fprintf(log_fp, ",x%" PRIu32 ":%llx-%llx",
                            i, regs0[i], regs1[i]);
            } else {
                fprintf(log_fp, ",%llx-%llx", regs0[i], regs1[i]);
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
#else
        unsigned long *regs0 = exec_result->regs_before.uregs;
        unsigned long *regs1 = exec_result->regs_after.uregs;

        for (uint32_t i = 0; i < UREG_COUNT; ++i) {
            if (i != A32_ORIG_r0) {
                if (only_reg_changes) {
                    if (regs0[i] != regs1[i])
                        fprintf(log_fp, ",%s:%lx-%lx", REG_STR[i], regs0[i], regs1[i]);
                } else {
                    fprintf(log_fp, ",%lx-%lx", regs0[i], regs1[i]);
                }
            }
        }
#endif
    }
    fprintf(log_fp, "\n");
    fclose(log_fp);
    return 0;
}
