#include "logging.h"
#include <stdio.h>
#include <sys/file.h>

void print_statusline(search_status *status)
{
    printf("\rinsn: 0x%08" PRIx32 ", "
           "checked: %" PRIu64 ", "
           "skipped: %" PRIu64 ", "
           "filtered: %" PRIu64 ", "
           "hidden: %" PRIu64 ", "
           "discreps: %" PRIu64 ", "
           "ips: %" PRIu64 "   ",
           status->curr_insn,
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
#ifdef __aarch64__
        printf("\n"
               "x0:     %016llx\t%016llx\n"
               "x1:     %016llx\t%016llx\n"
               "x2:     %016llx\t%016llx\n"
               "x3:     %016llx\t%016llx\n"
               "x4:     %016llx\t%016llx\n"
               "x5:     %016llx\t%016llx\n"
               "x6:     %016llx\t%016llx\n"
               "x7:     %016llx\t%016llx\n"
               "x8:     %016llx\t%016llx\n"
               "x9:     %016llx\t%016llx\n"
               "x10:    %016llx\t%016llx\n"
               "x11:    %016llx\t%016llx\n"
               "x12:    %016llx\t%016llx\n"
               "x13:    %016llx\t%016llx\n"
               "x14:    %016llx\t%016llx\n"
               "x15:    %016llx\t%016llx\n",
               result->regs_before.regs[0], result->regs_after.regs[0],
               result->regs_before.regs[1], result->regs_after.regs[1],
               result->regs_before.regs[2], result->regs_after.regs[2],
               result->regs_before.regs[3], result->regs_after.regs[3],
               result->regs_before.regs[4], result->regs_after.regs[4],
               result->regs_before.regs[5], result->regs_after.regs[5],
               result->regs_before.regs[6], result->regs_after.regs[6],
               result->regs_before.regs[7], result->regs_after.regs[7],
               result->regs_before.regs[8], result->regs_after.regs[8],
               result->regs_before.regs[9], result->regs_after.regs[9],
               result->regs_before.regs[10], result->regs_after.regs[10],
               result->regs_before.regs[11], result->regs_after.regs[11],
               result->regs_before.regs[12], result->regs_after.regs[12],
               result->regs_before.regs[13], result->regs_after.regs[13],
               result->regs_before.regs[14], result->regs_after.regs[14],
               result->regs_before.regs[15], result->regs_after.regs[15]);
        printf(""
               "x16:    %016llx\t%016llx\n"
               "x17:    %016llx\t%016llx\n"
               "x18:    %016llx\t%016llx\n"
               "x19:    %016llx\t%016llx\n"
               "x20:    %016llx\t%016llx\n"
               "x21:    %016llx\t%016llx\n"
               "x22:    %016llx\t%016llx\n"
               "x23:    %016llx\t%016llx\n"
               "x24:    %016llx\t%016llx\n"
               "x25:    %016llx\t%016llx\n"
               "x26:    %016llx\t%016llx\n"
               "x27:    %016llx\t%016llx\n"
               "x28:    %016llx\t%016llx\n"
               "x29:    %016llx\t%016llx\n"
               "x30:    %016llx\t%016llx\n",
               result->regs_before.regs[16], result->regs_after.regs[16],
               result->regs_before.regs[17], result->regs_after.regs[17],
               result->regs_before.regs[18], result->regs_after.regs[18],
               result->regs_before.regs[19], result->regs_after.regs[19],
               result->regs_before.regs[20], result->regs_after.regs[20],
               result->regs_before.regs[21], result->regs_after.regs[21],
               result->regs_before.regs[22], result->regs_after.regs[22],
               result->regs_before.regs[23], result->regs_after.regs[23],
               result->regs_before.regs[24], result->regs_after.regs[24],
               result->regs_before.regs[25], result->regs_after.regs[25],
               result->regs_before.regs[26], result->regs_after.regs[26],
               result->regs_before.regs[27], result->regs_after.regs[27],
               result->regs_before.regs[28], result->regs_after.regs[28],
               result->regs_before.regs[29], result->regs_after.regs[29],
               result->regs_before.regs[30], result->regs_after.regs[30]);
        printf(""
               "sp:     %016llx\t%016llx\n"
               "pc:     %016llx\t%016llx\n"
               "pstate: %016llx\t%016llx\n",
               result->regs_before.sp, result->regs_after.sp,
               result->regs_before.pc, result->regs_after.pc,
               result->regs_before.pstate, result->regs_before.pstate);
        printf("signal: %d\n", result->signal);
#else
        printf("\n"
               "r0:   %08lx  %08lx\n"
               "r1:   %08lx  %08lx\n"
               "r2:   %08lx  %08lx\n"
               "r3:   %08lx  %08lx\n"
               "r4:   %08lx  %08lx\n"
               "r5:   %08lx  %08lx\n"
               "r6:   %08lx  %08lx\n"
               "r7:   %08lx  %08lx\n"
               "r8:   %08lx  %08lx\n"
               "r9:   %08lx  %08lx\n"
               "r10:  %08lx  %08lx\n"
               "fp:   %08lx  %08lx\n"
               "ip:   %08lx  %08lx\n"
               "sp:   %08lx  %08lx\n"
               "lr:   %08lx  %08lx\n"
               "pc:   %08lx  %08lx\n"
               "cpsr: %08lx  %08lx\n",
               result->regs_before.uregs[A32_r0], result->regs_after.uregs[A32_r0],
               result->regs_before.uregs[A32_r1], result->regs_after.uregs[A32_r1],
               result->regs_before.uregs[A32_r2], result->regs_after.uregs[A32_r2],
               result->regs_before.uregs[A32_r3], result->regs_after.uregs[A32_r3],
               result->regs_before.uregs[A32_r4], result->regs_after.uregs[A32_r4],
               result->regs_before.uregs[A32_r5], result->regs_after.uregs[A32_r5],
               result->regs_before.uregs[A32_r6], result->regs_after.uregs[A32_r6],
               result->regs_before.uregs[A32_r7], result->regs_after.uregs[A32_r7],
               result->regs_before.uregs[A32_r8], result->regs_after.uregs[A32_r8],
               result->regs_before.uregs[A32_r9], result->regs_after.uregs[A32_r9],
               result->regs_before.uregs[A32_r10], result->regs_after.uregs[A32_r10],
               result->regs_before.uregs[A32_fp], result->regs_after.uregs[A32_fp],
               result->regs_before.uregs[A32_ip], result->regs_after.uregs[A32_ip],
               result->regs_before.uregs[A32_sp], result->regs_after.uregs[A32_sp],
               result->regs_before.uregs[A32_lr], result->regs_after.uregs[A32_lr],
               result->regs_before.uregs[A32_pc], result->regs_after.uregs[A32_pc],
               result->regs_before.uregs[A32_cpsr], result->regs_after.uregs[A32_cpsr]);
        printf("signal: %d\n", result->signal);
#endif
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
            "instructions_filtered:%" PRIu64 "\n"
            "hidden_instructions_found:%" PRIu64 "\n"
            "disas_discrepancies:%" PRIu64 "\n"
            "instructions_per_sec:%" PRIu64 "\n",
            status->curr_insn,
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

int write_logfile(char *filepath, execution_result *exec_result, bool write_regs)
{
    FILE *log_fp = fopen(filepath, "a");

    if (log_fp == NULL)
        return -1;

    if (write_regs) {
#ifdef __aarch64__
        unsigned long long *regs0 = exec_result->regs_before.regs;
        unsigned long long *regs1 = exec_result->regs_after.regs;

        fprintf(log_fp, "%08" PRIx32 ",hidden,%d,"
                        "%llx-%llx,%llx-%llx,%llx-%llx,%llx-%llx,"
                        "%llx-%llx,%llx-%llx,%llx-%llx,%llx-%llx,"
                        "%llx-%llx,%llx-%llx,%llx-%llx,%llx-%llx,"
                        "%llx-%llx,%llx-%llx,%llx-%llx,%llx-%llx,",
                        exec_result->insn, exec_result->signal,
                        regs0[0], regs1[0],
                        regs0[1], regs1[1],
                        regs0[2], regs1[2],
                        regs0[3], regs1[3],
                        regs0[4], regs1[4],
                        regs0[5], regs1[5],
                        regs0[6], regs1[6],
                        regs0[7], regs1[7],
                        regs0[8], regs1[8],
                        regs0[9], regs1[9],
                        regs0[10], regs1[10],
                        regs0[11], regs1[11],
                        regs0[12], regs1[12],
                        regs0[13], regs1[13],
                        regs0[14], regs1[14],
                        regs0[15], regs1[15]);
        fprintf(log_fp, "%llx-%llx,%llx-%llx,%llx-%llx,%llx-%llx,"
                        "%llx-%llx,%llx-%llx,%llx-%llx,%llx-%llx,"
                        "%llx-%llx,%llx-%llx,%llx-%llx,%llx-%llx,"
                        "%llx-%llx,%llx-%llx,%llx-%llx,",
                        regs0[16], regs1[16],
                        regs0[17], regs1[17],
                        regs0[18], regs1[18],
                        regs0[19], regs1[19],
                        regs0[20], regs1[20],
                        regs0[21], regs1[21],
                        regs0[22], regs1[22],
                        regs0[23], regs1[23],
                        regs0[24], regs1[24],
                        regs0[25], regs1[25],
                        regs0[26], regs1[26],
                        regs0[27], regs1[27],
                        regs0[28], regs1[28],
                        regs0[29], regs1[29],
                        regs0[30], regs1[30]);
        fprintf(log_fp, "%llx-%llx,%llx-%llx,%llx-%llx\n",
                        exec_result->regs_before.sp, exec_result->regs_after.sp,
                        exec_result->regs_before.pc, exec_result->regs_after.pc,
                        exec_result->regs_before.pstate, exec_result->regs_after.pstate);
#else
        unsigned long *regs0 = exec_result->regs_before.uregs;
        unsigned long *regs1 = exec_result->regs_after.uregs;

        fprintf(log_fp, "%08" PRIx32 ",hidden,%d,"
                        "%lx-%lx,%lx-%lx,%lx-%lx,%lx-%lx,"
                        "%lx-%lx,%lx-%lx,%lx-%lx,%lx-%lx,"
                        "%lx-%lx,%lx-%lx,%lx-%lx,%lx-%lx,"
                        "%lx-%lx,%lx-%lx,%lx-%lx,%lx-%lx,"
                        "%lx-%lx\n",
                        exec_result->insn, exec_result->signal,
                        regs0[A32_r0], regs1[A32_r0],
                        regs0[A32_r1], regs1[A32_r1],
                        regs0[A32_r2], regs1[A32_r2],
                        regs0[A32_r3], regs1[A32_r3],
                        regs0[A32_r4], regs1[A32_r4],
                        regs0[A32_r5], regs1[A32_r5],
                        regs0[A32_r6], regs1[A32_r6],
                        regs0[A32_r7], regs1[A32_r7],
                        regs0[A32_r8], regs1[A32_r8],
                        regs0[A32_r9], regs1[A32_r9],
                        regs0[A32_r10], regs1[A32_r10],
                        regs0[A32_fp], regs1[A32_fp],
                        regs0[A32_ip], regs1[A32_ip],
                        regs0[A32_sp], regs1[A32_sp],
                        regs0[A32_lr], regs1[A32_lr],
                        regs0[A32_pc], regs1[A32_pc],
                        regs0[A32_cpsr], regs1[A32_cpsr]);
#endif
    } else {
        fprintf(log_fp, "%08" PRIx32 ",hidden,%d\n",
                        exec_result->insn, exec_result->signal);
    }
    fclose(log_fp);
    return 0;
}
