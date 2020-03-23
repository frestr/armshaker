#pragma once
#include <inttypes.h>
#include <stdbool.h>
#include "reg_const.h"

typedef struct {
    uint32_t insn;
    char cs_disas[256];
    char libopcodes_disas[256];
    uint64_t instructions_checked;
    uint64_t instructions_skipped;
    uint64_t instructions_filtered;
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

void print_statusline(search_status*);
void print_execution_result(execution_result*);

int write_statusfile(char*, search_status*);
int write_logfile(char*, execution_result*, bool, bool);
