#pragma once
#include <sys/user.h>

#ifdef __aarch64__

#define USER_REGS_TYPE user_regs_struct
#define UREG_COUNT 31

#else

#define USER_REGS_TYPE user_regs

#define A32_r0      0
#define A32_r1      1
#define A32_r2      2
#define A32_r3      3
#define A32_r4      4
#define A32_r5      5
#define A32_r6      6
#define A32_r7      7
#define A32_r8      8
#define A32_r9      9
#define A32_r10     10
#define A32_fp      11
#define A32_ip      12
#define A32_sp      13
#define A32_lr      14
#define A32_pc      15
#define A32_cpsr    16
#define A32_ORIG_r0 17
#define UREG_COUNT  18

const char *REG_REPR[] = {
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
