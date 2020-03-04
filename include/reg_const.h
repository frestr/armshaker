#pragma once
#include <sys/user.h>

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
