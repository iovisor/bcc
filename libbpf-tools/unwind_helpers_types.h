// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright 2023 LG Electronics Inc.
#ifndef __UNWIND_HELPERS_TYPES_H
#define __UNWIND_HELPERS_TYPES_H

#define STRINGIFY(x)		#x
#define NAME(x)			STRINGIFY(x)

#define UW_STACK_MAX_SZ		4096
#define UW_SAMPLES_MAP		uw_samples
#define UW_STACKS_MAP		uw_stacks

/*
 * Defines the same structure as "struct pt_regs".
 * Since struct pt_regs is kernel-only, this data type is defined for use in both kernel and user space.
 */
#if defined(__TARGET_ARCH_arm64)
struct uw_user_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};
#elif defined(__TARGET_ARCH_x86)
struct uw_user_regs {
	__u64 r15;
	__u64 r14;
	__u64 r13;
	__u64 r12;
	__u64 rbp;
	__u64 rbx;
	__u64 r11;
	__u64 r10;
	__u64 r9;
	__u64 r8;
	__u64 rax;
	__u64 rcx;
	__u64 rdx;
	__u64 rsi;
	__u64 rdi;
	__u64 orig_rax;
	__u64 rip;
	__u64 cs;
	__u64 eflags;
	__u64 rsp;
	__u64 ss;
};
#else
#error This Architecture is not supported yet. Please open an issue
#endif

typedef struct uw_user_regs regs_dump_t;

typedef struct stack_dump {
	__u32 size;
	char *data;
} stack_dump_t;

struct sample_data {
	regs_dump_t user_regs;
	stack_dump_t user_stack;
};
#endif /* __UNWIND_HELPERS_TYPES_H */
