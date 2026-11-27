/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024 Samsung */
#ifndef __BLKALGN_H
#define __BLKALGN_H

#define MAX_FILENAME_LEN 127
#define NAME_LEN 32
#define TASK_COMM_LEN 16

#define MAX_SLOTS 16384 + 1

#define MINORBITS 20
#define MINORMASK ((1U << MINORBITS) - 1)
#define MKDEV(ma, mi) (((ma) << MINORBITS) | (mi))

struct hkey {
	char disk[NAME_LEN];
};

struct hval {
	__u32 slots[MAX_SLOTS];
	__u32 granularity;
};

#ifndef MAX_STACK_DEPTH
#define MAX_STACK_DEPTH 128
#endif

typedef __u64 stack_trace_t[MAX_STACK_DEPTH];

struct event {
	char comm[TASK_COMM_LEN];
	char disk[NAME_LEN];
	int pid;
	unsigned flags;
	unsigned lbs;
	unsigned len;
	unsigned long long sector;
	__s32 kstack_sz;
	__s32 ustack_sz;
	stack_trace_t kstack;
	stack_trace_t ustack;
};

#define min(x, y)                              \
	({                                     \
		typeof(x) _min1 = (x);         \
		typeof(y) _min2 = (y);         \
		(void)(&_min1 == &_min2);      \
		_min1 < _min2 ? _min1 : _min2; \
	})

void print_linear_hist_sec(unsigned int *vals, int vals_size, unsigned int base,
			   unsigned int step, const char *val_type,
			   unsigned int gran);

#endif /* __BLKALGN_H */
