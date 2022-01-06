/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __PAGEFAULTSNOOP_H
#define __PAGEFAULTSNOOP_H

#define TASK_COMM_LEN	16

typedef enum {
	PF_TYPE_FILE,
	PF_TYPE_ANON,
	PF_TYPE_SWAP,
	PF_TYPE_NUMA,
	PF_TYPE_WRITE,
} pf_type_enum;

struct pagefault_event {
	__u64 ts_us;
	__u32 pid;
	union {
		int ret;
		__u32 vm_fault;
	};
	pf_type_enum pf_type;
	char task[TASK_COMM_LEN];
	unsigned long address;
};

#endif /* __PAGEFAULTSNOOP_H */
