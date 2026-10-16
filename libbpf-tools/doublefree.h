/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright 2022 LG Electronics Inc. */
#ifndef __DOUBLEFREE_H
#define __DOUBLEFREE_H

#define MAX_ENTRIES 65536
/*
 * An entry in the pending-call maps is keyed by pid_tgid and lives only for
 * the duration of one allocator call, so the bound is the number of target
 * threads inside such a call at once, not the number of allocations.
 */
#define MAX_PENDING_CALLS 1024

/*
 * A report carries every stack trace it needs. Looking them up in the BPF
 * maps from user space would race with the target reusing the address, and
 * the stack of an unrelated allocation would be printed.
 */
struct event {
	__u64 addr;
	int alloc_stackid;
	int free_stackid;
	int doublefree_stackid;
};

/*
 * An address lives in 'allocs' while the target owns it and moves to 'frees'
 * once it is handed back, so freeing it again is simply a hit in 'frees'.
 */
struct free_info {
	int alloc_stackid;
	int free_stackid;
};

/* In-flight realloc()/reallocarray() call, keyed by pid_tgid. */
struct realloc_info {
	__u64 ptr;
	__u64 size;
};

#endif /* __DOUBLEFREE_H */
