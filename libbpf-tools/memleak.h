/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#ifndef __MEMLEAK_H
#define __MEMLEAK_H

#define MAX_HASH_ENTRY_NUM	(1024 * 1024)

struct alloc_info_t {
	__u64 size;
	__u64 timestamp_ns;
	int stack_id;
};

struct combined_alloc_info_t {
	__u64 total_size;
	__u64 number_of_allocs;
};

#endif /* __MEMLEAK_H */
