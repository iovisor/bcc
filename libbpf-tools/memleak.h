#ifndef __MEMLEAK_H
#define __MEMLEAK_H

#define ALLOCS_MAX_ENTRIES 1000000

typedef struct {
	__u64 size;
	__u64 timestamp_ns;
	int stack_id;
} alloc_info_t ;

typedef struct {
	__u64 total_size;
	__u64 number_of_allocs;
} combined_alloc_info_t ;

#endif /* __MEMLEAK_H */
