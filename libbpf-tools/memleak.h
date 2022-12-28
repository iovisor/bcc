#ifndef __MEMLEAK_H
#define __MEMLEAK_H

typedef struct {
	u64 size;
	u64 timestamp_ns;
	int stack_id;
} alloc_info_t ;

typedef struct {
	u64 total_size;
	u64 number_of_allocs;
} combined_alloc_info_t ;

#endif /* __MEMLEAK_H */
