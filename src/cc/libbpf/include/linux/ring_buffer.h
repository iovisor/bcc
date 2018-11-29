/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef _TOOLS_LINUX_RING_BUFFER_H_
#define _TOOLS_LINUX_RING_BUFFER_H_

#define READ_ONCE(x)		(*(volatile typeof(x) *)&x)
#define WRITE_ONCE(x, v)	(*(volatile typeof(x) *)&x) = (v)

#define barrier()		asm volatile("" ::: "memory")

#if defined(__x86_64__)
# define smp_store_release(p, v)		\
do {						\
	barrier();				\
	WRITE_ONCE(*p, v);			\
} while (0)

# define smp_load_acquire(p)			\
({						\
	typeof(*p) ___p = READ_ONCE(*p);	\
	barrier();				\
	___p;					\
})
#else
# define smp_mb()	__sync_synchronize()

# define smp_store_release(p, v)		\
do {						\
	smp_mb();				\
	WRITE_ONCE(*p, v);			\
} while (0)

# define smp_load_acquire(p)			\
({						\
	typeof(*p) ___p = READ_ONCE(*p);	\
	smp_mb();				\
	___p;					\
})
#endif /* defined(__x86_64__) */

static inline __u64 ring_buffer_read_head(struct perf_event_mmap_page *base)
{
	return smp_load_acquire(&base->data_head);
}

static inline void ring_buffer_write_tail(struct perf_event_mmap_page *base,
					  __u64 tail)
{
	smp_store_release(&base->data_tail, tail);
}

#endif /* _TOOLS_LINUX_RING_BUFFER_H_ */
