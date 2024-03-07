/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef __DEADLOCK_H
#define __DEADLOCK_H

#define TASK_COMM_LEN		16
#define MAX_ENTRIES		10240
#define MAX_EDGES		65536
#define MAX_THREADS		65536
/*
 * Maximum number of mutexes a single thread can hold at once.
 * If the number is too big, the unrolled loops wil cause the stack
 * to be too big, and the bpf verifier will fail.
 */
#define MAX_HELD_MUTEXES	16

/* Key type for edges. Represents an edge from mutex1 => mutex2. */
struct edges_key_t {
	__u64 mutex1;
	__u64 mutex2;
};

/* Leaf type for edges. Holds information about where each mutex was acquired. */
struct edges_leaf_t {
	__u64 mutex1_stack_id;
	__u64 mutex2_stack_id;
	__u32 thread_pid;
	char comm[TASK_COMM_LEN];
};

/* Info about parent thread when a child thread is created. */
struct thread_created_leaf_t {
	__u64 stack_id;
	__u32 parent_pid;
	char comm[TASK_COMM_LEN];
};

/* Info about held mutexes. `mutex` will be 0 if not held. */
struct held_mutex_t {
	__u64 mutex;
	__u64 stack_id;
};

/*
 * List of mutexes that a thread is holding. Whenever we loop over this array,
 * we need to force the compiler to unroll the loop, otherwise the bcc verifier
 * will fail because the loop will create a backwards edge.
 */
struct thread_to_held_mutex_leaf_t {
	struct held_mutex_t held_mutexes[MAX_HELD_MUTEXES];
};
#endif /* __DEADLOCK_H */
