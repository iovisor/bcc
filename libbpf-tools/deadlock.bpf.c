/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2022 LG Electronics */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "deadlock.h"
#include "maps.bpf.h"

const volatile pid_t targ_pid = -1;

/* Map of thread ID -> array of (mutex addresses, stack id) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct thread_to_held_mutex_leaf_t);
} thread_to_held_mutexes SEC(".maps");

/* Represents all edges currently in the mutex wait graph. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct edges_key_t);
	__type(value, struct edges_leaf_t);
} edges SEC(".maps");

/* Map of child thread pid -> info about parent thread. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct thread_created_leaf_t);
	__uint(max_entries, 10240); /* default size */
} thread_to_parent SEC(".maps");

/* Stack traces when threads are created and when mutexes are locked/unlocked. */
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32);
} stack_traces SEC(".maps");

/*
 * The first argument to the user space function we are tracing
 * is a pointer to the mutex M held by thread T.
 *
 * For all mutexes N held by mutexes_held[T]
 *   add edge N => M (held by T)
 * mutexes_held[T].add(M)
 */
SEC("uprobe/dummy_mutex_lock")
int BPF_KPROBE(dummy_mutex_lock, void *mutex)
{
	/* Higher 32 bits is process ID, Lower 32 bits is thread ID */
	u32 pid = bpf_get_current_pid_tgid();
	u64 stack_id;
	int added_mutex;
	char name[16];

	bpf_get_current_comm(&name, sizeof(name));

	struct thread_to_held_mutex_leaf_t empty_leaf = {};
	struct thread_to_held_mutex_leaf_t *leaf =
		bpf_map_lookup_or_try_init(&thread_to_held_mutexes, &pid, &empty_leaf);
	if (!leaf) {
		bpf_printk("could not add thread_to_held_mutex key, thread: %d, mutex: %p\n",
			   pid, mutex);
		return 1; /* Could not insert, no more memory */
	}

	/*
	 * Recursive mutexes lock the same mutex multiple times. We cannot tell if
	 * the mutex is recursive after the mutex is already created. To avoid noisy
	 * reports, disallow self edges. Do one pass to check if we are already
	 * holding the mutex, and if we are, do nothing.
	 */
	#pragma unroll
	for (int i = 0; i < MAX_HELD_MUTEXES; ++i) {
		if (leaf->held_mutexes[i].mutex == mutex) {
			return 1; /* Disallow self edges */
		}
	}

	stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);

	added_mutex = 0;
	#pragma unroll
	for (int i = 0; i < MAX_HELD_MUTEXES; ++i) {
		/* If this is a free slot, see if we can insert. */
		if (!leaf->held_mutexes[i].mutex) {
			if (!added_mutex) {
				leaf->held_mutexes[i].mutex = mutex;
				leaf->held_mutexes[i].stack_id = stack_id;
				added_mutex = 1;
			}
			continue; /* Nothing to do for a free slot */
		}

		/* Add edges from held mutex => current mutex */
		struct edges_key_t edge_key = {};
		edge_key.mutex1 = leaf->held_mutexes[i].mutex;
		edge_key.mutex2 = mutex;

		struct edges_leaf_t edge_leaf = {};
		edge_leaf.mutex1_stack_id = leaf->held_mutexes[i].stack_id;
		edge_leaf.mutex2_stack_id = stack_id;
		edge_leaf.thread_pid = pid;
		bpf_get_current_comm(&edge_leaf.comm, sizeof(edge_leaf.comm));

		/* Returns non-zero on error */
		int result = bpf_map_update_elem(&edges, &edge_key, &edge_leaf, BPF_ANY);
		if (result) {
			bpf_printk("could not add edge key %p, %p, error: %d\n",
				   edge_key.mutex1, edge_key.mutex2, result);
			continue; /* Could not insert, no more memory */
		}
	}

	/* There were no free slots for this mutex. */
	if (!added_mutex) {
		bpf_printk("could not add mutex %p, added_mutex: %d\n", mutex,
			   added_mutex);
		return 1;
	}

	return 0;
}

/*
 * The first argument to the user space function we are tracing
 * is a pointer to the mutex M held by thread T.
 *
 * mutexes_held[T].remove(M)
 */
SEC("kprobe/dummy_mutex_unlock")
int BPF_KPROBE(dummy_mutex_unlock, void *mutex)
{
	/* Higher 32 bits is process ID, Lower 32 bits is thread ID */
	u32 pid = bpf_get_current_pid_tgid();

	struct thread_to_held_mutex_leaf_t *leaf;
	leaf = bpf_map_lookup_elem(&thread_to_held_mutexes, &pid);
	if (!leaf) {
		/*
		 * If the leaf does not exist for the pid, then it means we either missed
		 * the acquire event, or we had no more memory and could not add it.
		 */
		bpf_printk("could not find thread_to_held_mutex, thread: %d, mutex: %p\n",
			   pid, mutex);
		return 1;
	}

	/*
	 * For older kernels without "Bpf: allow access into map value arrays"
	 * (https://lkml.org/lkml/2016/8/30/287) the bpf verifier will fail with an
	 * invalid memory access on `leaf->held_mutexes[i]` below. On newer kernels,
	 * we can avoid making this extra copy in `value` and use `leaf` directly.
	 */
	struct thread_to_held_mutex_leaf_t value = {};
	bpf_probe_read_user(&value, sizeof(struct thread_to_held_mutex_leaf_t), leaf);

	#pragma unroll
	for (int i = 0; i < MAX_HELD_MUTEXES; ++i) {
		/*
		 * Find the current mutex (if it exists), and clear it.
		 * Note: Can't use `leaf->` in this if condition, see comment above.
		 */
		if (value.held_mutexes[i].mutex == mutex) {
			leaf->held_mutexes[i].mutex = 0;
			leaf->held_mutexes[i].stack_id = 0;
		}
	}

	return 0;
}

/* Trace return from clone() syscall in the child thread (return value > 0). */
SEC("tracepoint/syscalls/sys_exit_clone")
int dummy_clone(struct trace_event_raw_sys_exit *ctx)
{
	u32 child_pid = (u32)ctx->ret;
	if (child_pid <= 0) {
		return 1;
	}

	struct thread_created_leaf_t thread_created_leaf = {};
	thread_created_leaf.parent_pid = bpf_get_current_pid_tgid();
	thread_created_leaf.stack_id =
		bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
	bpf_get_current_comm(&thread_created_leaf.comm,
			     sizeof(thread_created_leaf.comm));

	struct thread_created_leaf_t *insert_result =
		bpf_map_lookup_or_try_init(&thread_to_parent, &child_pid, &thread_created_leaf);
	if (!insert_result) {
		bpf_printk("could not add thread_created_key, child: %d, parent: %d\n", child_pid,
			   thread_created_leaf.parent_pid);
		return 1; /* Could not insert, no more memory */
	}
	return 0;
}
char LICENSE[] SEC("license") = "GPL";
