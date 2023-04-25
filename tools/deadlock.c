/*
 * deadlock.c  Detects potential deadlocks in a running process.
 *             For Linux, uses BCC, eBPF. See .py file.
 *
 * Copyright 2017 Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 1-Feb-2016   Kenny Yu   Created this.
 */

#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

// Maximum number of mutexes a single thread can hold at once.
// If the number is too big, the unrolled loops wil cause the stack
// to be too big, and the bpf verifier will fail.
#define MAX_HELD_MUTEXES 16

// Info about held mutexes. `mutex` will be 0 if not held.
struct held_mutex_t {
  u64 mutex;
  u64 stack_id;
};

// List of mutexes that a thread is holding. Whenever we loop over this array,
// we need to force the compiler to unroll the loop, otherwise the bcc verifier
// will fail because the loop will create a backwards edge.
struct thread_to_held_mutex_leaf_t {
  struct held_mutex_t held_mutexes[MAX_HELD_MUTEXES];
};

// Map of thread ID -> array of (mutex addresses, stack id)
BPF_HASH(thread_to_held_mutexes, u32, struct thread_to_held_mutex_leaf_t, MAX_THREADS);

// Key type for edges. Represents an edge from mutex1 => mutex2.
struct edges_key_t {
  u64 mutex1;
  u64 mutex2;
};

// Leaf type for edges. Holds information about where each mutex was acquired.
struct edges_leaf_t {
  u64 mutex1_stack_id;
  u64 mutex2_stack_id;
  u32 thread_pid;
  char comm[TASK_COMM_LEN];
};

// Represents all edges currently in the mutex wait graph.
BPF_HASH(edges, struct edges_key_t, struct edges_leaf_t, MAX_EDGES);

// Info about parent thread when a child thread is created.
struct thread_created_leaf_t {
  u64 stack_id;
  u32 parent_pid;
  char comm[TASK_COMM_LEN];
};

// Map of child thread pid -> info about parent thread.
BPF_HASH(thread_to_parent, u32, struct thread_created_leaf_t);

// Stack traces when threads are created and when mutexes are locked/unlocked.
BPF_STACK_TRACE(stack_traces, MAX_TRACES);

// The first argument to the user space function we are tracing
// is a pointer to the mutex M held by thread T.
//
// For all mutexes N held by mutexes_held[T]
//   add edge N => M (held by T)
// mutexes_held[T].add(M)
int trace_mutex_acquire(struct pt_regs *ctx, void *mutex_addr) {
  // Higher 32 bits is process ID, Lower 32 bits is thread ID
  u32 pid = bpf_get_current_pid_tgid();
  u64 mutex = (u64)mutex_addr;

  struct thread_to_held_mutex_leaf_t empty_leaf = {};
  struct thread_to_held_mutex_leaf_t *leaf =
      thread_to_held_mutexes.lookup_or_try_init(&pid, &empty_leaf);
  if (!leaf) {
    bpf_trace_printk(
        "could not add thread_to_held_mutex key, thread: %d, mutex: %p\n", pid,
        mutex);
    return 1; // Could not insert, no more memory
  }

  // Recursive mutexes lock the same mutex multiple times. We cannot tell if
  // the mutex is recursive after the mutex is already created. To avoid noisy
  // reports, disallow self edges. Do one pass to check if we are already
  // holding the mutex, and if we are, do nothing.
  #pragma unroll
  for (int i = 0; i < MAX_HELD_MUTEXES; ++i) {
    if (leaf->held_mutexes[i].mutex == mutex) {
      return 1; // Disallow self edges
    }
  }

  u64 stack_id =
      stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

  int added_mutex = 0;
  #pragma unroll
  for (int i = 0; i < MAX_HELD_MUTEXES; ++i) {
    // If this is a free slot, see if we can insert.
    if (!leaf->held_mutexes[i].mutex) {
      if (!added_mutex) {
        leaf->held_mutexes[i].mutex = mutex;
        leaf->held_mutexes[i].stack_id = stack_id;
        added_mutex = 1;
      }
      continue; // Nothing to do for a free slot
    }

    // Add edges from held mutex => current mutex
    struct edges_key_t edge_key = {};
    edge_key.mutex1 = leaf->held_mutexes[i].mutex;
    edge_key.mutex2 = mutex;

    struct edges_leaf_t edge_leaf = {};
    edge_leaf.mutex1_stack_id = leaf->held_mutexes[i].stack_id;
    edge_leaf.mutex2_stack_id = stack_id;
    edge_leaf.thread_pid = pid;
    bpf_get_current_comm(&edge_leaf.comm, sizeof(edge_leaf.comm));

    // Returns non-zero on error
    int result = edges.update(&edge_key, &edge_leaf);
    if (result) {
      bpf_trace_printk("could not add edge key %p, %p, error: %d\n",
                       edge_key.mutex1, edge_key.mutex2, result);
      continue; // Could not insert, no more memory
    }
  }

  // There were no free slots for this mutex.
  if (!added_mutex) {
    bpf_trace_printk("could not add mutex %p, added_mutex: %d\n", mutex,
                     added_mutex);
    return 1;
  }
  return 0;
}

// The first argument to the user space function we are tracing
// is a pointer to the mutex M held by thread T.
//
// mutexes_held[T].remove(M)
int trace_mutex_release(struct pt_regs *ctx, void *mutex_addr) {
  // Higher 32 bits is process ID, Lower 32 bits is thread ID
  u32 pid = bpf_get_current_pid_tgid();
  u64 mutex = (u64)mutex_addr;

  struct thread_to_held_mutex_leaf_t *leaf =
      thread_to_held_mutexes.lookup(&pid);
  if (!leaf) {
    // If the leaf does not exist for the pid, then it means we either missed
    // the acquire event, or we had no more memory and could not add it.
    bpf_trace_printk(
        "could not find thread_to_held_mutex, thread: %d, mutex: %p\n", pid,
        mutex);
    return 1;
  }

  // For older kernels without "Bpf: allow access into map value arrays"
  // (https://lkml.org/lkml/2016/8/30/287) the bpf verifier will fail with an
  // invalid memory access on `leaf->held_mutexes[i]` below. On newer kernels,
  // we can avoid making this extra copy in `value` and use `leaf` directly.
  struct thread_to_held_mutex_leaf_t value = {};
  bpf_probe_read_user(&value, sizeof(struct thread_to_held_mutex_leaf_t), leaf);

  #pragma unroll
  for (int i = 0; i < MAX_HELD_MUTEXES; ++i) {
    // Find the current mutex (if it exists), and clear it.
    // Note: Can't use `leaf->` in this if condition, see comment above.
    if (value.held_mutexes[i].mutex == mutex) {
      leaf->held_mutexes[i].mutex = 0;
      leaf->held_mutexes[i].stack_id = 0;
    }
  }

  return 0;
}

// Trace return from clone() syscall in the child thread (return value > 0).
int trace_clone(struct pt_regs *ctx, unsigned long flags, void *child_stack,
                void *ptid, void *ctid, struct pt_regs *regs) {
  u32 child_pid = PT_REGS_RC(ctx);
  if (child_pid <= 0) {
    return 1;
  }

  struct thread_created_leaf_t thread_created_leaf = {};
  thread_created_leaf.parent_pid = bpf_get_current_pid_tgid();
  thread_created_leaf.stack_id =
      stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
  bpf_get_current_comm(&thread_created_leaf.comm,
                       sizeof(thread_created_leaf.comm));

  struct thread_created_leaf_t *insert_result =
      thread_to_parent.lookup_or_try_init(&child_pid, &thread_created_leaf);
  if (!insert_result) {
    bpf_trace_printk(
        "could not add thread_created_key, child: %d, parent: %d\n", child_pid,
        thread_created_leaf.parent_pid);
    return 1; // Could not insert, no more memory
  }
  return 0;
}
