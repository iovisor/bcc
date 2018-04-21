#include <uapi/linux/futex.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
#include <linux/sched.h>
#include <linux/time.h>

#define DEBUG_STATS HAS_DEBUG_STATS
#define PID_FILTER(pid) PID_FILTER_EXPR

enum dbg_stat {
    DEBUG_STATS_ENUM_VALS
};

#if DEBUG_STATS
BPF_HASH(dbg_stats);

static inline unsigned int encode_cmd_stat(enum dbg_stat s, int cmd) {
    return (s << 16) + cmd;
}
#endif

static inline void dbg_stat_inc(enum dbg_stat s) {
#if DEBUG_STATS
    dbg_stats.increment(s);
#endif
}

static inline void dbg_stat_inc_cmd(enum dbg_stat s, int cmd) {
#if DEBUG_STATS
    dbg_stats.increment(s);
    dbg_stats.increment(encode_cmd_stat(s, cmd));
#endif
}

struct comm {
    char name[TASK_COMM_LEN];
};

struct lock_key {
    u64 uaddr;
    u32 pid;
    u32 tgid;
    int usr_stack_id;
};

struct cur_lock {
    u64 uaddr;
    u64 futex_enter_time;
    u64 block_time;
    u64 resume_time;
    int usr_stack_id;
    int cmd;
};

struct lock_stats {
    u64 elapsed_blocked_us;
    u64 elapsed_sys_us;
    u32 max_blocked_us;
    u32 max_sys_us;
    u32 wait_count;
    u32 blocked_count;
    u32 wake_count;
    u32 errors;
};

struct hist_key {
    struct {
        u64 uaddr;
        u32 tgid;
    } key;
    u32 slot;
};

BPF_HASH(pid_lock, u32, struct cur_lock, 1000);
BPF_HASH(tgid_comm, u32, struct comm, 1000);
BPF_HASH(lock_stats, struct lock_key, struct lock_stats, 100000);
BPF_STACK_TRACE(stack_traces, STACK_STORAGE_SIZE);
BPF_HISTOGRAM(dist, struct hist_key, 100000);

static inline struct lock_stats *
lookup_lock_stats(u32 pid, u32 tgid, struct cur_lock *lock) {
    struct lock_stats zero = {};
    struct lock_key key = {};
    key.pid = pid;
    key.tgid = tgid;
    key.uaddr = lock->uaddr;
    key.usr_stack_id = lock->usr_stack_id;
    return lock_stats.lookup_or_init(&key, &zero);
}

static inline void
stats_record_error(u32 pid, u32 tgid, struct cur_lock *lock) {
    struct lock_stats *stats = lookup_lock_stats(pid, tgid, lock);
    if (stats != 0) {
        stats->errors++;
    } else {
        dbg_stat_inc_cmd(ERROR_RECORD_ERROR, lock->cmd);
    }
}

// FUTEX_FD and FUTEX_TRYLOCK_PI are neither wait nor wake
// FUTEX_FD has also been removed
static bool is_wait(int cmd) {
    static const int wait_mask =
        (1 << FUTEX_WAIT) | (1 << FUTEX_LOCK_PI) |
        (1 << FUTEX_WAIT_BITSET) | (1 << FUTEX_WAIT_REQUEUE_PI);
    return (1 << cmd) & wait_mask;
}

static bool is_wake(int cmd) {
     // Requeue operations may not actually wake up any threads
     // (if the val arg is 0), but it's still OK to classify as wake
     // as the threads are moved along to another futex queue
     static const int wake_mask =
         (1 << FUTEX_WAKE) | (1 << FUTEX_WAKE_OP) |
         (1 << FUTEX_REQUEUE) | (1 << FUTEX_CMP_REQUEUE) |
         (1 << FUTEX_UNLOCK_PI) | (1 << FUTEX_WAKE_BITSET) |
         (1 << FUTEX_CMP_REQUEUE_PI);
     return (1 << cmd) & wake_mask;
}

static inline u32 nsec_to_usec(u64 t) {
    return (u32) (t / 1000);
}

static inline u32 usec_to_msec(u32 t) {
    return t / 1000;
}

static inline u32 nsec_to_msec(u64 t) {
    return usec_to_msec(nsec_to_usec(t));
}

#if DEBUG_STATS
static inline void debug_stats_update(
      struct cur_lock *lock, u32 elapsed_sys_us, u64 timestamp) {
  if (lock->block_time == 0 && lock->resume_time == 0) {
      if (is_wait(lock->cmd)) {
        dbg_stat_inc_cmd(FUTEX_WAIT_NO_BLOCK, lock->cmd);
      }
  } else if (lock->block_time == 0) {
      dbg_stat_inc_cmd(FUTEX_ERROR_MISSING_BLOCK_TIME, lock->cmd);
  } else if (lock->resume_time == 0) {
      dbg_stat_inc_cmd(FUTEX_ERROR_MISSING_RESUME_TIME, lock->cmd);
  } else if (lock->block_time > lock->resume_time) {
      dbg_stat_inc_cmd(FUTEX_ERROR_BLOCK_TIME_LATER_THAN_RESUME, lock->cmd);
  }

  if (usec_to_msec(elapsed_sys_us) > 500) {
      dbg_stat_inc_cmd(FUTEX_LONG_SYS_TIME, lock->cmd);
      if (lock->block_time == 0) {
          dbg_stat_inc_cmd(FUTEX_LONG_SYS_TIME_NO_BLOCK, lock->cmd);
      }
      if (lock->resume_time == 0) {
          dbg_stat_inc_cmd(FUTEX_LONG_SYS_TIME_NO_RESUME, lock->cmd);
      }
  }
  if (lock->block_time != 0 &&
          nsec_to_msec(lock->block_time - lock->futex_enter_time) > 500) {
      dbg_stat_inc_cmd(FUTEX_ENTER_DELAY, lock->cmd);
  }
  if (lock->resume_time != 0 &&
          nsec_to_msec(timestamp - lock->resume_time) > 500) {
      dbg_stat_inc_cmd(FUTEX_EXIT_DELAY, lock->cmd);
  }
}
#endif

static inline void
stats_update(u32 pid, u32 tgid, u64 timestamp, struct cur_lock *lock) {
    u32 elapsed_blocked_us = 0;
    u32 elapsed_sys_us = 0;

    if (lock->resume_time != 0 && lock->block_time != 0 && is_wait(lock->cmd)) {
        elapsed_blocked_us = nsec_to_usec(lock->resume_time - lock->block_time);
        dbg_stat_inc_cmd(FUTEX_WAIT_BLOCKED, lock->cmd);
    }
    elapsed_sys_us = nsec_to_usec(timestamp - lock->futex_enter_time)
                       - elapsed_blocked_us;

#if DEBUG_STATS
    debug_stats_update(lock, elapsed_sys_us, timestamp);
#endif

    // Don't update if missing only one of resume time or block time
    if ((lock->resume_time == 0) != (lock->block_time == 0)) {
        return;
    }

    struct lock_stats *stats = lookup_lock_stats(pid, tgid, lock);
    if (stats == 0) {
        // Should never happen, but needed to keep compiler happy
        dbg_stat_inc(ERROR_LOCK_STAT_LOOKUP_FAILED);
        return;
    }

    // stats is a pointer into a shared (RCU?) hash table
    stats->elapsed_blocked_us += elapsed_blocked_us;
    stats->elapsed_sys_us += elapsed_sys_us;
    if (elapsed_blocked_us > 0) {
        stats->blocked_count++;
    }
    if (elapsed_blocked_us > stats->max_blocked_us) {
        stats->max_blocked_us = elapsed_blocked_us;
    }
    if (elapsed_sys_us > stats->max_sys_us) {
        stats->max_sys_us = elapsed_sys_us;
    }
    if (is_wait(lock->cmd)) {
        stats->wait_count++;
    }
    if (is_wake(lock->cmd)) {
        stats->wake_count++;
    }

    // Histogram of block times
    struct hist_key hist_key = {};
    hist_key.key.uaddr = lock->uaddr;
    hist_key.key.tgid = tgid;
    hist_key.slot = bpf_log2(elapsed_blocked_us);
    dist.increment(hist_key);

    // Keep track of process names
    if (0 == tgid_comm.lookup(&tgid)) {
        struct comm comm;
        bpf_get_current_comm(&comm.name, sizeof(comm.name));
        tgid_comm.update(&tgid, &comm);
    }
}

#define INVALIDATED_PREEMPTED ~1ull
int sched_switch(struct pt_regs *ctx, struct task_struct *prev) {
    u32 blocked_pid = prev->pid;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid;
    u64 ts = bpf_ktime_get_ns();

    struct cur_lock *lock;
    lock = pid_lock.lookup(&blocked_pid);
    if (lock != 0) {
        dbg_stat_inc(SCHED_SWITCH);
        if (prev->state == TASK_RUNNING) {
            dbg_stat_inc(SCHED_PREEMPT);
            lock->block_time = INVALIDATED_PREEMPTED;
        } else {
            lock->block_time = ts;
        }
    }

    lock = pid_lock.lookup(&pid);
    if (lock != 0 && lock->block_time != 0) {
        dbg_stat_inc(SCHED_SWITCH);
        lock->resume_time = ts;
    }

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_futex) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid;
    u32 tgid = pid_tgid >> 32;

    if (!(PID_FILTER(tgid)))
            return 0;

    struct cur_lock lock = {};
    lock.uaddr = (u64) args->uaddr;
    lock.futex_enter_time = bpf_ktime_get_ns();
    lock.usr_stack_id = stack_traces.get_stackid(
        (struct pt_regs*) args, BPF_F_REUSE_STACKID | BPF_F_USER_STACK);
    lock.cmd = args->op & FUTEX_CMD_MASK;

    dbg_stat_inc_cmd(FUTEX_ENTER, lock.cmd);

#if DEBUG_STATS
    struct cur_lock *last_lock = pid_lock.lookup(&pid);
    if (last_lock != 0) {
        dbg_stat_inc_cmd(FUTEX_ERROR_ENTER_TWICE, lock.cmd);
    }
#endif

    pid_lock.update(&pid, &lock);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_futex) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid;
    u32 tgid = pid_tgid >> 32;

    if (!(PID_FILTER(tgid)))
        return 0;

    struct cur_lock *lock = pid_lock.lookup(&pid);
    if (lock != 0) {
        dbg_stat_inc_cmd(FUTEX_EXIT, lock->cmd);
        if (lock->block_time != INVALIDATED_PREEMPTED) {
          u64 timestamp = bpf_ktime_get_ns();
          stats_update(pid, tgid, timestamp, lock);
        }
        pid_lock.delete(&pid);
    } else {
        dbg_stat_inc(FUTEX_EXIT);
        dbg_stat_inc(FUTEX_ERROR_EXIT_WITHOUT_MATCHING_ENTRY);
    }

    if (args->ret < 0) {
        if (lock != 0) {
            stats_record_error(pid, tgid, lock);
        } else {
            dbg_stat_inc(ERROR_RECORD_ERROR);
        }
    }
    return 0;
}
