// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Google LLC.
 *
 * Based on klockstat from BCC by Jiri Olsa and others
 * 2021-10-26   Barret Rhoden   Created this.
 */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "klockstat.h"
#include "bits.bpf.h"

const volatile pid_t targ_tgid = 0;
const volatile pid_t targ_pid = 0;
void *const volatile targ_lock = NULL;
const volatile int per_thread = 0;

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, MAX_ENTRIES);
	__uint(key_size, sizeof(u32));
	__uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
} stack_map SEC(".maps");

/*
 * Uniquely identifies a task grabbing a particular lock; a task can only hold
 * the same lock once (non-recursive mutexes).
 */
struct task_lock {
	u64 task_id;
	u64 lock_ptr;
};

struct task_state {
	u16 nlmsg_type;
	u16 ioctl;
};

struct lockholder_info {
	s32 stack_id;
	u16 nlmsg_type;
	u16 ioctl;
	u64 task_id;
	u64 try_at;
	u64 acq_at;
	u64 rel_at;
	u64 lock_ptr;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct task_lock);
	__type(value, struct lockholder_info);
} lockholder_map SEC(".maps");

/*
 * Keyed by stack_id.
 *
 * Multiple call sites may have the same underlying lock, but we only know the
 * stats for a particular stack frame.  Multiple tasks may have the same
 * stackframe.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, s32);
	__type(value, struct lock_stat);
} stat_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, void *);
} locks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct task_state);
} task_states SEC(".maps");

static bool tracing_task(u64 task_id)
{
	u32 tgid = task_id >> 32;
	u32 pid = task_id;

	if (targ_tgid && targ_tgid != tgid)
		return false;
	if (targ_pid && targ_pid != pid)
		return false;
	return true;
}

static void lock_contended(void *ctx, void *lock)
{
	u64 task_id;
	struct lockholder_info li[1] = {0};
	struct task_lock tl = {};

	if (targ_lock && targ_lock != lock)
		return;
	task_id = bpf_get_current_pid_tgid();
	if (!tracing_task(task_id))
		return;

	li->task_id = task_id;
	li->lock_ptr = (u64)lock;
	li->stack_id = bpf_get_stackid(ctx, &stack_map, BPF_F_FAST_STACK_CMP);

	/* Legit failures include EEXIST */
	if (li->stack_id < 0)
		return;
	li->try_at = bpf_ktime_get_ns();

	tl.task_id = task_id;
	tl.lock_ptr = (u64)lock;
	bpf_map_update_elem(&lockholder_map, &tl, li, BPF_ANY);
}

static void lock_aborted(void *lock)
{
	u64 task_id;
	struct task_lock tl = {};

	if (targ_lock && targ_lock != lock)
		return;
	task_id = bpf_get_current_pid_tgid();
	if (!tracing_task(task_id))
		return;
	tl.task_id = task_id;
	tl.lock_ptr = (u64)lock;
	bpf_map_delete_elem(&lockholder_map, &tl);
}

static void lock_acquired(void *lock)
{
	u64 task_id;
	u32 tid;
	struct task_state *state;
	struct lockholder_info *li;
	struct task_lock tl = {};

	if (targ_lock && targ_lock != lock)
		return;
	task_id = bpf_get_current_pid_tgid();
	if (!tracing_task(task_id))
		return;

	tl.task_id = task_id;
	tl.lock_ptr = (u64)lock;
	li = bpf_map_lookup_elem(&lockholder_map, &tl);
	if (!li)
		return;

	li->acq_at = bpf_ktime_get_ns();

	tid = (u32)task_id;
	state = bpf_map_lookup_elem(&task_states, &tid);
	if (state) {
		li->nlmsg_type = state->nlmsg_type;
		li->ioctl = state->ioctl;
	}
}

static void account(struct lockholder_info *li)
{
	struct lock_stat *ls;
	u64 delta;
	u32 key = li->stack_id;

	if (per_thread)
		key = li->task_id;

	/*
	 * Multiple threads may have the same stack_id.  Even though we are
	 * holding the lock, dynamically allocated mutexes can have the same
	 * callgraph but represent different locks.  Also, a rwsem can be held
	 * by multiple readers at the same time.  They will be accounted as
	 * the same lock, which is what we want, but we need to use atomics to
	 * avoid corruption, especially for the total_time variables.
	 * But it should be ok for per-thread since it's not racy anymore.
	 */
	ls = bpf_map_lookup_elem(&stat_map, &key);
	if (!ls) {
		struct lock_stat fresh = {0};

		bpf_map_update_elem(&stat_map, &key, &fresh, BPF_ANY);
		ls = bpf_map_lookup_elem(&stat_map, &key);
		if (!ls)
			return;

		if (per_thread)
			bpf_get_current_comm(ls->acq_max_comm, TASK_COMM_LEN);
	}

	delta = li->acq_at - li->try_at;
	__sync_fetch_and_add(&ls->acq_count, 1);
	__sync_fetch_and_add(&ls->acq_total_time, delta);
	if (delta > READ_ONCE(ls->acq_max_time)) {
		WRITE_ONCE(ls->acq_max_time, delta);
		WRITE_ONCE(ls->acq_max_id, li->task_id);
		WRITE_ONCE(ls->acq_max_lock_ptr, li->lock_ptr);
		WRITE_ONCE(ls->acq_max_nltype, li->nlmsg_type);
		WRITE_ONCE(ls->acq_max_ioctl, li->ioctl);
		/*
		 * Potentially racy, if multiple threads think they are the max,
		 * so you may get a clobbered write.
		 */
		if (!per_thread)
			bpf_get_current_comm(ls->acq_max_comm, TASK_COMM_LEN);
	}

	delta = li->rel_at - li->acq_at;
	__sync_fetch_and_add(&ls->hld_count, 1);
	__sync_fetch_and_add(&ls->hld_total_time, delta);
	if (delta > READ_ONCE(ls->hld_max_time)) {
		WRITE_ONCE(ls->hld_max_time, delta);
		WRITE_ONCE(ls->hld_max_id, li->task_id);
		WRITE_ONCE(ls->hld_max_lock_ptr, li->lock_ptr);
		WRITE_ONCE(ls->hld_max_nltype, li->nlmsg_type);
		WRITE_ONCE(ls->hld_max_ioctl, li->ioctl);
		if (!per_thread)
			bpf_get_current_comm(ls->hld_max_comm, TASK_COMM_LEN);
	}
}

static void lock_released(void *lock)
{
	u64 task_id;
	struct lockholder_info *li;
	struct task_lock tl = {};

	if (targ_lock && targ_lock != lock)
		return;
	task_id = bpf_get_current_pid_tgid();
	if (!tracing_task(task_id))
		return;
	tl.task_id = task_id;
	tl.lock_ptr = (u64)lock;
	li = bpf_map_lookup_elem(&lockholder_map, &tl);
	if (!li)
		return;

	li->rel_at = bpf_ktime_get_ns();
	account(li);

	bpf_map_delete_elem(&lockholder_map, &tl);
}

static void record_nltype(const struct nlmsghdr *hdr)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct task_state state = {};

	/* nlmsg_type and ioctl will never be set at the same time */
	state.nlmsg_type = BPF_CORE_READ(hdr, nlmsg_type);
	bpf_map_update_elem(&task_states, &tid, &state, BPF_ANY);
}

static void record_ioctl(unsigned int cmd)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct task_state state = {.ioctl = cmd};

	/* nlmsg_type and ioctl will never be set at the same time */
	bpf_map_update_elem(&task_states, &tid, &state, BPF_ANY);
}

static void release_task_state(void)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();

	bpf_map_delete_elem(&task_states, &tid);
}

SEC("fentry/rtnetlink_rcv_msg")
int BPF_PROG(rtnetlink_rcv_msg, struct sk_buff *skb, struct nlmsghdr *nlh,
	     struct netlink_ext_ack *extack)
{
	record_nltype(nlh);
	return 0;
}

SEC("fexit/rtnetlink_rcv_msg")
int BPF_PROG(rtnetlink_rcv_msg_exit, struct sk_buff *skb, struct nlmsghdr *nlh,
	     struct netlink_ext_ack *extack, long ret)
{
	release_task_state();
	return 0;
}

SEC("fentry/netlink_dump")
int BPF_PROG(netlink_dump, struct sock *sk, bool lock_taken)
{
	struct netlink_sock *nlk = container_of(sk, struct netlink_sock, sk);
	const struct nlmsghdr *nlh;

	nlh = BPF_CORE_READ(nlk, cb.nlh);
	record_nltype(nlh);
	return 0;
}

SEC("fexit/netlink_dump")
int BPF_PROG(netlink_dump_exit, struct sk_buff *skb, struct nlmsghdr *nlh,
	     struct netlink_ext_ack *extack)
{
	release_task_state();
	return 0;
}

SEC("fentry/sock_do_ioctl")
int BPF_PROG(sock_do_ioctl, struct net *net, struct socket *sock,
	     unsigned int cmd, unsigned long arg)
{
	record_ioctl(cmd);
	return 0;
}

SEC("fexit/sock_do_ioctl")
int BPF_PROG(sock_do_ioctl_exit)
{
	release_task_state();
	return 0;
}

SEC("fentry/mutex_lock")
int BPF_PROG(mutex_lock, struct mutex *lock)
{
	lock_contended(ctx, lock);
	return 0;
}

SEC("fexit/mutex_lock")
int BPF_PROG(mutex_lock_exit, struct mutex *lock, long ret)
{
	lock_acquired(lock);
	return 0;
}

SEC("fexit/mutex_trylock")
int BPF_PROG(mutex_trylock_exit, struct mutex *lock, long ret)
{
	if (ret) {
		lock_contended(ctx, lock);
		lock_acquired(lock);
	}
	return 0;
}

SEC("fentry/mutex_lock_interruptible")
int BPF_PROG(mutex_lock_interruptible, struct mutex *lock)
{
	lock_contended(ctx, lock);
	return 0;
}

SEC("fexit/mutex_lock_interruptible")
int BPF_PROG(mutex_lock_interruptible_exit, struct mutex *lock, long ret)
{
	if (ret)
		lock_aborted(lock);
	else
		lock_acquired(lock);
	return 0;
}

SEC("fentry/mutex_lock_killable")
int BPF_PROG(mutex_lock_killable, struct mutex *lock)
{
	lock_contended(ctx, lock);
	return 0;
}

SEC("fexit/mutex_lock_killable")
int BPF_PROG(mutex_lock_killable_exit, struct mutex *lock, long ret)
{
	if (ret)
		lock_aborted(lock);
	else
		lock_acquired(lock);
	return 0;
}

SEC("fentry/mutex_unlock")
int BPF_PROG(mutex_unlock, struct mutex *lock)
{
	lock_released(lock);
	return 0;
}

SEC("fentry/down_read")
int BPF_PROG(down_read, struct rw_semaphore *lock)
{
	lock_contended(ctx, lock);
	return 0;
}

SEC("fexit/down_read")
int BPF_PROG(down_read_exit, struct rw_semaphore *lock, long ret)
{
	lock_acquired(lock);
	return 0;
}

SEC("fexit/down_read_trylock")
int BPF_PROG(down_read_trylock_exit, struct rw_semaphore *lock, long ret)
{
	if (ret == 1) {
		lock_contended(ctx, lock);
		lock_acquired(lock);
	}
	return 0;
}

SEC("fentry/down_read_interruptible")
int BPF_PROG(down_read_interruptible, struct rw_semaphore *lock)
{
	lock_contended(ctx, lock);
	return 0;
}

SEC("fexit/down_read_interruptible")
int BPF_PROG(down_read_interruptible_exit, struct rw_semaphore *lock, long ret)
{
	if (ret)
		lock_aborted(lock);
	else
		lock_acquired(lock);
	return 0;
}

SEC("fentry/down_read_killable")
int BPF_PROG(down_read_killable, struct rw_semaphore *lock)
{
	lock_contended(ctx, lock);
	return 0;
}

SEC("fexit/down_read_killable")
int BPF_PROG(down_read_killable_exit, struct rw_semaphore *lock, long ret)
{
	if (ret)
		lock_aborted(lock);
	else
		lock_acquired(lock);
	return 0;
}

SEC("fentry/up_read")
int BPF_PROG(up_read, struct rw_semaphore *lock)
{
	lock_released(lock);
	return 0;
}

SEC("fentry/down_write")
int BPF_PROG(down_write, struct rw_semaphore *lock)
{
	lock_contended(ctx, lock);
	return 0;
}

SEC("fexit/down_write")
int BPF_PROG(down_write_exit, struct rw_semaphore *lock, long ret)
{
	lock_acquired(lock);
	return 0;
}

SEC("fexit/down_write_trylock")
int BPF_PROG(down_write_trylock_exit, struct rw_semaphore *lock, long ret)
{
	if (ret == 1) {
		lock_contended(ctx, lock);
		lock_acquired(lock);
	}
	return 0;
}

SEC("fentry/down_write_killable")
int BPF_PROG(down_write_killable, struct rw_semaphore *lock)
{
	lock_contended(ctx, lock);
	return 0;
}

SEC("fexit/down_write_killable")
int BPF_PROG(down_write_killable_exit, struct rw_semaphore *lock, long ret)
{
	if (ret)
		lock_aborted(lock);
	else
		lock_acquired(lock);
	return 0;
}

SEC("fentry/up_write")
int BPF_PROG(up_write, struct rw_semaphore *lock)
{
	lock_released(lock);
	return 0;
}

SEC("kprobe/mutex_lock")
int BPF_KPROBE(kprobe_mutex_lock, struct mutex *lock)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();

	bpf_map_update_elem(&locks, &tid, &lock, BPF_ANY);
	lock_contended(ctx, lock);
	return 0;
}

SEC("kretprobe/mutex_lock")
int BPF_KRETPROBE(kprobe_mutex_lock_exit, long ret)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	void **lock;

	lock = bpf_map_lookup_elem(&locks, &tid);
	if (!lock)
		return 0;

	bpf_map_delete_elem(&locks, &tid);
	lock_acquired(*lock);
	return 0;
}

SEC("kprobe/mutex_trylock")
int BPF_KPROBE(kprobe_mutex_trylock, struct mutex *lock)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();

	bpf_map_update_elem(&locks, &tid, &lock, BPF_ANY);
	return 0;
}

SEC("kretprobe/mutex_trylock")
int BPF_KRETPROBE(kprobe_mutex_trylock_exit, long ret)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	void **lock;

	lock = bpf_map_lookup_elem(&locks, &tid);
	if (!lock)
		return 0;

	bpf_map_delete_elem(&locks, &tid);

	if (ret) {
		lock_contended(ctx, *lock);
		lock_acquired(*lock);
	}
	return 0;
}

SEC("kprobe/mutex_lock_interruptible")
int BPF_KPROBE(kprobe_mutex_lock_interruptible, struct mutex *lock)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();

	bpf_map_update_elem(&locks, &tid, &lock, BPF_ANY);
	lock_contended(ctx, lock);
	return 0;
}

SEC("kretprobe/mutex_lock_interruptible")
int BPF_KRETPROBE(kprobe_mutex_lock_interruptible_exit, long ret)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	void **lock;

	lock = bpf_map_lookup_elem(&locks, &tid);
	if (!lock)
		return 0;

	bpf_map_delete_elem(&locks, &tid);

	if (ret)
		lock_aborted(*lock);
	else
		lock_acquired(*lock);
	return 0;
}

SEC("kprobe/mutex_lock_killable")
int BPF_KPROBE(kprobe_mutex_lock_killable, struct mutex *lock)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();

	bpf_map_update_elem(&locks, &tid, &lock, BPF_ANY);
	lock_contended(ctx, lock);
	return 0;
}

SEC("kretprobe/mutex_lock_killable")
int BPF_KRETPROBE(kprobe_mutex_lock_killable_exit, long ret)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	void **lock;

	lock = bpf_map_lookup_elem(&locks, &tid);
	if (!lock)
		return 0;

	bpf_map_delete_elem(&locks, &tid);

	if (ret)
		lock_aborted(*lock);
	else
		lock_acquired(*lock);
	return 0;
}

SEC("kprobe/mutex_unlock")
int BPF_KPROBE(kprobe_mutex_unlock, struct mutex *lock)
{
	lock_released(lock);
	return 0;
}

SEC("kprobe/down_read")
int BPF_KPROBE(kprobe_down_read, struct rw_semaphore *lock)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();

	bpf_map_update_elem(&locks, &tid, &lock, BPF_ANY);
	lock_contended(ctx, lock);
	return 0;
}

SEC("kretprobe/down_read")
int BPF_KRETPROBE(kprobe_down_read_exit, long ret)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	void **lock;

	lock = bpf_map_lookup_elem(&locks, &tid);
	if (!lock)
		return 0;

	bpf_map_delete_elem(&locks, &tid);

	lock_acquired(*lock);
	return 0;
}

SEC("kprobe/down_read_trylock")
int BPF_KPROBE(kprobe_down_read_trylock, struct rw_semaphore *lock)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();

	bpf_map_update_elem(&locks, &tid, &lock, BPF_ANY);
	return 0;
}

SEC("kretprobe/down_read_trylock")
int BPF_KRETPROBE(kprobe_down_read_trylock_exit, long ret)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	void **lock;

	lock = bpf_map_lookup_elem(&locks, &tid);
	if (!lock)
		return 0;

	bpf_map_delete_elem(&locks, &tid);

	if (ret == 1) {
		lock_contended(ctx, *lock);
		lock_acquired(*lock);
	}
	return 0;
}

SEC("kprobe/down_read_interruptible")
int BPF_KPROBE(kprobe_down_read_interruptible, struct rw_semaphore *lock)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();

	bpf_map_update_elem(&locks, &tid, &lock, BPF_ANY);
	lock_contended(ctx, lock);
	return 0;
}

SEC("kretprobe/down_read_interruptible")
int BPF_KRETPROBE(kprobe_down_read_interruptible_exit, long ret)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	void **lock;

	lock = bpf_map_lookup_elem(&locks, &tid);
	if (!lock)
		return 0;

	bpf_map_delete_elem(&locks, &tid);

	if (ret)
		lock_aborted(*lock);
	else
		lock_acquired(*lock);
	return 0;
}

SEC("kprobe/down_read_killable")
int BPF_KPROBE(kprobe_down_read_killable, struct rw_semaphore *lock)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();

	bpf_map_update_elem(&locks, &tid, &lock, BPF_ANY);
	lock_contended(ctx, lock);
	return 0;
}

SEC("kretprobe/down_read_killable")
int BPF_KRETPROBE(kprobe_down_read_killable_exit, long ret)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	void **lock;

	lock = bpf_map_lookup_elem(&locks, &tid);
	if (!lock)
		return 0;

	bpf_map_delete_elem(&locks, &tid);

	if (ret)
		lock_aborted(*lock);
	else
		lock_acquired(*lock);
	return 0;
}

SEC("kprobe/up_read")
int BPF_KPROBE(kprobe_up_read, struct rw_semaphore *lock)
{
	lock_released(lock);
	return 0;
}

SEC("kprobe/down_write")
int BPF_KPROBE(kprobe_down_write, struct rw_semaphore *lock)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();

	bpf_map_update_elem(&locks, &tid, &lock, BPF_ANY);
	lock_contended(ctx, lock);
	return 0;
}

SEC("kretprobe/down_write")
int BPF_KRETPROBE(kprobe_down_write_exit, long ret)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	void **lock;

	lock = bpf_map_lookup_elem(&locks, &tid);
	if (!lock)
		return 0;

	bpf_map_delete_elem(&locks, &tid);

	lock_acquired(*lock);
	return 0;
}

SEC("kprobe/down_write_trylock")
int BPF_KPROBE(kprobe_down_write_trylock, struct rw_semaphore *lock)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();

	bpf_map_update_elem(&locks, &tid, &lock, BPF_ANY);
	return 0;
}

SEC("kretprobe/down_write_trylock")
int BPF_KRETPROBE(kprobe_down_write_trylock_exit, long ret)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	void **lock;

	lock = bpf_map_lookup_elem(&locks, &tid);
	if (!lock)
		return 0;

	bpf_map_delete_elem(&locks, &tid);

	if (ret == 1) {
		lock_contended(ctx, *lock);
		lock_acquired(*lock);
	}
	return 0;
}

SEC("kprobe/down_write_killable")
int BPF_KPROBE(kprobe_down_write_killable, struct rw_semaphore *lock)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();

	bpf_map_update_elem(&locks, &tid, &lock, BPF_ANY);
	lock_contended(ctx, lock);
	return 0;
}

SEC("kretprobe/down_write_killable")
int BPF_KRETPROBE(kprobe_down_write_killable_exit, long ret)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	void **lock;

	lock = bpf_map_lookup_elem(&locks, &tid);
	if (!lock)
		return 0;

	bpf_map_delete_elem(&locks, &tid);

	if (ret)
		lock_aborted(*lock);
	else
		lock_acquired(*lock);
	return 0;
}

SEC("kprobe/up_write")
int BPF_KPROBE(kprobe_up_write, struct rw_semaphore *lock)
{
	lock_released(lock);
	return 0;
}

SEC("kprobe/rtnetlink_rcv_msg")
int BPF_KPROBE(kprobe_rtnetlink_rcv_msg, struct sk_buff *skb, struct nlmsghdr *nlh,
	       struct netlink_ext_ack *ext)
{
	record_nltype(nlh);
	return 0;
}

SEC("kretprobe/rtnetlink_rcv_msg")
int BPF_KRETPROBE(kprobe_rtnetlink_rcv_msg_exit, long ret)
{
	release_task_state();
	return 0;
}

SEC("kprobe/netlink_dump")
int BPF_KPROBE(kprobe_netlink_dump, struct sock *sk, bool lock_taken)
{
	struct netlink_sock *nlk = container_of(sk, struct netlink_sock, sk);
	const struct nlmsghdr *nlh;

	nlh = BPF_CORE_READ(nlk, cb.nlh);
	record_nltype(nlh);
	return 0;
}

SEC("kretprobe/netlink_dump")
int BPF_KRETPROBE(kprobe_netlink_dump_exit, long ret)
{
	release_task_state();
	return 0;
}

SEC("kprobe/sock_do_ioctl")
int BPF_PROG(kprobe_sock_do_ioctl, struct net *net, struct socket *sock,
	     unsigned int cmd, unsigned long arg)
{
	record_ioctl(cmd);
	return 0;
}

SEC("kretprobe/sock_do_ioctl")
int BPF_PROG(kprobe_sock_do_ioctl_exit)
{
	release_task_state();
	return 0;
}




char LICENSE[] SEC("license") = "GPL";
