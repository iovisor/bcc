/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2021 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "compat.bpf.h"
#include "mountsnoop.h"

#define MAX_ENTRIES 10240

const volatile pid_t target_pid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct arg);
} args SEC(".maps");

static int probe_entry(const char *src, const char *dest, const char *fs,
		       __u64 flags, const char *data, enum op op)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	struct arg arg = {};

	if (target_pid && target_pid != pid)
		return 0;

	arg.ts = bpf_ktime_get_ns();
	arg.op = op;

	switch (op) {
	case MOUNT:
		arg.mount.flags = flags;
		arg.mount.src = src;
		arg.mount.dest = dest;
		arg.mount.fs = fs;
		arg.mount.data= data;
		break;
	case UMOUNT:
		arg.umount.flags = flags;
		arg.umount.dest = dest;
		break;
	}
	bpf_map_update_elem(&args, &tid, &arg, BPF_ANY);
	return 0;
};

static int probe_exit(void *ctx, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	struct task_struct *task;
	struct event *eventp;
	struct arg *argp;

	argp = bpf_map_lookup_elem(&args, &tid);
	if (!argp)
		return 0;

	eventp = reserve_buf(sizeof(*eventp));
	if (!eventp)
		goto cleanup;

	task = (struct task_struct *)bpf_get_current_task();
	eventp->delta = bpf_ktime_get_ns() - argp->ts;
	eventp->op = argp->op;
	eventp->pid = pid;
	eventp->tid = tid;
	eventp->mnt_ns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	eventp->ret = ret;
	bpf_get_current_comm(&eventp->comm, sizeof(eventp->comm));

	switch (argp->op) {
	case MOUNT:
		eventp->mount.flags = argp->mount.flags;
		bpf_probe_read_user_str(eventp->mount.src, sizeof(eventp->mount.src), argp->mount.src);
		bpf_probe_read_user_str(eventp->mount.dest, sizeof(eventp->mount.dest), argp->mount.dest);
		bpf_probe_read_user_str(eventp->mount.fs, sizeof(eventp->mount.fs), argp->mount.fs);
		bpf_probe_read_user_str(eventp->mount.data, sizeof(eventp->mount.data), argp->mount.data);
		break;
	case UMOUNT:
		eventp->umount.flags = argp->umount.flags;
		bpf_probe_read_user_str(eventp->umount.dest, sizeof(eventp->umount.dest), argp->umount.dest);
		break;
	}

	submit_buf(ctx, eventp, sizeof(*eventp));

cleanup:
	bpf_map_delete_elem(&args, &tid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mount")
int mount_entry(struct syscall_trace_enter *ctx)
{
	const char *src = (const char *)ctx->args[0];
	const char *dest = (const char *)ctx->args[1];
	const char *fs = (const char *)ctx->args[2];
	__u64 flags = (__u64)ctx->args[3];
	const char *data = (const char *)ctx->args[4];

	return probe_entry(src, dest, fs, flags, data, MOUNT);
}

SEC("tracepoint/syscalls/sys_exit_mount")
int mount_exit(struct syscall_trace_exit *ctx)
{
	return probe_exit(ctx, (int)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_umount")
int umount_entry(struct syscall_trace_enter *ctx)
{
	const char *dest = (const char *)ctx->args[0];
	__u64 flags = (__u64)ctx->args[1];

	return probe_entry(NULL, dest, NULL, flags, NULL, UMOUNT);
}

SEC("tracepoint/syscalls/sys_exit_umount")
int umount_exit(struct syscall_trace_exit *ctx)
{
	return probe_exit(ctx, (int)ctx->ret);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
