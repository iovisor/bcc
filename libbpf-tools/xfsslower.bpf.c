// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "xfsslower.h"

#define BPF_F_INDEX_MASK		0xffffffffULL
#define BPF_F_CURRENT_CPU		BPF_F_INDEX_MASK

const volatile pid_t targ_tgid = 0;
const volatile __u64 min_lat = 0;

struct piddata {
	u64 ts;
	loff_t start;
	loff_t end;
	struct file *fp;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u32);
	__type(value, struct piddata);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

struct args {
	__u64 args[5];
	__u64 ret;
};

static __always_inline int
probe_entry(struct file *fp, loff_t start, loff_t end)
{
	u64 id = bpf_get_current_pid_tgid();
	struct piddata piddata = {};
	u32 tgid = id >> 32;
	u32 pid = id;

	if (targ_tgid && targ_tgid != tgid)
		return 0;

	piddata.ts = bpf_ktime_get_ns();
	piddata.fp = fp;
	piddata.start = start;
	piddata.end = end;
	if (piddata.fp)
		bpf_map_update_elem(&start, &pid, &piddata, 0);
	return 0;
}

SEC("fentry/xfs_file_read_iter")
int fentry__xfs_file_read_iter(struct args *ctx)
{
	struct kiocb *iocb = (void*)ctx->args[0];

	return probe_entry(iocb->ki_filp, iocb->ki_pos, 0);
}

SEC("fentry/xfs_file_write_iter")
int fentry__xfs_file_write_iter(struct args *ctx)
{
	struct kiocb *iocb = (void*)ctx->args[0];

	return probe_entry(iocb->ki_filp, iocb->ki_pos, 0);
}

SEC("fentry/xfs_file_open")
int fentry__xfs_file_open(struct args *ctx)
{
	struct file *fp = (void*)ctx->args[1];

	return probe_entry(fp, 0, 0);
}

SEC("fentry/xfs_file_fsync")
int fencty__xfs_file_fsync(struct args *ctx)
{
	struct file *fp = (void*)ctx->args[0];
	loff_t start = (loff_t)ctx->args[1];
	loff_t end = (loff_t)ctx->args[2];

	return probe_entry(fp, start, end);
}

static __always_inline int probe_exit(struct args *ctx, char type)
{
	u64 id = bpf_get_current_pid_tgid();
	u64 end_ns = bpf_ktime_get_ns();
	struct piddata *piddatap;
	struct event event = {};
	struct qstr qs = {};
	u32 tgid = id >> 32;
	u32 pid = id;
	u64 delta_us;

	if (targ_tgid && targ_tgid != tgid)
		return 0;

	piddatap = bpf_map_lookup_elem(&start, &pid);
	if (!piddatap)
		return 0;    /* missed entry */

	delta_us = (end_ns - piddatap->ts) / 1000;
	bpf_map_delete_elem(&start, &pid);

	if ((s64)delta_us < 0 || delta_us <= min_lat)
		return 0;

	qs = BPF_CORE_READ(piddatap, fp, f_path.dentry, d_name);
	if (qs.len == 0)
		return 0;

	bpf_core_read_str(&event.file, sizeof(event.file), qs.name);
	bpf_get_current_comm(&event.task, sizeof(event.task));
	event.delta_us = delta_us;
	event.end_ns = end_ns;
	event.offset = piddatap->start;
	event.size = type != TRACE_FSYNC ? (ssize_t)ctx->ret :
		piddatap->end - piddatap->start;
	event.type = type;
	event.tgid = tgid;

	/* output */
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));
	return 0;
}

SEC("fexit/xfs_file_read_iter")
int fexit__xfs_file_read_iter(struct args *ctx)
{
	return probe_exit(ctx, TRACE_READ);
}

SEC("fexit/xfs_file_write_iter")
int fexit__xfs_file_write_iter(struct args *ctx)
{
	return probe_exit(ctx, TRACE_WRITE);
}

SEC("fexit/xfs_file_open")
int fexit__xfs_file_open(struct args *ctx)
{
	ssize_t size = (ssize_t)ctx->ret;

	return probe_exit(ctx, TRACE_OPEN);
}

SEC("fexit/xfs_file_sync")
int fexit__xfs_file_sync(struct args *ctx)
{
	return probe_exit(ctx, TRACE_FSYNC);
}

char LICENSE[] SEC("license") = "GPL";
