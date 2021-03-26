// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "xfsslower.h"

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

static __always_inline int
probe_entry(struct file *fp, loff_t s, loff_t e)
{
	u64 id = bpf_get_current_pid_tgid();
	struct piddata piddata;
	u32 tgid = id >> 32;
	u32 pid = id;

	if (!fp)
		return 0;
	if (targ_tgid && targ_tgid != tgid)
		return 0;

	piddata.ts = bpf_ktime_get_ns();
	piddata.start = s;
	piddata.end = e;
	piddata.fp = fp;
	bpf_map_update_elem(&start, &pid, &piddata, 0);
	return 0;
}

SEC("kprobe/xfs_file_read_iter")
int BPF_KPROBE(xfs_file_read_iter, struct kiocb *iocb)
{
	struct file *fp = BPF_CORE_READ(iocb, ki_filp);
	loff_t start = BPF_CORE_READ(iocb, ki_pos);

	return probe_entry(fp, start, 0);
}

SEC("kprobe/xfs_file_write_iter")
int BPF_KPROBE(xfs_file_write_iter, struct kiocb *iocb)
{
	struct file *fp = BPF_CORE_READ(iocb, ki_filp);
	loff_t start = BPF_CORE_READ(iocb, ki_pos);

	return probe_entry(fp, start, 0);
}

SEC("kprobe/xfs_file_open")
int BPF_KPROBE(xfs_file_open, struct inode *inode, struct file *file)
{
	return probe_entry(file, 0, 0);
}

SEC("kprobe/xfs_file_fsync")
int BPF_KPROBE(xfs_file_fsync, struct file *file, loff_t start,
	       loff_t end)
{
	return probe_entry(file, start, end);
}

static __always_inline int
probe_exit(struct pt_regs *ctx, char type, ssize_t size)
{
	u64 id = bpf_get_current_pid_tgid();
	u64 end_ns = bpf_ktime_get_ns();
	struct piddata *piddatap;
	struct event event = {};
	struct dentry *dentry;
	const u8 *qs_name_ptr;
	u32 tgid = id >> 32;
	struct file *fp;
	u32 pid = id;
	u64 delta_us;
	u32 qs_len;

	if (targ_tgid && targ_tgid != tgid)
		return 0;

	piddatap = bpf_map_lookup_elem(&start, &pid);
	if (!piddatap)
		return 0;    /* missed entry */

	delta_us = (end_ns - piddatap->ts) / 1000;
	bpf_map_delete_elem(&start, &pid);

	if ((s64)delta_us < 0 || delta_us <= min_lat * 1000)
		return 0;

	fp = piddatap->fp;
	dentry = BPF_CORE_READ(fp, f_path.dentry);
	qs_len = BPF_CORE_READ(dentry, d_name.len);
	qs_name_ptr = BPF_CORE_READ(dentry, d_name.name);
	bpf_probe_read_kernel_str(&event.file, sizeof(event.file), qs_name_ptr);
	bpf_get_current_comm(&event.task, sizeof(event.task));
	event.delta_us = delta_us;
	event.end_ns = end_ns;
	event.offset = piddatap->start;
	if (type != TRACE_FSYNC)
		event.size = size;
	else
		event.size = piddatap->end - piddatap->start;
	event.type = type;
	event.tgid = tgid;

	/* output */
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));
	return 0;
}

SEC("kretprobe/xfs_file_read_iter")
int BPF_KRETPROBE(xfs_file_read_iters_ret, ssize_t ret)
{
	return probe_exit(ctx, TRACE_READ, ret);
}

SEC("kretprobe/xfs_file_write_iter")
int BPF_KRETPROBE(xfs_file_write_iter_ret, ssize_t ret)
{
	return probe_exit(ctx, TRACE_WRITE, ret);
}

SEC("kretprobe/xfs_file_open")
int BPF_KRETPROBE(xfs_file_open_ret)
{
	return probe_exit(ctx, TRACE_OPEN, 0);
}

SEC("kretprobe/xfs_file_fsync")
int BPF_KRETPROBE(xfs_file_sync_ret)
{
	return probe_exit(ctx, TRACE_FSYNC, 0);
}

char LICENSE[] SEC("license") = "GPL";
