// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Francis Laniel <flaniel@linux.microsoft.com>
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "biotop.h"
#include "maps.bpf.h"
#include "core_fixes.bpf.h"

const volatile pid_t target_pid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct request *);
	__type(value, struct start_req_t);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct request *);
	__type(value, struct who_t);
} whobyreq SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct info_t);
	__type(value, struct val_t);
} counts SEC(".maps");

static __always_inline
int trace_start(struct request *req)
{
	struct who_t who = {};
	__u64 pid_tgid;
	__u32 pid;

	/* cache PID and comm by-req */
	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;

	if (target_pid && target_pid != pid)
		return 0;

	bpf_get_current_comm(&who.name, sizeof(who.name));
	who.pid = pid;
	bpf_map_update_elem(&whobyreq, &req, &who, 0);

	return 0;
}

SEC("kprobe/blk_mq_start_request")
int BPF_KPROBE(blk_mq_start_request, struct request *req)
{
	/* time block I/O */
	struct start_req_t start_req;

	start_req.ts = bpf_ktime_get_ns();
	start_req.data_len = BPF_CORE_READ(req, __data_len);

	bpf_map_update_elem(&start, &req, &start_req, 0);
	return 0;
}

static __always_inline
int trace_done(struct request *req)
{
	struct val_t *valp, zero = {};
	struct info_t info = {};
	struct start_req_t *startp;
	unsigned int cmd_flags;
	struct gendisk *disk;
	struct who_t *whop;
	u64 delta_us;
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;

	if (target_pid && target_pid != pid)
		goto cleanup;

	/* fetch timestamp and calculate delta */
	startp = bpf_map_lookup_elem(&start, &req);
	if (!startp)
		goto cleanup;    /* missed tracing issue */

	delta_us = (bpf_ktime_get_ns() - startp->ts) / 1000;

	/* setup info_t key */
	cmd_flags = BPF_CORE_READ(req, cmd_flags);

	disk = get_disk(req);
	info.major = BPF_CORE_READ(disk, major);
	info.minor = BPF_CORE_READ(disk, first_minor);
	info.rwflag = !!((cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE);

	whop = bpf_map_lookup_elem(&whobyreq, &req);
	if (whop) {
		info.pid = whop->pid;
		__builtin_memcpy(&info.name, whop->name, sizeof(info.name));
	}

	valp = bpf_map_lookup_or_try_init(&counts, &info, &zero);

	if (valp) {
		/* save stats */
		valp->us += delta_us;
		valp->bytes += startp->data_len;
		valp->io++;
	}

cleanup:
	bpf_map_delete_elem(&start, &req);
	bpf_map_delete_elem(&whobyreq, &req);
	return 0;
}

SEC("kprobe/blk_account_io_start")
int BPF_KPROBE(blk_account_io_start, struct request *req)
{
	return trace_start(req);
}

SEC("kprobe/blk_account_io_done")
int BPF_KPROBE(blk_account_io_done, struct request *req)
{
	return trace_done(req);
}

SEC("kprobe/__blk_account_io_start")
int BPF_KPROBE(__blk_account_io_start, struct request *req)
{
	return trace_start(req);
}

SEC("kprobe/__blk_account_io_done")
int BPF_KPROBE(__blk_account_io_done, struct request *req)
{
	return trace_done(req);
}

SEC("tp_btf/block_io_start")
int BPF_PROG(block_io_start, struct request *req)
{
	return trace_start(req);
}

SEC("tp_btf/block_io_done")
int BPF_PROG(block_io_done, struct request *req)
{
	return trace_done(req);
}

char LICENSE[] SEC("license") = "GPL";
