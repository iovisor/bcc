// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "biosnoop.h"

#define MAX_ENTRIES 10240

const volatile char targ_disk[DISK_NAME_LEN] = {};
const volatile bool targ_queued = false;

struct piddata {
	char comm[TASK_COMM_LEN];
	u32 pid;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct request *);
	__type(value, struct piddata);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} infobyreq SEC(".maps");

struct stage {
	u64 insert;
	u64 issue;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct request *);
	__type(value, struct stage);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

static __always_inline
int trace_pid(struct request *rq)
{
	u64 id = bpf_get_current_pid_tgid();
	struct piddata piddata = {};

	piddata.pid = id;
	bpf_get_current_comm(&piddata.comm, sizeof(&piddata.comm));
	bpf_map_update_elem(&infobyreq, &rq, &piddata, 0);
	return 0;
}

SEC("fentry/blk_account_io_start")
int BPF_PROG(fentry__blk_account_io_start, struct request *rq)
{
	return trace_pid(rq);
}

SEC("kprobe/blk_account_io_merge_bio")
int BPF_KPROBE(kprobe__blk_account_io_merge_bio, struct request *rq)
{
	return trace_pid(rq);
}

static __always_inline bool disk_filtered(const char *disk)
{
	int i;

	for (i = 0; targ_disk[i] != '\0' && i < DISK_NAME_LEN; i++) {
		if (disk[i] != targ_disk[i])
			return false;
	}
	return true;
}

static __always_inline
int trace_rq_start(struct request *rq, bool insert)
{
	struct stage *stagep, stage = {};
	u64 ts = bpf_ktime_get_ns();
	char disk[DISK_NAME_LEN];

	stagep = bpf_map_lookup_elem(&start, &rq);
	if (!stagep) {
		bpf_probe_read_kernel_str(&disk, sizeof(disk),
					rq->rq_disk->disk_name);
		if (!disk_filtered(disk)) {
			bpf_map_delete_elem(&infobyreq, &rq);
			return 0;
		}
		stagep = &stage;
	}
	if (insert)
		stagep->insert = ts;
	else
		stagep->issue = ts;
	if (stagep == &stage)
		bpf_map_update_elem(&start, &rq, stagep, 0);
	return 0;
}

SEC("tp_btf/block_rq_insert")
int BPF_PROG(tp_btf__block_rq_insert, struct request_queue *q,
	     struct request *rq)
{
	return trace_rq_start(rq, true);
}

SEC("tp_btf/block_rq_issue")
int BPF_PROG(tp_btf__block_rq_issue, struct request_queue *q,
	     struct request *rq)
{
	return trace_rq_start(rq, false);
}

SEC("tp_btf/block_rq_complete")
int BPF_PROG(tp_btf__block_rq_complete, struct request *rq, int error,
	     unsigned int nr_bytes)
{
	u64 slot, ts = bpf_ktime_get_ns();
	struct piddata *piddatap;
	struct event event = {};
	struct stage *stagep;
	s64 delta;

	stagep = bpf_map_lookup_elem(&start, &rq);
	if (!stagep)
		return 0;
	delta = (s64)(ts - stagep->issue);
	if (delta < 0)
		goto cleanup;
	piddatap = bpf_map_lookup_elem(&infobyreq, &rq);
	if (!piddatap) {
		event.comm[0] = '?';
	} else {
		__builtin_memcpy(&event.comm, piddatap->comm,
				sizeof(event.comm));
		event.pid = piddatap->pid;
	}
	event.delta = delta;
	if (targ_queued && BPF_CORE_READ(rq, q, elevator)) {
		if (!stagep->insert)
			event.qdelta = -1; /* missed or don't insert entry */
		else
			event.qdelta = stagep->issue - stagep->insert;
	}
	event.ts = ts;
	event.sector = rq->__sector;
	event.len = rq->__data_len;
	event.cmd_flags = rq->cmd_flags;
	bpf_probe_read_kernel_str(&event.disk, sizeof(event.disk),
				rq->rq_disk->disk_name);
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
			sizeof(event));

cleanup:
	bpf_map_delete_elem(&start, &rq);
	bpf_map_delete_elem(&infobyreq, &rq);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
