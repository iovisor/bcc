// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bitesize.h"
#include "bits.bpf.h"
#include "core_fixes.bpf.h"

const volatile char targ_comm[TASK_COMM_LEN] = {};
const volatile bool filter_dev = false;
const volatile __u32 targ_dev = 0;

extern __u32 LINUX_KERNEL_VERSION __kconfig;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct hist_key);
	__type(value, struct hist);
} hists SEC(".maps");

static struct hist initial_hist;

static __always_inline bool comm_allowed(const char *comm)
{
	int i;

	for (i = 0; i < TASK_COMM_LEN && targ_comm[i] != '\0'; i++) {
		if (comm[i] != targ_comm[i])
			return false;
	}
	return true;
}

static int trace_rq_issue(struct request *rq)
{
	struct hist_key hkey;
	struct hist *histp;
	u64 slot;

	if (filter_dev) {
		struct gendisk *disk = get_disk(rq);
		u32 dev;

		dev = disk ? MKDEV(BPF_CORE_READ(disk, major),
				BPF_CORE_READ(disk, first_minor)) : 0;
		if (targ_dev != dev)
			return 0;
	}
	bpf_get_current_comm(&hkey.comm, sizeof(hkey.comm));
	if (!comm_allowed(hkey.comm))
		return 0;

	histp = bpf_map_lookup_elem(&hists, &hkey);
	if (!histp) {
		bpf_map_update_elem(&hists, &hkey, &initial_hist, 0);
		histp = bpf_map_lookup_elem(&hists, &hkey);
		if (!histp)
			return 0;
	}
	/*
	 * BPF_CORE_READ, rather than a direct dereference: the raw_tp fallback
	 * gets its arguments as untyped scalars, so a plain rq->__data_len
	 * would be rejected by the verifier.
	 */
	slot = log2l(BPF_CORE_READ(rq, __data_len) / 1024);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&histp->slots[slot], 1);

	return 0;
}

static int handle_block_rq_issue(u64 *ctx)
{
	/**
	 * commit a54895fa (block: remove the request_queue to argument
	 * request based tracepoints) changed tracepoint argument list
	 * from TP_PROTO(struct request_queue *q, struct request *rq)
	 * to TP_PROTO(struct request *rq)
	 * see:
	 *     https://github.com/torvalds/linux/commit/a54895fa
	 */
	if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 10, 137))
		return trace_rq_issue((void *)ctx[0]);
	else
		return trace_rq_issue((void *)ctx[1]);
}

SEC("tp_btf/block_rq_issue")
int block_rq_issue_btf(u64 *ctx)
{
	return handle_block_rq_issue(ctx);
}

/*
 * raw_tp is used as a fallback for kernels without BTF-enabled raw
 * tracepoints (tp_btf), which are only available since v5.5. This
 * allows the tool to run on older LTS kernels such as v4.19 and v5.4.
 */
SEC("raw_tp/block_rq_issue")
int BPF_PROG(block_rq_issue)
{
	return handle_block_rq_issue(ctx);
}

char LICENSE[] SEC("license") = "GPL";
