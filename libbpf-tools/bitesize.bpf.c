// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bitesize.h"
#include "bits.bpf.h"

const volatile char targ_comm[TASK_COMM_LEN] = {};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct hist_key);
	__type(value, struct hist);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} hists SEC(".maps");

static struct hist initial_hist;

static __always_inline bool comm_filtered(const char *comm)
{
	int i;

	for (i = 0; targ_comm[i] != '\0' && i < TASK_COMM_LEN; i++) {
		if (comm[i] != targ_comm[i])
			return false;
	}
	return true;
}

SEC("tp_btf/block_rq_issue")
int BPF_PROG(tp_btf__block_rq_issue, struct request_queue *q,
	     struct request *rq)
{
	struct hist_key hkey;
	struct hist *histp;
	u64 slot;

	bpf_get_current_comm(&hkey.comm, sizeof(hkey.comm));
	if (!comm_filtered(hkey.comm))
		return 0;

	histp = bpf_map_lookup_elem(&hists, &hkey);
	if (!histp) {
		bpf_map_update_elem(&hists, &hkey, &initial_hist, 0);
		histp = bpf_map_lookup_elem(&hists, &hkey);
		if (!histp)
			return 0;
	}
	slot = log2l(rq->__data_len / 1024);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&histp->slots[slot], 1);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
