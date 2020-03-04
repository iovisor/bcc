// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "drsnoop.h"

#define BPF_F_INDEX_MASK		0xffffffffULL
#define BPF_F_CURRENT_CPU		BPF_F_INDEX_MASK

const volatile pid_t targ_pid = 0;
const volatile pid_t targ_tgid = 0;
const volatile __u64 vm_zone_stat_kaddr = 0;

struct piddata {
	u64 ts;
	u64 nr_free_pages;
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

SEC("tp_btf/mm_vmscan_direct_reclaim_begin")
int handle__mm_vmscan_direct_reclaim_begin(u64 *ctx)
{
	u64 *vm_zone_stat_kaddrp = (u64*)vm_zone_stat_kaddr;
	u64 id = bpf_get_current_pid_tgid();
	struct piddata piddata = {};
	u32 tgid = id >> 32;
	u32 pid = id;

	if (targ_tgid && targ_tgid != tgid)
		return 0;
	if (targ_pid && targ_pid != pid)
		return 0;

	piddata.ts = bpf_ktime_get_ns();
	if (vm_zone_stat_kaddrp) {
		bpf_probe_read(&piddata.nr_free_pages,
			       sizeof(*vm_zone_stat_kaddrp),
			       &vm_zone_stat_kaddrp[NR_FREE_PAGES]);
	}

	bpf_map_update_elem(&start, &pid, &piddata, 0);
	return 0;
}

SEC("tp_btf/mm_vmscan_direct_reclaim_end")
int handle__mm_vmscan_direct_reclaim_end(u64 *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	/* TP_PROTO(unsigned long nr_reclaimed) */
	u64 nr_reclaimed = ctx[0];
	struct piddata *piddatap;
	struct event event = {};
	u32 tgid = id >> 32;
	u32 pid = id;
	u64 delta_ns;

	if (targ_tgid && targ_tgid != tgid)
		return 0;
	if (targ_pid && targ_pid != pid)
		return 0;

	/* fetch timestamp and calculate delta */
	piddatap = bpf_map_lookup_elem(&start, &pid);
	if (!piddatap)
		return 0;   /* missed entry */

	delta_ns = bpf_ktime_get_ns() - piddatap->ts;

	event.pid = pid;
	event.nr_reclaimed = nr_reclaimed;
	event.delta_ns = delta_ns;
	event.nr_free_pages = piddatap->nr_free_pages;
	bpf_get_current_comm(&event.task, TASK_COMM_LEN);

	/* output */
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));

	bpf_map_delete_elem(&start, &pid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
