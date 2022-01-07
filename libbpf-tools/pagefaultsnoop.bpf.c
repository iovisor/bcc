/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2022 Rong Tao */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "pagefaultsnoop.h"
#include "maps.bpf.h"
#include "bits.bpf.h"

#define MAX_ENTRIES	10240

const volatile pid_t target_pid = 0;
const volatile bool ignore_errors = true;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct vm_fault *);
} vmfs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, __u64);
} starts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct hist hists[PF_TYPE_MAX] = {};

static int pagefault_entry(struct pt_regs *ctx, struct vm_fault *vmf)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	__u64 ts;

	if (target_pid && target_pid != pid)
		return 0;

	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&vmfs, &tid, &vmf, BPF_ANY);
	bpf_map_update_elem(&starts, &tid, &ts, BPF_ANY);
	return 0;
};

static int pagefault_exit(struct pt_regs *ctx, pf_type_enum pf_type)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	struct vm_fault **vmfp, *vmf;
	struct vm_area_struct *vma;
	struct pagefault_event event = {};
	int ret;
	__u64 ts = bpf_ktime_get_ns();
	__u64 *tsp, slot;
	__s64 delta;

	tsp = bpf_map_lookup_elem(&starts, &tid);
	if (!tsp)
        return 0;

	delta = (__s64)(ts - *tsp);
	if (delta < 0) {
        goto cleanup;
	}

	vmfp = bpf_map_lookup_elem(&vmfs, &tid);
	if (!vmfp)
		return 0;

	ret = PT_REGS_RC(ctx);
	if (ignore_errors && ret != 0)
		goto cleanup;

	vmf = *vmfp;
	vma = BPF_CORE_READ(vmf, vma);

	event.ts_us = bpf_ktime_get_ns() / 1000;
	event.pid = pid;
	event.ret = ret;
	event.address = BPF_CORE_READ_BITFIELD_PROBED(vmf, address);
	bpf_get_current_comm(&event.task, sizeof(event.task));
	event.delta = delta;
	event.pf_type = pf_type;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

	slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&hists[pf_type].slots[slot], 1);

cleanup:
	bpf_map_delete_elem(&vmfs, &tid);
	bpf_map_delete_elem(&starts, &tid);
	return 0;
}

SEC("kprobe/do_anonymous_page")
int BPF_KPROBE(do_anonymous_entry, struct vm_fault *vmf)
{
	return pagefault_entry(ctx, vmf);
}

SEC("kretprobe/do_anonymous_page")
int BPF_KRETPROBE(do_anonymous_exit)
{
	return pagefault_exit(ctx, PF_TYPE_ANON);
}

SEC("kprobe/__do_fault")
int BPF_KPROBE(do_fault_entry, struct vm_fault *vmf)
{
	return pagefault_entry(ctx, vmf);
}

SEC("kretprobe/__do_fault")
int BPF_KRETPROBE(do_fault_exit)
{
	return pagefault_exit(ctx, PF_TYPE_FILE);
}

SEC("kprobe/do_swap_page")
int BPF_KPROBE(do_swap_entry, struct vm_fault *vmf)
{
	return pagefault_entry(ctx, vmf);
}

SEC("kretprobe/do_swap_page")
int BPF_KRETPROBE(do_swap_exit)
{
	return pagefault_exit(ctx, PF_TYPE_SWAP);
}

SEC("kprobe/do_numa_page")
int BPF_KPROBE(do_numa_entry, struct vm_fault *vmf)
{
	return pagefault_entry(ctx, vmf);
}

SEC("kretprobe/do_numa_page")
int BPF_KRETPROBE(do_numa_exit)
{
	return pagefault_exit(ctx, PF_TYPE_NUMA);
}

SEC("kprobe/do_wp_page")
int BPF_KPROBE(do_wp_entry, struct vm_fault *vmf)
{
	return pagefault_entry(ctx, vmf);
}

SEC("kretprobe/do_wp_page")
int BPF_KRETPROBE(do_wp_exit)
{
	return pagefault_exit(ctx, PF_TYPE_WRITE);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
