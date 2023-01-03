/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021~2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "core_fixes.bpf.h"
#include "mdflush.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
} events SEC(".maps");

SEC("fentry/md_flush_request")
int BPF_PROG(md_flush_request, void *mddev, void *bio)
{
	__u64 pid = bpf_get_current_pid_tgid() >> 32;
	struct event event = {};
	struct gendisk *gendisk;

	event.pid = pid;
	gendisk = get_gendisk(bio);
	BPF_CORE_READ_STR_INTO(event.disk, gendisk, disk_name);
	bpf_get_current_comm(event.comm, sizeof(event.comm));
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

SEC("kprobe/md_flush_request")
int BPF_KPROBE(kprobe_md_flush_request, void *mddev, void *bio)
{
	__u64 pid = bpf_get_current_pid_tgid() >> 32;
	struct event event = {};
	struct gendisk *gendisk;

	event.pid = pid;
	gendisk = get_gendisk(bio);
	BPF_CORE_READ_STR_INTO(event.disk, gendisk, disk_name);
	bpf_get_current_comm(event.comm, sizeof(event.comm));
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
