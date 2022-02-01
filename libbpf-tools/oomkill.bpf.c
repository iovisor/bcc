// SPDX-License-Identifier: GPL
/* Copyright (c) 2022 The Inspektor Gadget authors */
#include <linux/oom.h>
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "oomkill.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("kprobe/oom_kill_process")
void BPF_KPROBE(oom_kill_process, struct oom_control *oc, const char *unused)
{
	struct task_struct *victim;
	struct task_struct *task;
	struct event event = {};

	task = (struct task_struct *) bpf_get_current_task();
	victim = BPF_CORE_READ(oc, chosen);

	event.tpid = bpf_get_current_pid_tgid() >> 32;
	event.kpid = BPF_CORE_READ(victim, tgid);
	event.pages = BPF_CORE_READ(oc, totalpages);
	bpf_get_current_comm(&event.tcomm, sizeof(event.tcomm));
	bpf_probe_read_kernel(&event.kcomm, sizeof(event.kcomm),
			      BPF_CORE_READ(victim, comm));

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
			      sizeof(event));
}

/*
 * This eBPF core program is based on bcc oomkill BPF code from iovisor
 * oomkill.py file.
 * This file was under Apache-2.0 license, I would have liked to stick with this
 * to respect its history but I need to be able to call GPL-only functions.
 */
char _license[] SEC("license") = "GPL";
