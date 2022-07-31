// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "bpfsnoop.h"

const volatile bool debug = false;

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("kprobe/__x64_sys_bpf")
int BPF_KPROBE_SYSCALL(do_sys_bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
	if (cmd != BPF_PROG_LOAD || !attr) {
		return 0;
	}
        __u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	struct event event = {};
	struct task_struct *task;
	task = (struct task_struct *)bpf_get_current_task();
	event.pid = pid;
	event.ppid = BPF_CORE_READ(task, real_parent, tgid);
	event.insn_cnt = BPF_CORE_READ(attr, insn_cnt);
	event.prog_type = BPF_CORE_READ(attr, prog_type);

	bpf_probe_read_str(&event.prog_name, sizeof(event.prog_name), &attr->prog_name);
	// TODO: Why doesn't the CORE macro work?
	// BPF_CORE_READ_STR_INTO(event.prog_name, attr, prog_name);
	if (debug) {
		bpf_printk("bpf_attr.insn_cnt: %lu", BPF_CORE_READ(attr, insn_cnt));
		bpf_printk("bpf_attr.prog_type: %lu", BPF_CORE_READ(attr, prog_type));
	}

	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
			sizeof(event));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
