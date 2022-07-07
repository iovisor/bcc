/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2021 Sony Group Corporation */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "sysinjector.h"

const volatile pid_t targ_tgid = 0;
const volatile char targ_comm[TASK_COMM_LEN] = {};
const volatile int retval = 0;

static __always_inline int comm_allowed(const char *comm)
{
	int i;

	for (i = 0; i < TASK_COMM_LEN && targ_comm[i] != '\0'; i++) {
		if (comm[i] != targ_comm[i])
			return false;
	}
	return true;
}

SEC("kprobe/target_syscall")
int BPF_KPROBE(handle_retval_at_enter)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid >> 32;
	char current_comm[TASK_COMM_LEN];

	if (targ_tgid && targ_tgid != tgid)
		return 0;

	bpf_get_current_comm(current_comm, sizeof(current_comm));
	if (!comm_allowed(current_comm))
		return 0;

	bpf_override_return(ctx, retval);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
