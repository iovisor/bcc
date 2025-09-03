// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Jingxiang Zeng
// Copyright (c) 2022 Krisztian Fekete
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "compat.bpf.h"
#include "oomkill.h"

/* linux:include/linux/memcontrol.h */
struct mem_cgroup {
	struct cgroup_subsys_state css;
};

SEC("kprobe/oom_kill_process")
int BPF_KPROBE(oom_kill_process, struct oom_control *oc, const char *message)
{
	struct data_t *data;
	struct mem_cgroup *memcg;

	data = reserve_buf(sizeof(*data));
	if (!data)
		return 0;

	data->fpid = bpf_get_current_pid_tgid() >> 32;
	data->tpid = BPF_CORE_READ(oc, chosen, tgid);
	data->pages = BPF_CORE_READ(oc, totalpages);
	data->cgroupid = bpf_get_current_cgroup_id();

	/* Get the memory cgroup id */
	memcg = BPF_CORE_READ(oc, memcg);
	if (memcg) {
		struct cgroup *cgrp = BPF_CORE_READ(memcg, css.cgroup);
		data->mem_cgroupid = BPF_CORE_READ(cgrp, kn, id);
	} else
		data->mem_cgroupid = 0;

	bpf_get_current_comm(&data->fcomm, sizeof(data->fcomm));
	bpf_probe_read_kernel(&data->tcomm, sizeof(data->tcomm), BPF_CORE_READ(oc, chosen, comm));
	submit_buf(ctx, data, sizeof(*data));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
