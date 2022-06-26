// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Ze Gao

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "funcslower.h"

const volatile pid_t targ_tgid = 0;
const volatile __u64 duration = 0;
const volatile __u32 num_args = 0;
const volatile bool filter_cg = false;
const volatile bool show_kstack = false;
const volatile bool show_ustack = false;

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_PIDS);
        __type(key, u64);
        __type(value, struct entry_t);
} starts SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_STACK_TRACE);
        __uint(key_size, sizeof(u32));
} stackmap SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
        __type(key, u32);
        __type(value, u32);
        __uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
        __uint(key_size, sizeof(u32));
        __uint(value_size, sizeof(u32));
} events SEC(".maps");

static inline int trace_entry(struct pt_regs *ctx) {
        struct entry_t entry = {};

        if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
                return 0;
        entry.start_ns = bpf_ktime_get_ns();
        entry.tgid = bpf_get_current_pid_tgid();
        if (targ_tgid != -1 && targ_tgid != (entry.tgid >> 32))
                return 0;

        entry.args[0] = PT_REGS_PARM1_CORE(ctx);
        entry.args[1] = PT_REGS_PARM2_CORE(ctx);
        entry.args[2] = PT_REGS_PARM3_CORE(ctx);
        entry.args[3] = PT_REGS_PARM4_CORE(ctx);
        entry.args[4] = PT_REGS_PARM5_CORE(ctx);

        bpf_map_update_elem(&starts, &entry.tgid, &entry, BPF_ANY);

        return 0;
}

static inline int trace_return(struct pt_regs *ctx) {
        u64 tgid, nsec, delta_ns;
        struct entry_t *entry;
        struct data_t data = {};

        if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
                return 0;
        nsec = bpf_ktime_get_ns();
        tgid = bpf_get_current_pid_tgid();
        entry = bpf_map_lookup_elem(&starts, &tgid);
        if (!entry)
                return 0;
        bpf_map_delete_elem(&starts, &tgid);
        delta_ns = nsec - entry->start_ns;
        if (delta_ns < duration)
                return 0;
        data.id = bpf_get_attach_cookie(ctx);
        data.tgid = entry->tgid;
        data.start_ns = entry->start_ns;
        data.duration_ns = delta_ns;
        data.kstack = show_kstack ? bpf_get_stackid(ctx, &stackmap, 0) : -1;
        data.ustack = show_ustack
                          ? bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK)
                          : -1;
        data.retval = PT_REGS_RC_CORE(ctx);
        __builtin_memcpy(&data.args[0], &entry->args, sizeof(data.args));
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data,
                              sizeof(data));

        return 0;
}

SEC("kprobe/dummy_kprobe")
int dummy_kprobe(struct pt_regs *ctx) { return trace_entry(ctx); }

SEC("kretprobe/dummy_kretprobe")
int dummy_kretprobe(struct pt_regs *ctx) { return trace_return(ctx); }

char LICENSE[] SEC("license") = "GPL";
