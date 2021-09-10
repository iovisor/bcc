// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Devidas Jadhav
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "killsnoop.h"

#define MAX_ENTRIES 10240

const volatile pid_t target_pid = 0;
const volatile bool  trace_failed_only = false;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct val_t);
} values SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct val_t {
    u64 pid;
    int sig;
    int tpid;
    char comm[TASK_COMM_LEN];
};

static int probe_entry(void *ctx, int tpid, int sig)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    __u32 tid = (__u32)id;

    if (target_pid && target_pid != pid)
        return 0;

    struct val_t val = {.pid = pid};
    val.tpid = tpid;
    val.sig = sig;

    bpf_map_update_elem(&values, &tid, &val, BPF_ANY);
    return 0;
};


static int probe_return(void *ctx, int ret)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    __u32 tid = (__u32)id;
    struct event event = {};
    struct val_t *valp;

    valp = bpf_map_lookup_elem(&values, &tid);
    if (valp == 0)
        return 0;

    if (trace_failed_only && ret >= 0) {
        bpf_map_delete_elem(&values, &tid);
        return 0;
    }

    event.pid = pid;
    event.ret = ret;
    event.tpid = valp->tpid;
    event.ret = ret;
    event.sig = valp->sig;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    bpf_map_delete_elem(&values, &tid);
    return 0;
}

    SEC("tracepoint/syscalls/sys_enter_kill")
int handle_kill_entry(struct trace_event_raw_sys_enter *ctx)
{
    return probe_entry(ctx, (const int)ctx->args[0], (const int)ctx->args[1]);
}

    SEC("tracepoint/syscalls/sys_exit_kill")
int handle_kill_return(struct trace_event_raw_sys_exit *ctx)
{
    return probe_return(ctx, (int)ctx->ret);
}

    SEC("tracepoint/syscalls/sys_enter_tkill")
int handle_tkill_entry(struct trace_event_raw_sys_enter *ctx)
{
    return probe_entry(ctx, (const int)ctx->args[0], (const int)ctx->args[1]);
}

    SEC("tracepoint/syscalls/sys_exit_tkill")
int handle_tkill_return(struct trace_event_raw_sys_exit *ctx)
{
    return probe_return(ctx, (int)ctx->ret);
}

char LICENSE[] SEC("license") = "GPL";
