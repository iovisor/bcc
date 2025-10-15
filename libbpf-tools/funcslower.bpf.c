/* SPDX-License-Identifier: GPL-2.0 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "funcslower.h"
#include "bits.bpf.h"

#define PERF_MAX_STACK_DEPTH 127
#define MAX_ENTRIES 10240

struct entry_t {
	__u64 id;
	__u64 start_ns;
	__u64 args[MAX_ARGS];
	int user_stack_id;
	int kernel_stack_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, struct entry_t);
} entryinfo SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(__u64));
	__uint(max_entries, 2048);
} stacks SEC(".maps");

const volatile __u32 tgid = 0;
const volatile __u64 min_lat_ns = 1000000;
const volatile bool need_args = false;
const volatile int args_count = 0;
const volatile bool need_user_stack = false;
const volatile bool need_kernel_stack = false;

static int trace_entry(struct pt_regs *ctx, int id)
{
	__u64 tgid_pid = bpf_get_current_pid_tgid();
	__u32 current_tgid = tgid_pid >> 32;

	if (tgid && current_tgid != tgid)
		return 0;

	struct entry_t entry = {};
	entry.start_ns = bpf_ktime_get_ns();
	entry.id = id;

	if (need_args) {
		entry.args[0] = PT_REGS_PARM1(ctx);
		entry.args[1] = PT_REGS_PARM2(ctx);
		entry.args[2] = PT_REGS_PARM3(ctx);
		entry.args[3] = PT_REGS_PARM4(ctx);
		entry.args[4] = PT_REGS_PARM5(ctx);
		entry.args[5] = PT_REGS_PARM6(ctx);
	}

	if (need_user_stack)
		entry.user_stack_id = bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK);
	else
		entry.user_stack_id = -1;

	if (need_kernel_stack)
		entry.kernel_stack_id = bpf_get_stackid(ctx, &stacks, 0);
	else
		entry.kernel_stack_id = -1;

	bpf_map_update_elem(&entryinfo, &tgid_pid, &entry, BPF_ANY);
	return 0;
}

SEC("kretprobe/funcslower_return")
int funcslower_return(struct pt_regs *ctx)
{
	struct entry_t *entryp;
	__u64 tgid_pid = bpf_get_current_pid_tgid();

	entryp = bpf_map_lookup_elem(&entryinfo, &tgid_pid);
	if (!entryp)
		return 0;

	__u64 delta_ns = bpf_ktime_get_ns() - entryp->start_ns;
	bpf_map_delete_elem(&entryinfo, &tgid_pid);

	if (delta_ns < min_lat_ns)
		return 0;

	struct event event = {};
	event.id = entryp->id;
	event.tgid_pid = tgid_pid;
	event.start_ns = entryp->start_ns;
	event.duration_ns = delta_ns;
	event.retval = PT_REGS_RC(ctx);
	event.user_stack_id = entryp->user_stack_id;
	event.kernel_stack_id = entryp->kernel_stack_id;

	if (need_args) {
		bpf_probe_read_kernel(&event.args, sizeof(event.args), entryp->args);
	}

	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

	return 0;
}

#define DEFINE_PROBE(i) \
	SEC("kprobe/funcslower_entry_" #i) \
	int funcslower_entry_##i(struct pt_regs *ctx) \
	{\
		return trace_entry(ctx, i); \
	}

DEFINE_PROBE(0); DEFINE_PROBE(1); DEFINE_PROBE(2); DEFINE_PROBE(3);
DEFINE_PROBE(4); DEFINE_PROBE(5); DEFINE_PROBE(6); DEFINE_PROBE(7);
DEFINE_PROBE(8); DEFINE_PROBE(9); DEFINE_PROBE(10); DEFINE_PROBE(11);
DEFINE_PROBE(12); DEFINE_PROBE(13); DEFINE_PROBE(14); DEFINE_PROBE(15);
DEFINE_PROBE(16); DEFINE_PROBE(17); DEFINE_PROBE(18); DEFINE_PROBE(19);

char LICENSE[] SEC("license") = "GPL";
