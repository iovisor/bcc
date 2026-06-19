// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Chenyue Zhou  (original BCC Python version)
// Copyright (c) 2026 Ism Hong      (libbpf/CO-RE port)
//
// Based on softirqslower(8) from BCC by Chenyue Zhou.
// libbpf/CO-RE version.
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "softirqslower.h"

/* Configurable from userspace via rodata */
const volatile __u64 min_us    = 10000;
const volatile int   targ_cpu  = -1;

/*
 * Per-CPU arrays indexed by softirq vector number.
 * raise[vec] stores the timestamp when the softirq was raised.
 * entry[vec] stores the timestamp when the softirq handler started.
 *
 * We use PERCPU_ARRAY so we don't need locks; each CPU has its own slot.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, NR_SOFTIRQS);
	__type(key, u32);
	__type(value, u64);
} raise_ts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, NR_SOFTIRQS);
	__type(key, u32);
	__type(value, u64);
} entry_ts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

static __always_inline bool cpu_allowed(u32 cpu)
{
	if (targ_cpu < 0)
		return true;
	return (int)cpu == targ_cpu;
}

static __always_inline void submit_event(void *ctx, u32 stage, u32 vec,
					 u32 cpu, u64 delta_us)
{
	struct event e = {};

	e.stage    = stage;
	e.vec      = vec;
	e.cpu      = cpu;
	e.delta_us = delta_us;
	bpf_get_current_comm(&e.task, sizeof(e.task));
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &e, sizeof(e));
}

/*
 * softirq_raise  –  record the moment raise_softirq() fires.
 * Only record if the slot is empty (ts == 0); if it is already occupied the
 * previous raise hasn't been consumed yet, which means we'd overwrite a
 * pending timestamp.  We intentionally skip it so we don't lose the older
 * measurement.
 */
static int handle_raise(void *ctx, unsigned int vec_nr)
{
	u64 ts, *tsp;
	u32 cpu, vec = vec_nr;

	cpu = bpf_get_smp_processor_id();
	if (!cpu_allowed(cpu) || vec >= NR_SOFTIRQS)
		return 0;

	tsp = bpf_map_lookup_elem(&raise_ts, &vec);
	if (!tsp)
		return 0;

	/*
	 * Only store if not already pending (equivalent to the Python version's
	 * "not_first" check: skip if a prior raise timestamp wasn't consumed).
	 */
	if (*tsp == 0) {
		ts = bpf_ktime_get_ns();
		*tsp = ts;
	}
	return 0;
}

/*
 * softirq_entry  –  measure raise→entry latency, then start entry timer.
 */
static int handle_entry(void *ctx, unsigned int vec_nr)
{
	u64 now, delta_us, *tsp;
	u32 cpu, vec = vec_nr;

	cpu = bpf_get_smp_processor_id();
	if (!cpu_allowed(cpu) || vec >= NR_SOFTIRQS)
		return 0;

	now = bpf_ktime_get_ns();

	/* Raise → entry latency */
	tsp = bpf_map_lookup_elem(&raise_ts, &vec);
	if (tsp && *tsp) {
		delta_us = (now - *tsp) / 1000;
		if (delta_us >= min_us)
			submit_event(ctx, SOFTIRQ_RAISE, vec, cpu, delta_us);
		*tsp = 0;
	}

	/* Start entry timer (always, even if we missed the raise event) */
	tsp = bpf_map_lookup_elem(&entry_ts, &vec);
	if (tsp)
		*tsp = now;

	return 0;
}

/*
 * softirq_exit  –  measure entry→exit (handler runtime) latency.
 */
static int handle_exit(void *ctx, unsigned int vec_nr)
{
	u64 now, delta_us, *tsp;
	u32 cpu, vec = vec_nr;

	cpu = bpf_get_smp_processor_id();
	if (!cpu_allowed(cpu) || vec >= NR_SOFTIRQS)
		return 0;

	now = bpf_ktime_get_ns();

	tsp = bpf_map_lookup_elem(&entry_ts, &vec);
	if (!tsp || !*tsp)
		return 0;

	delta_us = (now - *tsp) / 1000;
	*tsp = 0;

	if (delta_us >= min_us)
		submit_event(ctx, SOFTIRQ_ENTRY, vec, cpu, delta_us);

	return 0;
}

/* ── tp_btf variants (preferred when kernel BTF is available) ── */

SEC("tp_btf/softirq_raise")
int BPF_PROG(softirq_raise_btf, unsigned int vec_nr)
{
	return handle_raise(ctx, vec_nr);
}

SEC("tp_btf/softirq_entry")
int BPF_PROG(softirq_entry_btf, unsigned int vec_nr)
{
	return handle_entry(ctx, vec_nr);
}

SEC("tp_btf/softirq_exit")
int BPF_PROG(softirq_exit_btf, unsigned int vec_nr)
{
	return handle_exit(ctx, vec_nr);
}

/* ── raw_tp fallback variants ── */

SEC("raw_tp/softirq_raise")
int BPF_PROG(softirq_raise_raw, unsigned int vec_nr)
{
	return handle_raise(ctx, vec_nr);
}

SEC("raw_tp/softirq_entry")
int BPF_PROG(softirq_entry_raw, unsigned int vec_nr)
{
	return handle_entry(ctx, vec_nr);
}

SEC("raw_tp/softirq_exit")
int BPF_PROG(softirq_exit_raw, unsigned int vec_nr)
{
	return handle_exit(ctx, vec_nr);
}

char LICENSE[] SEC("license") = "GPL";
