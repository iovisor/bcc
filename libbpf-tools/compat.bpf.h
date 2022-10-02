// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */

#ifndef __COMPAT_BPF_H
#define __COMPAT_BPF_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define MAX_EVENT_SIZE		10240
#define RINGBUF_SIZE		(1024 * 256)

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, MAX_EVENT_SIZE);
} heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_SIZE);
} events SEC(".maps");

static __always_inline void *reserve_buf(__u64 size)
{
	static const int zero = 0;

	if (bpf_core_type_exists(struct bpf_ringbuf))
		return bpf_ringbuf_reserve(&events, size, 0);

	return bpf_map_lookup_elem(&heap, &zero);
}

static __always_inline long submit_buf(void *ctx, void *buf, __u64 size)
{
	if (bpf_core_type_exists(struct bpf_ringbuf)) {
		bpf_ringbuf_submit(buf, 0);
		return 0;
	}

	return bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, buf, size);
}

#endif /* __COMPAT_BPF_H */
