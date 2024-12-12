/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2022 Rong Tao */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "slabratetop.h"

#define MAX_ENTRIES	10240

const volatile pid_t target_pid = 0;

static struct slabrate_info slab_zero_value = {};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, char *);
	__type(value, struct slabrate_info);
} slab_entries SEC(".maps");

static int probe_entry(struct kmem_cache *cachep)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	struct slabrate_info *valuep;
	const char *name = BPF_CORE_READ(cachep, name);

	if (target_pid && target_pid != pid)
		return 0;

	valuep = bpf_map_lookup_elem(&slab_entries, &name);
	if (!valuep) {
		bpf_map_update_elem(&slab_entries, &name, &slab_zero_value, BPF_ANY);
		valuep = bpf_map_lookup_elem(&slab_entries, &name);
		if (!valuep)
			return 0;
		bpf_probe_read_kernel(&valuep->name, sizeof(valuep->name), name);
	}

	valuep->count++;
	valuep->size += BPF_CORE_READ(cachep, size);

	return 0;
}

SEC("kprobe/kmem_cache_alloc")
int BPF_KPROBE(kmem_cache_alloc, struct kmem_cache *cachep)
{
	return probe_entry(cachep);
}

SEC("kprobe/kmem_cache_alloc_noprof")
int BPF_KPROBE(kmem_cache_alloc_noprof, struct kmem_cache *cachep)
{
       return probe_entry(cachep);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
