/* Copyright (c) 2019 Brendan Gregg. */
/* Licensed under the Apache License, Version 2.0 (the "License"). */
/* This was originally created for the BPF Performance Tools book */
/* published by Addison Wesley. ISBN-13: 9780136554820 */
/* When copying or porting, include this comment. */

/* 03-Jul-2019   Brendan Gregg   Ported from bpftrace to BCC. */
/* 06-Apr-2023   Ben Olson       Ported from BCC to libbpf */


#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "swapin.h"
#include "bits.bpf.h"
#include "maps.bpf.h"

#define MAX_ENTRIES 10240

const volatile pid_t target_pid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct key_t);
	__type(value, u64);
} counts SEC(".maps");

SEC("kprobe/swap_readpage")
int BPF_KPROBE(swap_readpage) {
	u64 *valp, zero = 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;

	if (target_pid && target_pid != pid) {
		return 0;
	}

	struct key_t key = {.pid = pid};
	bpf_get_current_comm(&key.comm, sizeof(key.comm));
	valp = bpf_map_lookup_or_try_init(&counts, &key, &zero);
	if (valp) {
		__sync_fetch_and_add(valp, 1);
	}
	return 0;
}
