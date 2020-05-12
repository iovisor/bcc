// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Anton Protopopov
//
// Based on vfsstat(8) from BCC by Brendan Gregg
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "vfsstat.h"

__u64 stats[S_MAXSTAT] = {};

static __always_inline int inc_stats(int key)
{
	__atomic_add_fetch(&stats[key], 1, __ATOMIC_RELAXED);
	return 0;
}

SEC("kprobe/vfs_read")
int BPF_KPROBE(kprobe__vfs_read)
{
	return inc_stats(S_READ);
}

SEC("kprobe/vfs_write")
int BPF_KPROBE(kprobe__vfs_write)
{
	return inc_stats(S_WRITE);
}

SEC("kprobe/vfs_fsync")
int BPF_KPROBE(kprobe__vfs_fsync)
{
	return inc_stats(S_FSYNC);
}

SEC("kprobe/vfs_open")
int BPF_KPROBE(kprobe__vfs_open)
{
	return inc_stats(S_OPEN);
}

SEC("kprobe/vfs_create")
int BPF_KPROBE(kprobe__vfs_create)
{
	return inc_stats(S_CREATE);
}

char LICENSE[] SEC("license") = "GPL";
