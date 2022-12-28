#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "memleak.h"

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024);
} rb SEC(".maps");

SEC("tracepoint/kmem/kmalloc")
int tracepoint__kmalloc(struct trace_kmalloc *ctx)
{
	return 1;
}

SEC("tracepoint/kmem/kfree")
int tracepoint__kfree(struct trace_kmalloc *ctx)
{
	return 1;
}
