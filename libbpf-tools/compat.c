// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */

#include "compat.h"
#include "trace_helpers.h"
#include <stdlib.h>
#include <errno.h>
#include <bpf/libbpf.h>

#define PERF_BUFFER_PAGES	64

struct bpf_buffer {
	struct bpf_map *events;
	void *inner;
	bpf_buffer_sample_fn fn;
	void *ctx;
	int type;
};

static void perfbuf_sample_fn(void *ctx, int cpu, void *data, __u32 size)
{
	struct bpf_buffer *buffer = ctx;
	bpf_buffer_sample_fn fn;

	fn = buffer->fn;
	if (!fn)
		return;

	(void)fn(buffer->ctx, data, size);
}

struct bpf_buffer *bpf_buffer__new(struct bpf_map *events, struct bpf_map *heap)
{
	struct bpf_buffer *buffer;
	bool use_ringbuf;
	int type;

	use_ringbuf = probe_ringbuf();
	if (use_ringbuf) {
		bpf_map__set_autocreate(heap, false);
		type = BPF_MAP_TYPE_RINGBUF;
	} else {
		bpf_map__set_type(events, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
		bpf_map__set_key_size(events, sizeof(int));
		bpf_map__set_value_size(events, sizeof(int));
		type = BPF_MAP_TYPE_PERF_EVENT_ARRAY;
	}

	buffer = calloc(1, sizeof(*buffer));
	if (!buffer) {
		errno = ENOMEM;
		return NULL;
	}

	buffer->events = events;
	buffer->type = type;
	return buffer;
}

int bpf_buffer__open(struct bpf_buffer *buffer, bpf_buffer_sample_fn sample_cb,
		     bpf_buffer_lost_fn lost_cb, void *ctx)
{
	int fd, type;
	void *inner;

	fd = bpf_map__fd(buffer->events);
	type = buffer->type;

	switch (type) {
	case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
		buffer->fn = sample_cb;
		buffer->ctx = ctx;
		inner = perf_buffer__new(fd, PERF_BUFFER_PAGES, perfbuf_sample_fn, lost_cb, buffer, NULL);
		break;
	case BPF_MAP_TYPE_RINGBUF:
		inner = ring_buffer__new(fd, sample_cb, ctx, NULL);
		break;
	default:
		return 0;
	}

	if (!inner)
		return -errno;

	buffer->inner = inner;
	return 0;
}

int bpf_buffer__poll(struct bpf_buffer *buffer, int timeout_ms)
{
	switch (buffer->type) {
	case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
		return perf_buffer__poll(buffer->inner, timeout_ms);
	case BPF_MAP_TYPE_RINGBUF:
		return ring_buffer__poll(buffer->inner, timeout_ms);
	default:
		return -EINVAL;
	}
}

void bpf_buffer__free(struct bpf_buffer *buffer)
{
	if (!buffer)
		return;

	switch (buffer->type) {
	case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
		perf_buffer__free(buffer->inner);
		break;
	case BPF_MAP_TYPE_RINGBUF:
		ring_buffer__free(buffer->inner);
		break;
	}
	free(buffer);
}
