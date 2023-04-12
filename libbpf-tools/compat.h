// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */

#ifndef __COMPAT_H
#define __COMPAT_H

#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>
#include <linux/bpf.h>

#define POLL_TIMEOUT_MS 100

struct bpf_buffer;
struct bpf_map;

typedef int (*bpf_buffer_sample_fn)(void *ctx, void *data, size_t size);
typedef void (*bpf_buffer_lost_fn)(void *ctx, int cpu, __u64 cnt);

struct bpf_buffer *bpf_buffer__new(struct bpf_map *events, struct bpf_map *heap);
int bpf_buffer__open(struct bpf_buffer *buffer, bpf_buffer_sample_fn sample_cb,
		     bpf_buffer_lost_fn lost_cb, void *ctx);
int bpf_buffer__poll(struct bpf_buffer *, int timeout_ms);
void bpf_buffer__free(struct bpf_buffer *);

/* taken from libbpf */
#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

static inline void *libbpf_reallocarray(void *ptr, size_t nmemb, size_t size)
{
	size_t total;

#if __has_builtin(__builtin_mul_overflow)
	if (__builtin_mul_overflow(nmemb, size, &total))
		return NULL;
#else
	if (size == 0 || nmemb > ULONG_MAX / size)
		return NULL;
	total = nmemb * size;
#endif
	return realloc(ptr, total);
}

#endif /* __COMPAT_H */
