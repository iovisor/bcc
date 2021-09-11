/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2021 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "ttysnoop.h"

#define WRITE			1
/**
 * starting from linux v5.14-rc1, ITER_IOVEC has value 0 instead of 4
 * see:
 *     https://github.com/torvalds/linux/commit/8cd54c1c8480
 *     https://github.com/torvalds/linux/blob/v5.14-rc1/include/linux/uio.h#L22
 */
#define ITER_IOVEC_v514		0

/**
 * starting from linux v5.14-rc1, struct iov_iter has new definition
 * define our own struct iov_iter since vmlinux.h is outdated
 * see:
 *     https://github.com/torvalds/linux/commit/8cd54c1c8480
 *     https://github.com/torvalds/linux/blob/v5.14-rc1/include/linux/uio.h#L30-L50
 */
struct iov_iter___v514 {
	__u8 iter_type;
	bool data_source;
	union {
		const struct kvec *kvec;
	};
};

static int zero = 0;
const volatile __u64 pts = 0;
const volatile int read_bytes = 256;
const volatile int read_count = 16;

extern __u32 LINUX_KERNEL_VERSION __kconfig;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct event);
} heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

static int probe_tty_write(void *ctx, const char *buf, size_t count)
{
	struct event *eventp;
	int i;

	eventp = bpf_map_lookup_elem(&heap, &zero);
	if (!eventp)
		return 0;

	for (i = 0; i < read_count; i++) {
		if (bpf_probe_read_user(eventp->buf, BUF_SIZE, buf))
			return 0;

		if (count < BUF_SIZE) {
			eventp->count = count;
		} else {
			eventp->count = BUF_SIZE - 1;
		}
		eventp->buf[eventp->count] = '\0';
		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, eventp, sizeof(*eventp));

		if (count < BUF_SIZE)
			return 0;

		count -= eventp->count;
		buf += eventp->count;
	}

	return 0;
};

static int probe_entry(void *ctx, struct file *file, const char *buf, size_t count)
{
	if (BPF_CORE_READ(file, f_inode, i_ino) != pts)
		return 0;

	return probe_tty_write(ctx, buf, count);
}

SEC("kprobe/tty_write")
int BPF_KPROBE(tty_write_entry, struct file *file, const char *buf, size_t count)
{
	return probe_entry(ctx, file, buf, count);
}

SEC("fentry/tty_write")
int BPF_PROG(tty_write_fentry)
{
	struct iov_iter___v514 *from_v514;
	struct iov_iter *from;
	struct kiocb *iocb;
	struct file * file;
	const char *buf;
	size_t count;

	/**
	 * commit 9bb48c82aced (v5.11-rc4) tty: implement write_iter
	 * changed arguments of tty_write function
	 */
	if (LINUX_KERNEL_VERSION < KERNEL_VERSION(5, 11, 0)) {
		file = (struct file *)ctx[0];
		buf = (const char *)ctx[1];
		count = (size_t)ctx[2];
		return probe_entry(ctx, file, buf, count);
	}

	iocb = (struct kiocb *)ctx[0];
	if (BPF_CORE_READ(iocb, ki_filp, f_inode, i_ino) != pts)
		return 0;

	/**
	 * commit 8cd54c1c8480 iov_iter: separate direction from flavour
	 * `type` is represented by iter_type and data_source seperately
	 */
	from_v514 = (struct iov_iter___v514 *)ctx[1];
	if (bpf_core_field_exists(from_v514->iter_type)) {
		if (BPF_CORE_READ(from_v514, iter_type) != ITER_IOVEC_v514)
			return 0;
		if (BPF_CORE_READ(from_v514, data_source) != WRITE)
			return 0;

		buf = BPF_CORE_READ(from_v514, kvec, iov_base);
		count = BPF_CORE_READ(from_v514, kvec, iov_len);
		return probe_tty_write(ctx, buf, count);
	}

	from = (struct iov_iter *)ctx[1];
	if (BPF_CORE_READ(from, type) != (ITER_IOVEC + WRITE))
		return 0;

	buf = BPF_CORE_READ(from, kvec, iov_base);
	count = BPF_CORE_READ(from, kvec, iov_len);
	return probe_tty_write(ctx, buf, count);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
