// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2023 Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>
//
// Base on ttysnoop.py 2016 Brendan Gregg.
//
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "ttysnoop.h"
#include "compat.bpf.h"
#include "core_fixes.bpf.h"

#define WRITE		1
#define ITER_UBUF	6

const volatile int user_data_count = 16;
const volatile int pts_inode = -1;

static int
do_tty_write(void *ctx, const struct file *file, const char *buf, size_t count)
{
	if (BPF_CORE_READ(file, f_inode, i_ino) != pts_inode)
		return 0;

	if (count < 0)
		return 0;

	for (int i = 0; i < user_data_count && count; i++) {
		struct event *event = reserve_buf(sizeof(*event));

		if (!event)
			break;

		 /**
		  * bpf_probe_read_user() can only use a fixed size, so truncate
		  * to count in user space
		  */
		if (bpf_probe_read_user(&event->buf, BUFSIZE, (void *)buf)) {
			discard_buf(event);
			break;
		}

		if (count > BUFSIZE) {
			event->buf[BUFSIZE] = 0;
			event->count = BUFSIZE;
		} else {
			event->buf[count] = 0;
			event->count = count;
		}

		submit_buf(ctx, event, sizeof(*event));

		if (count < BUFSIZE)
			break;

		count -= BUFSIZE;
		buf += BUFSIZE;
	}

	return 0;
}

/*
 * commit 9bb48c82aced (v5.11-rc4) tty: implement write_iter
 * hanged arguments of tty_write function
 */
SEC("kprobe/tty_write")
int BPF_KPROBE(kprobe__tty_write_old)
{
	size_t count;
	const char *buf;
	const struct file *file;

	file = (struct file *)PT_REGS_PARM1_CORE(ctx);
	buf = (const char *)PT_REGS_PARM2_CORE(ctx);
	count = (size_t)PT_REGS_PARM3_CORE(ctx);

	return do_tty_write(ctx, file, buf, count);
}

SEC("kprobe/tty_write")
int BPF_KPROBE(kprobe__tty_write_new)
{
	size_t count;
	const char *buf;
	const struct file *file;
	struct kiocb *iocb = (struct kiocb *)PT_REGS_PARM1_CORE(ctx);
	struct iov_iter *from = (struct iov_iter *)PT_REGS_PARM2_CORE(ctx);

	file = BPF_CORE_READ(iocb, ki_filp);

	/* commit 8cd54c1c8480 ("iov_iter: separate direction from flavour")
	 * Instead of having them mixed in iter->type, use separate ->iter_type
	 * and ->data_source (u8 and bool resp.)
	 */
	if (iov_iter_has_iter_type()) {
		if (BPF_CORE_READ(from, iter_type) != ITER_IOVEC &&
		    BPF_CORE_READ(from, iter_type) != ITER_UBUF)
			return 0;
		if (BPF_CORE_READ(from, data_source) != WRITE)
			return 0;

		switch (BPF_CORE_READ(from, iter_type)) {
		case ITER_IOVEC:
			buf = BPF_CORE_READ(from, kvec, iov_base);
			count = BPF_CORE_READ(from, kvec, iov_len);
			break;
		/* commit fcb14cb1bdac ("new iov_iter flavour - ITER_UBUF")
		 * implement new iov_iter flavour ITER_UBUF
		 */
		case ITER_UBUF:
			buf = BPF_CORE_READ((struct iov_iter___x *)from, ubuf);
			count = BPF_CORE_READ(from, count);
			break;
		default:
			return 0;
		}
	} else {
		if (BPF_CORE_READ((struct iov_iter___o *)from, type) !=
		    (ITER_IOVEC + WRITE))
			return 0;

		buf = BPF_CORE_READ(from, kvec, iov_base);
		count = BPF_CORE_READ(from, kvec, iov_len);
	}

	return do_tty_write(ctx, file, buf, count);
}

char LICENSE[] SEC("license") = "GPL";
