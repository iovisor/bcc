/*
 * bitehist.c	Block I/O size histogram.
 *		For Linux, uses BCC, eBPF. See .py file.
 *
 * Copyright (c) 2013-2015 PLUMgrid, http://plumgrid.com
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * 15-Aug-2015	Brendan Gregg	Created this.
 */

#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

BPF_TABLE("array", int, u64, dist, 64);

int kprobe__blk_account_io_completion(struct pt_regs *ctx, struct request *req)
{
	int index = bpf_log2l(req->__data_len / 1024);
	u64 *leaf = dist.lookup(&index);
	if (leaf) (*leaf)++;

	return 0;
}
