/*
 * bitehist.c	Block I/O size histogram.
 *		For Linux, uses BCC, eBPF. See .py file.
 *
 * Based on eBPF sample tracex2 by Alexi Starovoitov.
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

static unsigned int log2(unsigned int v)
{
	unsigned int r;
	unsigned int shift;

	r = (v > 0xFFFF) << 4; v >>= r;
	shift = (v > 0xFF) << 3; v >>= shift; r |= shift;
	shift = (v > 0xF) << 2; v >>= shift; r |= shift;
	shift = (v > 0x3) << 1; v >>= shift; r |= shift;
	r |= (v >> 1);
	return r;
}

static unsigned int log2l(unsigned long v)
{
	unsigned int hi = v >> 32;
	if (hi)
		return log2(hi) + 32 + 1;
	else
		return log2(v) + 1;
}

int do_request(struct pt_regs *ctx, struct request *req)
{
	int index = log2l(req->__data_len / 1024);
	u64 *leaf = dist.lookup(&index);
	if (leaf) (*leaf)++;

	return 0;
}
