/*
 * disksnoop.c	Trace block device I/O: basic version of iosnoop.
 *		For Linux, uses BCC, eBPF. See .py file.
 *
 * Copyright (c) 2015 Brendan Gregg.
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * 11-Aug-2015	Brendan Gregg	Created this.
 */

#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

struct key_t {
	struct request *req;
};
BPF_HASH(start, struct key_t);

int do_request(struct pt_regs *ctx, struct request *req) {
	struct key_t key = {};
	u64 ts;

	// stash start timestamp by request ptr
	ts = bpf_ktime_get_ns();
	key.req = req;
	start.update(&key, &ts);

	return 0;
}

int do_completion(struct pt_regs *ctx, struct request *req) {
	struct key_t key = {};
	u64 *tsp, delta;

	key.req = req;
	tsp = start.lookup(&key);

	if (tsp != 0) {
		delta = bpf_ktime_get_ns() - *tsp;
		bpf_trace_printk("%d %x %d\n", req->__data_len,
		    req->cmd_flags, delta / 1000);
		start.delete(&key);
	}

	return 0;
}
