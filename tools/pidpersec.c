/*
 * pidpersec.c	Count new processes (via fork).
 *		For Linux, uses BCC, eBPF. See the Python front-end.
 *
 * USAGE: pidpersec.py
 *
 * Copyright (c) 2015 Brendan Gregg.
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * 11-Aug-2015	Brendan Gregg	Created this.
 */

#include <uapi/linux/ptrace.h>

enum stat_types {
	S_COUNT = 1,
	S_MAXSTAT
};

BPF_TABLE("array", int, u64, stats, S_MAXSTAT + 1);

void stats_increment(int key) {
	u64 *leaf = stats.lookup(&key);
	if (leaf) (*leaf)++;
}

void do_count(struct pt_regs *ctx) { stats_increment(S_COUNT); }
