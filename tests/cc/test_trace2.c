// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")
#include <linux/ptrace.h>
BPF_TABLE("hash", u64, u64, stats, 1024);

int count_sched(struct pt_regs *ctx) {
  (*stats.lookup_or_init(ctx->bx, 0))++;
  return 0;
}
