// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")
#include <linux/ptrace.h>
struct Ptr { u64 ptr; };
struct Counters { u64 stat1; };
BPF_TABLE("hash", struct Ptr, struct Counters, stats, 1024);

int count_sched(struct pt_regs *ctx) {
  struct Ptr key = {.ptr = ctx->PT_REGS_PARM1};
  struct Counters zleaf = {0};
  stats.lookup_or_init(&key, &zleaf)->stat1++;
  return 0;
}
