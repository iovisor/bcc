// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")
#include <linux/ptrace.h>
struct Ptr { u64 ptr; };
struct Counters { u64 stat1; };
BPF_HASH(stats, struct Ptr, struct Counters, 1024);

int count_sched(struct pt_regs *ctx) {
  struct Ptr key = {.ptr = PT_REGS_PARM1(ctx)};
  struct Counters zleaf = {0};
  struct Counters *val = stats.lookup_or_try_init(&key, &zleaf);
  if (val) {
    val->stat1++;
  }
  return 0;
}
