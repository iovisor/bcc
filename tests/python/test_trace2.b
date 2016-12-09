// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")
#include "kprobe.b"
struct Ptr { u64 ptr:64; };
struct Counters { u64 stat1:64; };
Table<Ptr, Counters, FIXED_MATCH, AUTO> stats(1024);

u32 count_sched (struct proto::pt_regs *ctx) {
  struct Ptr key = {.ptr=ctx->bx};
  atomic_add(stats[key].stat1, 1);
}
