// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")
struct Ptr {
  u64 ptr:64;
};
struct Counters {
  u64 stat1:64;
  u64 stat2:64;
};
Table<Ptr, Counters, FIXED_MATCH, AUTO> stats(1024);

// example with on_valid syntax
u32 sys_wr (struct proto::pt_regs *ctx) {
  struct Ptr key = {.ptr=ctx->di};
  struct Counters *leaf;
  leaf = stats[key];
  if leaf {
    atomic_add(leaf->stat2, 1);
  }
  log("sys_wr: %p\n", ctx->di);
  return 0;
}

// example with smallest available syntax
// note: if stats[key] fails, program returns early
u32 sys_rd (struct proto::pt_regs *ctx) {
  struct Ptr key = {.ptr=ctx->di};
  atomic_add(stats[key].stat1, 1);
}

// example with if/else case
u32 sys_bpf (struct proto::pt_regs *ctx) {
  struct Ptr key = {.ptr=ctx->di};
  struct Counters *leaf;
  leaf = stats[key];
  if leaf {
    atomic_add(leaf->stat1, 1);
  } else {
    log("update %llx failed\n", ctx->di);
  }
  return 0;
}

