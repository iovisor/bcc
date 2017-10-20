// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")
#include <linux/ptrace.h>
#include <linux/blkdev.h>
struct Request { u64 rq; };
struct Time { u64 start; };
BPF_HASH(requests, struct Request, struct Time, 1024);
#define SLOTS 100
BPF_ARRAY(latency, u64, SLOTS);

static u32 log2(u32 v) {
  u32 r, shift;

  r = (v > 0xFFFF) << 4; v >>= r;
  shift = (v > 0xFF) << 3; v >>= shift; r |= shift;
  shift = (v > 0xF) << 2; v >>= shift; r |= shift;
  shift = (v > 0x3) << 1; v >>= shift; r |= shift;
  r |= (v >> 1);
  return r;
}

static u32 log2l(u64 v) {
  u32 hi = v >> 32;
  if (hi)
    return log2(hi) + 32;
  else
    return log2(v);
}

int probe_blk_start_request(struct pt_regs *ctx) {
  struct Request rq = {.rq = PT_REGS_PARM1(ctx)};
  struct Time tm = {.start = bpf_ktime_get_ns()};
  requests.update(&rq, &tm);
  return 0;
}

int probe_blk_update_request(struct pt_regs *ctx) {
  struct Request rq = {.rq = PT_REGS_PARM1(ctx)};
  struct Time *tm = requests.lookup(&rq);
  if (!tm) return 0;
  u64 delta = bpf_ktime_get_ns() - tm->start;
  requests.delete(&rq);
  u64 lg = log2l(delta);
  u64 base = 1ull << lg;
  u32 index = (lg * 64 + (delta - base) * 64 / base) * 3 / 64;
  if (index >= SLOTS)
    index = SLOTS - 1;

  u64 zero = 0;
  u64 *val = latency.lookup_or_init(&index, &zero);
  lock_xadd(val, 1);
  return 0;
}
