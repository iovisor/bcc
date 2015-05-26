#include <linux/ptrace.h>
#include "../../src/cc/bpf_helpers.h"
struct Ptr { u64 ptr; };
struct Counters { u64 stat1; };
BPF_TABLE("hash", struct Ptr, struct Counters, stats, 1024);

BPF_EXPORT(count_sched)
int count_sched(struct pt_regs *ctx) {
  struct Ptr key = {.ptr=ctx->bx};
#if 1
  stats.data[(u64)&key].stat1++;
#else
  struct Counters zleaf = {0};
  stats.upsert(&key, &zleaf)->stat1++;
#endif
  return 0;
}
