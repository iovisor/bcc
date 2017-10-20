/*
 * LLCStat Show LLC hit ratio for each process on each CPU core.
 *         For Linux, uses BCC, eBPF. Embedded C.
 *
 * Basic example of BCC timed sampling perf event.
 *
 * USAGE: LLCStat [duration]
 *
 * Copyright (c) Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 */

#include <linux/perf_event.h>
#include <unistd.h>
#include <iomanip>
#include <iostream>
#include <string>

#include "BPF.h"

const std::string BPF_PROGRAM = R"(
#include <linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>

struct event_t {
    int cpu;
    int pid;
    char name[16];
};

BPF_HASH(ref_count, struct event_t);
BPF_HASH(miss_count, struct event_t);

static inline __attribute__((always_inline)) void get_key(struct event_t* key) {
    key->cpu = bpf_get_smp_processor_id();
    key->pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&(key->name), sizeof(key->name));
}

int on_cache_miss(struct bpf_perf_event_data *ctx) {
    struct event_t key = {};
    get_key(&key);

    u64 zero = 0, *val;
    val = miss_count.lookup_or_init(&key, &zero);
    (*val) += ctx->sample_period;

    return 0;
}

int on_cache_ref(struct bpf_perf_event_data *ctx) {
    struct event_t key = {};
    get_key(&key);

    u64 zero = 0, *val;
    val = ref_count.lookup_or_init(&key, &zero);
    (*val) += ctx->sample_period;

    return 0;
}
)";

struct event_t {
  int cpu;
  int pid;
  char name[16];
};

int main(int argc, char** argv) {
  ebpf::BPF bpf;
  auto init_res = bpf.init(BPF_PROGRAM);
  if (init_res.code() != 0) {
    std::cerr << init_res.msg() << std::endl;
    return 1;
  }

  auto attach_ref_res =
      bpf.attach_perf_event(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_REFERENCES,
                            "on_cache_ref", 100, 0);
  if (attach_ref_res.code() != 0) {
    std::cerr << attach_ref_res.msg() << std::endl;
    return 1;
  }
  auto attach_miss_res = bpf.attach_perf_event(
      PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES, "on_cache_miss", 100, 0);
  if (attach_miss_res.code() != 0) {
    std::cerr << attach_miss_res.msg() << std::endl;
    return 1;
  }

  int probe_time = 10;
  if (argc == 2) {
    probe_time = atoi(argv[1]);
  }
  std::cout << "Probing for " << probe_time << " seconds" << std::endl;
  sleep(probe_time);
  bpf.detach_perf_event(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_REFERENCES);
  bpf.detach_perf_event(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES);

  auto refs = bpf.get_hash_table<event_t, uint64_t>("ref_count");
  auto misses = bpf.get_hash_table<event_t, uint64_t>("miss_count");
  for (auto it : refs.get_table_offline()) {
    uint64_t hit;
    try {
      auto miss = misses[it.first];
      hit = miss <= it.second ? it.second - miss : 0;
    } catch (...) {
      hit = it.second;
    }
    double ratio = (double(hit) / double(it.second)) * 100.0;
    std::cout << "PID " << std::setw(8) << std::setfill(' ') << it.first.pid;
    std::cout << std::setw(20) << std::setfill(' ') << std::left
              << " (" + std::string(it.first.name) + ") " << std::right;
    std::cout << "on CPU " << std::setw(2) << std::setfill(' ') << it.first.cpu;
    std::cout << " Hit Rate " << std::setprecision(4) << ratio << "% ";
    std::cout << "(" << hit << "/" << it.second << ")" << std::endl;
  }
  return 0;
}
