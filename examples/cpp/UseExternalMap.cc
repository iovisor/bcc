/*
 * UseExternalMap shows how to access an external map through
 * C++ interface. The external map could be a pinned map.
 * This example simulates the pinned map through a locally
 * created map by calling libbpf bpf_create_map.
 *
 * Copyright (c) Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 */

#include <stdint.h>
#include <iostream>

#include "BPF.h"

// Used by C++ get hash_table
struct sched_switch_info {
  int prev_pid;
  int next_pid;
  char prev_comm[16];
  char next_comm[16];
};

#define CHECK(condition, msg)        \
  ({                                 \
    if (condition) {                 \
      std::cerr << msg << std::endl; \
      return 1;                      \
    }                                \
  })

const std::string BPF_PROGRAM = R"(
#include <linux/sched.h>

struct sched_switch_info {
  int prev_pid;
  int next_pid;
  char prev_comm[16];
  char next_comm[16];
};

BPF_TABLE("extern", u32, u32, control, 1);
BPF_HASH(counts, struct sched_switch_info, u32);
int on_sched_switch(struct tracepoint__sched__sched_switch *args) {
  struct sched_switch_info key = {};
  u32 zero = 0, *val;

  /* only do something when control is on */
  val = control.lookup(&zero);
  if (!val || *val == 0)
    return 0;

  /* record sched_switch info in counts table */
  key.prev_pid = args->prev_pid;
  key.next_pid = args->next_pid;
  __builtin_memcpy(&key.prev_comm, args->prev_comm, 16);
  __builtin_memcpy(&key.next_comm, args->next_comm, 16);
  val = counts.lookup_or_init(&key, &zero);
  (*val)++;

  return 0;
}
)";

static void print_counts(ebpf::BPF *bpfp, std::string msg) {
  auto counts_table_hdl =
      bpfp->get_hash_table<struct sched_switch_info, uint32_t>("counts");
  printf("%s\n", msg.c_str());
  printf("%-8s  %-16s      %-8s  %-16s   %-4s\n", "PREV_PID", "PREV_COMM",
         "CURR_PID", "CURR_COMM", "CNT");
  for (auto it : counts_table_hdl.get_table_offline()) {
    printf("%-8d (%-16s) ==> %-8d (%-16s): %-4d\n", it.first.prev_pid,
           it.first.prev_comm, it.first.next_pid, it.first.next_comm,
           it.second);
  }
}

int main() {
  int ctrl_map_fd;
  uint32_t val;

  // create a map through bpf_create_map, bcc knows nothing about this map.
  ctrl_map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, "control", sizeof(uint32_t),
                               sizeof(uint32_t), 1, 0);
  CHECK(ctrl_map_fd < 0, "bpf_create_map failure");

  // populate control map into TableStorage
  std::unique_ptr<ebpf::TableStorage> local_ts =
      ebpf::createSharedTableStorage();
  ebpf::Path global_path({"control"});
  ebpf::TableDesc table_desc("control", ebpf::FileDesc(ctrl_map_fd),
                             BPF_MAP_TYPE_ARRAY, sizeof(uint32_t),
                             sizeof(uint32_t), 1, 0);
  local_ts->Insert(global_path, std::move(table_desc));

  // constructor with the pre-populated table storage
  ebpf::BPF bpf(0, &*local_ts);
  auto res = bpf.init(BPF_PROGRAM);
  CHECK(res.code(), res.msg());

  // attach to the tracepoint sched:sched_switch
  res = bpf.attach_tracepoint("sched:sched_switch", "on_sched_switch");
  CHECK(res.code(), res.msg());

  // wait for some scheduling events
  sleep(1);

  auto control_table_hdl = bpf.get_array_table<uint32_t>("control");
  res = control_table_hdl.get_value(0, val);
  CHECK(res.code() || val != 0, res.msg());

  // we should not see any events here
  print_counts(&bpf, "events with control off:");

  printf("\n");

  // change the control to on so bpf program starts to count events
  val = 1;
  res = control_table_hdl.update_value(0, val);
  CHECK(res.code(), res.msg());

  // verify we get the control on back
  val = 0;
  res = control_table_hdl.get_value(0, val);
  CHECK(res.code() || val != 1, res.msg());

  // wait for some scheduling events
  sleep(1);

  // we should see a bunch of events here
  print_counts(&bpf, "events with control on:");

  return 0;
}
