/*
 * RecordMySQLQuery Record MySQL queries by probing the alloc_query() function
 *                  in mysqld. For Linux, uses BCC, eBPF. Embedded C.
 *
 * Basic example of BCC and uprobes.
 *
 * Copyright (c) Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 */

#include <unistd.h>
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <string>

#include "BPF.h"

const std::string BPF_PROGRAM = R"(
#include <linux/ptrace.h>

struct query_probe_t {
  uint64_t ts;
  pid_t pid;
  char query[100];
};

BPF_HASH(queries, struct query_probe_t, int);

int probe_mysql_query(struct pt_regs *ctx, void* thd, char* query, size_t len) {
  if (query) {
    struct query_probe_t key = {};

    key.ts = bpf_ktime_get_ns();
    key.pid = bpf_get_current_pid_tgid();

    bpf_probe_read_str(&key.query, sizeof(key.query), query);

    int one = 1;
    queries.update(&key, &one);
  }
  return 0;
}
)";
const std::string ALLOC_QUERY_FUNC = "_Z11alloc_queryP3THDPKcj";

// Define the same struct to use in user space.
struct query_probe_t {
  uint64_t ts;
  pid_t pid;
  char query[100];
};

int main(int argc, char** argv) {
  if (argc < 2) {
    std::cout << "USAGE: RecordMySQLQuery PATH_TO_MYSQLD [duration]"
              << std::endl;
    exit(1);
  }

  std::string mysql_path(argv[1]);
  std::cout << "Using mysqld path: " << mysql_path << std::endl;

  ebpf::BPF bpf;
  auto init_res = bpf.init(BPF_PROGRAM);
  if (init_res.code() != 0) {
    std::cerr << init_res.msg() << std::endl;
    return 1;
  }

  auto attach_res =
      bpf.attach_uprobe(mysql_path, ALLOC_QUERY_FUNC, "probe_mysql_query");
  if (attach_res.code() != 0) {
    std::cerr << attach_res.msg() << std::endl;
    return 1;
  }

  int probe_time = 10;
  if (argc >= 3)
    probe_time = atoi(argv[2]);
  std::cout << "Probing for " << probe_time << " seconds" << std::endl;
  sleep(probe_time);

  auto table_handle = bpf.get_hash_table<query_probe_t, int>("queries");
  auto table = table_handle.get_table_offline();
  std::sort(
      table.begin(), table.end(),
      [](std::pair<query_probe_t, int> a, std::pair<query_probe_t, int> b) {
        return a.first.ts < b.first.ts;
      });
  std::cout << table.size() << " queries recorded:" << std::endl;
  for (auto it : table) {
    std::cout << "Time: " << it.first.ts << " PID: " << it.first.pid
              << " Query: " << it.first.query << std::endl;
  }

  auto detach_res = bpf.detach_uprobe(mysql_path, ALLOC_QUERY_FUNC);
  if (detach_res.code() != 0) {
    std::cerr << detach_res.msg() << std::endl;
    return 1;
  }

  return 0;
}
