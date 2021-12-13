/*
 * Copyright (c) Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * Usage:
 *   ./TaskIterator
 *
 * BPF task iterator is available since linux 5.8.
 * This example shows how to dump all threads in the system with
 * bpf iterator. An example output likes below:
 *   tid     comm
 *   1       systemd
 *   2       kthreadd
 *   3       rcu_gp
 *   4       rcu_par_gp
 *   6       kworker/0:0H
 *   ...
 *   2613386 sleep
 *   2613474 GetCountersCPU6
 *   2613587 GetCountersCPU7
 *   2613621 CPUThreadPool69
 *   2613906 GetCountersCPU5
 *   2614140 GetCountersCPU2
 *   2614193 CfgrExtension56
 *   2614449 ruby-timer-thr
 *   2614529 chef-client
 *   2615122 systemd-hostnam
 *   ...
 *   2608477 sudo
 *   2608478 TaskIterator
 */

#include <unistd.h>
#include <fstream>
#include <iostream>
#include <string>

#include "bcc_version.h"
#include "BPF.h"

const std::string BPF_PROGRAM = R"(
#include <linux/bpf.h>
#include <linux/seq_file.h>
#include <linux/sched.h>

/* the structure is defined in .c file, so explicitly define
 * the structure here.
 */
struct bpf_iter__task {
  union {
    struct bpf_iter_meta *meta;
  };
  union {
    struct task_struct *task;
  };
};

struct info_t {
  int tid;
  char comm[TASK_COMM_LEN];
};

BPF_ITER(task) {
  struct seq_file *seq = ctx->meta->seq;
  struct task_struct *task = ctx->task;
  struct info_t info = {};

  if (task == (void *)0)
    return 0;

  info.tid = task->pid;
  __builtin_memcpy(&info.comm, task->comm, sizeof(info.comm));
  bpf_seq_write(seq, &info, sizeof(info));

  return 0;
}
)";

// linux/sched.h
#define TASK_COMM_LEN	16

struct info_t {
  int tid;
  char comm[TASK_COMM_LEN];
};

int main() {
  ebpf::BPF bpf;
  auto res = bpf.init(BPF_PROGRAM);
  if (!res.ok()) {
    std::cerr << res.msg() << std::endl;
    return 1;
  }

  int prog_fd;
  res = bpf.load_func("bpf_iter__task", BPF_PROG_TYPE_TRACING, prog_fd);
  if (!res.ok()) {
    std::cerr << res.msg() << std::endl;
    return 1;
  }

  int link_fd = bcc_iter_attach(prog_fd, NULL, 0);
  if (link_fd < 0) {
    std::cerr << "bcc_iter_attach failed: " << link_fd << std::endl;
    return 1;
  }

  int iter_fd = bcc_iter_create(link_fd);
  if (iter_fd < 0) {
    std::cerr << "bcc_iter_create failed: " << iter_fd << std::endl;
    close(link_fd);
    return 1;
  }

  // Header.
  printf("tid\tcomm\n");

  struct info_t info[20];
  int len, leftover = 0, info_size = 20 * sizeof(struct info_t);
  while ((len = read(iter_fd, (char *)info + leftover, info_size - leftover))) {
    if (len < 0) {
      if (len == -EAGAIN)
	continue;
      std::cerr << "read failed: " << len << std::endl;
      break;
    }

    int num_info = len / sizeof(struct info_t);
    for (int i = 0; i < num_info; i++) {
      printf("%d\t%s\n", info[i].tid, info[i].comm);
    }

    leftover = len % sizeof(struct info_t);
    if (num_info > 0)
      memcpy(info, (void *)&info[num_info], leftover);
  }

  close(iter_fd);
  close(link_fd);
  return 0;
}
