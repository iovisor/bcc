/*
 * CGroupTest Demonstrate how to use BPF cgroup API to collect file open event
 *
 * Basic example of cgroup and BPF kprobes.
 *
 * USAGE: CGroupTest cgroup2_path
 *
 * EXAMPLES:
 * 1. Create a directory under cgroup2 mountpoint:
 *    $ sudo mkdir /sys/fs/cgroup/unified/test
 * 2. Add current bash into the testing cgroup:
 *    $ sudo echo $$ | sudo tee -a /sys/fs/cgroup/unified/test/cgroup.procs
 * 3. Open another bash window, and start CGroupTest as:
 *    $ sudo ./examples/cpp/CGroupTest /sys/fs/cgroup/unified/test
 * 4. Run file open activity from previous bash window should be printed.
 *
 * Copyright (c) Jinshan Xiong
 * Licensed under the Apache License, Version 2.0 (the "License")
 */

#include <unistd.h>
#include <fstream>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string>

#include "BPF.h"

const std::string BPF_PROGRAM = R"(
#include <linux/sched.h>
#include <linux/path.h>
#include <linux/dcache.h>

BPF_CGROUP_ARRAY(cgroup, 1);

int on_vfs_open(struct pt_regs *ctx, struct path *path) {
  if (cgroup.check_current_task(0) > 0)
    bpf_trace_printk("file '%s' was opened!\n", path->dentry->d_name.name);
  return 0;
}
)";

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << argv[0] << ": requires _one_ cgroup path" << std::endl;
    return 1;
  }

  ebpf::BPF bpf;
  auto init_res = bpf.init(BPF_PROGRAM);
  if (init_res.code() != 0) {
    std::cerr << init_res.msg() << std::endl;
    return 1;
  }

  auto cgroup_array = bpf.get_cgroup_array("cgroup");
  auto update_res = cgroup_array.update_value(0, argv[1]);
  if (update_res.code() != 0) {
    std::cerr << update_res.msg() << std::endl;
    return 1;
  }

  auto attach_res =
      bpf.attach_kprobe("vfs_open", "on_vfs_open");
  if (attach_res.code() != 0) {
    std::cerr << attach_res.msg() << std::endl;
    return 1;
  }

  std::ifstream pipe("/sys/kernel/debug/tracing/trace_pipe");
  std::string line;

  std::cout << "Started tracing open event, hit Ctrl-C to terminate." << std::endl;
  while (std::getline(pipe, line))
    std::cout << line << std::endl;

  auto detach_res = bpf.detach_kprobe("vfs_open");
  if (detach_res.code() != 0) {
    std::cerr << detach_res.msg() << std::endl;
    return 1;
  }

  return 0;
}
