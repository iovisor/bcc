/*
 * Copyright (c) Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 */

#include <unistd.h>
#include <fstream>
#include <iostream>
#include <string>

#include "BPF.h"

const std::string BPF_PROGRAM = R"(
int on_sys_clone(void *ctx) {
  bpf_trace_printk("Hello, World! Here I did a sys_clone call!\n");
  return 0;
}
)";

int main() {
  ebpf::BPF bpf;
  auto init_res = bpf.init(BPF_PROGRAM);
  if (init_res.code() != 0) {
    std::cerr << init_res.msg() << std::endl;
    return 1;
  }

  std::ifstream pipe("/sys/kernel/debug/tracing/trace_pipe");
  std::string line;
  std::string clone_fnname = bpf.get_syscall_fnname("clone");

  auto attach_res = bpf.attach_kprobe(clone_fnname, "on_sys_clone");
  if (attach_res.code() != 0) {
    std::cerr << attach_res.msg() << std::endl;
    return 1;
  }

  while (true) {
    if (std::getline(pipe, line)) {
      std::cout << line << std::endl;
      // Detach the probe if we got at least one line.
      auto detach_res = bpf.detach_kprobe(clone_fnname);
      if (detach_res.code() != 0) {
        std::cerr << detach_res.msg() << std::endl;
        return 1;
      }
      break;
    } else {
      std::cout << "Waiting for a sys_clone event" << std::endl;
      sleep(1);
    }
  }

  return 0;
}
