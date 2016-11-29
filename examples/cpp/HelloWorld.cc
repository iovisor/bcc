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
  if (std::get<0>(init_res) != 0) {
    std::cerr << std::get<1>(init_res) << std::endl;
    return 1;
  }

  std::ifstream pipe("/sys/kernel/debug/tracing/trace_pipe");
  std::string line;

  auto attach_res = bpf.attach_kprobe("sys_clone", "on_sys_clone");
  if (std::get<0>(attach_res) != 0) {
    std::cerr << std::get<1>(attach_res) << std::endl;
    return 1;
  }

  while (true) {
    if (std::getline(pipe, line)) {
      std::cout << line << std::endl;
      // Detach the probe if we got at least one line.
      auto detach_res = bpf.detach_kprobe("sys_clone");
      if (std::get<0>(detach_res) != 0) {
        std::cerr << std::get<1>(detach_res) << std::endl;
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
