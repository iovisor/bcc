/*
 * FollyRequestContextSwitch Monitor RequestContext switch events for any binary
 *                           uses the class from [folly](http://bit.ly/2h6S1yx).
 *                           For Linux, uses BCC, eBPF. Embedded C.
 *
 * Basic example of using USDT with BCC.
 *
 * USAGE: FollyRequestContextSwitch PATH_TO_BINARY
 *
 * Copyright (c) Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 */

#include <signal.h>
#include <iostream>
#include <vector>

#include "BPF.h"

const std::string BPF_PROGRAM = R"(
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

struct event_t {
  int pid;
  char name[16];
  uint64_t old_addr;
  uint64_t new_addr;
};

BPF_PERF_OUTPUT(events);

int on_context_switch(struct pt_regs *ctx) {
  struct event_t event = {};

  event.pid = bpf_get_current_pid_tgid();
  bpf_get_current_comm(&event.name, sizeof(event.name));

  bpf_usdt_readarg(1, ctx, &event.old_addr);
  bpf_usdt_readarg(2, ctx, &event.new_addr);

  events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}
)";

// Define the same struct to use in user space.
struct event_t {
  int pid;
  char name[16];
  uint64_t old_addr;
  uint64_t new_addr;
};

void handle_output(void* cb_cookie, void* data, int data_size) {
  auto event = static_cast<event_t*>(data);
  std::cout << "PID " << event->pid << " (" << event->name << ") ";
  std::cout << "folly::RequestContext switch from " << event->old_addr << " to "
            << event->new_addr << std::endl;
}

ebpf::BPF* bpf;

void signal_handler(int s) {
  std::cerr << "Terminating..." << std::endl;
  delete bpf;
  exit(0);
}

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cout << "USAGE: FollyRequestContextSwitch PATH_TO_BINARY" << std::endl;
    exit(1);
  }
  std::string binary_path(argv[1]);

  bpf = new ebpf::BPF();
  std::vector<ebpf::USDT> u;
  u.emplace_back(binary_path, "folly", "request_context_switch_before",
                 "on_context_switch");
  auto init_res = bpf->init(BPF_PROGRAM, {}, u);
  if (init_res.code() != 0) {
    std::cerr << init_res.msg() << std::endl;
    return 1;
  }

  auto attach_res = bpf->attach_usdt(u[0]);
  if (attach_res.code() != 0) {
    std::cerr << attach_res.msg() << std::endl;
    return 1;
  }

  auto open_res = bpf->open_perf_buffer("events", &handle_output);
  if (open_res.code() != 0) {
    std::cerr << open_res.msg() << std::endl;
    return 1;
  }

  signal(SIGINT, signal_handler);
  std::cout << "Started tracing, hit Ctrl-C to terminate." << std::endl;
  auto perf_buffer = bpf->get_perf_buffer("events");
  if (perf_buffer)
    while (true)
      // 100ms timeout
      perf_buffer->poll(100);

  return 0;
}
