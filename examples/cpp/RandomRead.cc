/*
 * RandomRead Monitor random number read events.
 *            For Linux, uses BCC, eBPF. Embedded C.
 *
 * Basic example of BCC Tracepoint and perf buffer.
 *
 * USAGE: RandomRead
 *
 * Copyright (c) Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 */

#include <signal.h>
#include <sys/resource.h>
#include <iostream>

#include "BPF.h"

const std::string BPF_PROGRAM = R"(
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

#ifndef CGROUP_FILTER
#define CGROUP_FILTER 0
#endif

struct event_t {
  int pid;
  char comm[16];
  int cpu;
  int got_bits;
};

BPF_PERF_OUTPUT(events);
BPF_CGROUP_ARRAY(cgroup, 1);

int on_urandom_read(struct bpf_raw_tracepoint_args *ctx) {
  if (CGROUP_FILTER && (cgroup.check_current_task(0) != 1))
    return 0;

  struct event_t event = {};
  event.pid = bpf_get_current_pid_tgid();
  bpf_get_current_comm(&event.comm, sizeof(event.comm));
  event.cpu = bpf_get_smp_processor_id();
  // from include/trace/events/random.h:
  //    TP_PROTO(int got_bits, int pool_left, int input_left)
  event.got_bits = ctx->args[0];

  events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}
)";

// Define the same struct to use in user space.
struct event_t {
  int pid;
  char comm[16];
  int cpu;
  int got_bits;
};

void handle_output(void* cb_cookie, void* data, int data_size) {
  auto event = static_cast<event_t*>(data);
  std::cout << "PID: " << event->pid << " (" << event->comm << ") on CPU "
            << event->cpu << " read " << event->got_bits << " bits"
            << std::endl;
}

ebpf::BPF* bpf;

void signal_handler(int s) {
  std::cerr << "Terminating..." << std::endl;
  delete bpf;
  exit(0);
}

void usage(void) {
  std::cerr << "USAGE: RandomRead [{-r|-u} [cgroup2_path]]" << std::endl;
}

int main(int argc, char** argv) {
  if (argc > 3) {
    usage();
    return 1;
  }

  bool allow_rlimit = true;
  if (argc >= 2) {
    // Set a small rlimit for MEMLOCK
    struct rlimit rlim_new = {4096, 4096};
    setrlimit(RLIMIT_MEMLOCK, &rlim_new);

    if (strcmp(argv[1], "-r") == 0) {
      allow_rlimit = false;
    } else if (strcmp(argv[1], "-u") == 0) {
      allow_rlimit = true;
    } else {
      usage();
      return 1;
    }
  }

  std::vector<std::string> cflags = {};
  if (argc == 3)
    cflags.emplace_back("-DCGROUP_FILTER=1");

  bpf = new ebpf::BPF(0, nullptr, true, "", allow_rlimit);
  auto init_res = bpf->init(BPF_PROGRAM, cflags, {});
  if (init_res.code() != 0) {
    std::cerr << init_res.msg() << std::endl;
    return 1;
  }
  if (argc == 3) {
    auto cgroup_array = bpf->get_cgroup_array("cgroup");
    auto update_res = cgroup_array.update_value(0, argv[2]);
    if (update_res.code() != 0) {
      std::cerr << update_res.msg() << std::endl;
      return 1;
    }
  }

  auto attach_res =
      bpf->attach_raw_tracepoint("urandom_read", "on_urandom_read");
  if (attach_res.code() != 0) {
    std::cerr << attach_res.msg() << std::endl;
    return 1;
  }

  auto open_res = bpf->open_perf_buffer("events", &handle_output);
  if (open_res.code() != 0) {
    std::cerr << open_res.msg() << std::endl;
    return 1;
  }

  // done with all initial work, free bcc memory
  if (bpf->free_bcc_memory()) {
    std::cerr << "Failed to free llvm/clang memory" << std::endl;
    return 1;
  }

  signal(SIGINT, signal_handler);
  std::cout << "Started tracing, hit Ctrl-C to terminate." << std::endl;
  while (true)
    bpf->poll_perf_buffer("events");

  return 0;
}
