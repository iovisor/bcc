/*
 * Copyright (c) Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * Usage:
 *   ./KFunc
 * A sample output:
 *   Started tracing, hit Ctrl-C to terminate.
 *      FD  FNAME
 *    NONE  /proc/stat
 *      87  /proc/stat
 *    NONE  /proc/8208/status
 *      36  /proc/8208/status
 *    NONE  /proc/8208/status
 *      36  /proc/8208/status
 *    ...
 *
 * KFunc support is only available at kernel version 5.5 and later.
 * This example only works for x64.
 */

#include <fstream>
#include <iostream>
#include <iomanip>
#include <string>

#include "bcc_version.h"
#include "BPF.h"

const std::string BPF_PROGRAM = R"(
#include <linux/ptrace.h>

struct info_t {
  char name[64];
  int fd;
  int is_ret;
};
BPF_PERF_OUTPUT(events);

KFUNC_PROBE(__x64_sys_openat, struct pt_regs *regs)
{
  const char __user *filename = (char *)PT_REGS_PARM2(regs);
  struct info_t info = {};

  bpf_probe_read_user_str(info.name, sizeof(info.name), filename);
  info.is_ret = 0;
  events.perf_submit(ctx, &info, sizeof(info));
  return 0;
}

KRETFUNC_PROBE(__x64_sys_openat, struct pt_regs *regs, int ret)
{
  const char __user *filename = (char *)PT_REGS_PARM2(regs);
  struct info_t info = {};

  bpf_probe_read_user_str(info.name, sizeof(info.name), filename);
  info.fd = ret;
  info.is_ret = 1;
  events.perf_submit(ctx, &info, sizeof(info));
  return 0;
}
)";

struct info_t {
  char name[64];
  int fd;
  int is_ret;
};

void handle_output(void *cb_cookie, void *data, int data_size) {
  auto info = static_cast<info_t *>(data);
  if (info->is_ret)
    std::cout << std::setw(5) << info->fd << "  " << info->name << std::endl;
  else
    std::cout << " NONE  " << info->name << std::endl;
}

int main() {
  ebpf::BPF bpf;
  auto res = bpf.init(BPF_PROGRAM);
  if (res.code() != 0) {
    std::cerr << res.msg() << std::endl;
    return 1;
  }

  int prog_fd;
  res = bpf.load_func("kfunc____x64_sys_openat", BPF_PROG_TYPE_TRACING, prog_fd);
  if (res.code() != 0) {
    std::cerr << res.msg() << std::endl;
    return 1;
  }

  int ret = bpf_attach_kfunc(prog_fd);
  if (ret < 0) {
    std::cerr << "bpf_attach_kfunc failed: " << ret << std::endl;
    return 1;
  }

  res = bpf.load_func("kretfunc____x64_sys_openat", BPF_PROG_TYPE_TRACING, prog_fd);
  if (res.code() != 0) {
    std::cerr << res.msg() << std::endl;
    return 1;
  }

  ret = bpf_attach_kfunc(prog_fd);
  if (ret < 0) {
    std::cerr << "bpf_attach_kfunc failed: " << ret << std::endl;
    return 1;
  }

  auto open_res = bpf.open_perf_buffer("events", &handle_output);
  if (open_res.code() != 0) {
    std::cerr << open_res.msg() << std::endl;
    return 1;
  }

  std::cout << "Started tracing, hit Ctrl-C to terminate." << std::endl;
  std::cout << "   FD  FNAME" << std::endl;
  auto perf_buffer = bpf.get_perf_buffer("events");
  if (perf_buffer) {
    while (true)
      // 100ms timeout
      perf_buffer->poll(100);
  }

  return 0;
}
