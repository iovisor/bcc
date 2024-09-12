/*
 * Copyright (c) Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * Usage:
 *   $ ./KModRetExample
 *   opened file: /bin/true
 *   security_file_open() is called 1 times, expecting 1
 *
 * Kfunc modify_ret support is only available at kernel version 5.6 and later.
 * This example only works for x64. Currently, only the kernel functions can
 * be attached with BPF_MODIFY_RETURN:
 *   - Whitelisted for error injection by checking within_error_injection_list.
 *     Similar discussions happened for the bpf_override_return helper.
 *   - The LSM security hooks (kernel global function with prefix "security_").
 */

#include <fstream>
#include <iostream>
#include <iomanip>
#include <string>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "bcc_version.h"
#include "BPF.h"

const std::string BPF_PROGRAM = R"(
#include <linux/fs.h>
#include <asm/errno.h>

BPF_ARRAY(target_pid, u32, 1);
static bool match_target_pid()
{
  int key = 0, *val, tpid, cpid;

  val = target_pid.lookup(&key);
  if (!val)
    return false;

  tpid = *val;
  cpid = bpf_get_current_pid_tgid() >> 32;
  if (tpid == 0 || tpid != cpid)
     return false;
  return true;
}

struct fname_buf {
  char buf[16];
};
BPF_ARRAY(fname_table, struct fname_buf, 1);

KMOD_RET(__x64_sys_openat, struct pt_regs *regs, int ret)
{
  if (!match_target_pid())
    return 0;

  // openat syscall arguments:
  //   int dfd, const char __user * filename, int flags, umode_t mode
  char *filename = (char *)PT_REGS_PARM2_SYSCALL(regs);

  int key = 0;
  struct fname_buf *val;
  val = fname_table.lookup(&key);
  if (!val)
    return false;

  if (bpf_copy_from_user(val, sizeof(*val), filename) < 0)
    return 0;

  /* match target_pid, return -EINVAL. */
  return -EINVAL;
}

BPF_ARRAY(count, u32, 1);
KMOD_RET(security_file_open, struct file *file, int ret)
{
  if (!match_target_pid())
    return 0;

  int key = 0, *val;
  val = count.lookup(&key);
  if (!val)
    return 0;

  /* no modification, kernel func continues to execute after this. */
  lock_xadd(val, 1);
  return 0;
}
)";

struct fname_buf {
  char buf[16];
};

static int modify_return(ebpf::BPF &bpf) {
  int prog_fd;
  auto res = bpf.load_func("kmod_ret____x64_sys_openat",
                           BPF_PROG_TYPE_TRACING, prog_fd, BPF_F_SLEEPABLE);
  if (!res.ok()) {
    std::cerr << res.msg() << std::endl;
    return 1;
  }

  int attach_fd = bpf_attach_kfunc(prog_fd);
  if (attach_fd < 0) {
    std::cerr << "bpf_attach_kfunc failed: " << attach_fd << std::endl;
    return 1;
  }

  int ret = open("/bin/true", O_RDONLY);
  if (ret >= 0 || errno != EINVAL) {
    close(attach_fd);
    std::cerr << "incorrect open result" << std::endl;
    return 1;
  }

  auto fname_table = bpf.get_array_table<struct fname_buf>("fname_table");
  uint32_t key = 0;
  struct fname_buf val;
  res = fname_table.get_value(key, val);
  if (!res.ok()) {
    close(attach_fd);
    std::cerr << res.msg() << std::endl;
    return 1;
  }
  std::cout << "opened file: " << val.buf << std::endl;

  // detach the kfunc.
  close(attach_fd);
  return 0;
}

static int not_modify_return(ebpf::BPF &bpf) {
  int prog_fd;
  auto res = bpf.load_func("kmod_ret__security_file_open",
                            BPF_PROG_TYPE_TRACING, prog_fd);
  if (!res.ok()) {
    std::cerr << res.msg() << std::endl;
    return 1;
  }

  int attach_fd = bpf_attach_kfunc(prog_fd);
  if (attach_fd < 0) {
    std::cerr << "bpf_attach_kfunc failed: " << attach_fd << std::endl;
    return 1;
  }

  int ret = open("/bin/true", O_RDONLY);
  if (ret < 0) {
    close(attach_fd);
    std::cerr << "incorrect open result" << std::endl;
    return 1;
  }

  auto count_table = bpf.get_array_table<uint32_t>("count");
  uint32_t key = 0, val = 0;
  res = count_table.get_value(key, val);
  if (!res.ok()) {
    close(attach_fd);
    std::cerr << res.msg() << std::endl;
    return 1;
  }

  close(attach_fd);
  std::cout << "security_file_open() is called " << val << " times, expecting 1\n";
  return 0;
}

int main() {
  ebpf::BPF bpf;
  auto res = bpf.init(BPF_PROGRAM);
  if (!res.ok()) {
    std::cerr << res.msg() << std::endl;
    return 1;
  }

  uint32_t key = 0, val = getpid();
  auto pid_table = bpf.get_array_table<uint32_t>("target_pid");
  res = pid_table.update_value(key, val);
  if (!res.ok()) {
    std::cerr << res.msg() << std::endl;
    return 1;
  }

  if (modify_return(bpf))
    return 1;

  if (not_modify_return(bpf))
    return 1;

  return 0;
}
