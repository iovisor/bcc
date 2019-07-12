/*
 * This is an example of a hardware breakpoint on a kernel address.
 * run in project examples directory with:
 * sudo ./breakpoint.py <0xaddress> <pid> <breakpoint_type>
 * HW_BREAKPOINT_W = 2
 * HW_BREAKPOINT_RW = 3
 *
 * You may need to clear the old tracepipe inputs before running the script : 
 * echo > /sys/kernel/debug/tracing/trace 
 *
 *  10-Jul-2019   Aanandita Dhawan   Created this.
 */


#include <unistd.h>
#include <fstream>
#include <iostream>
#include <string>
#include <stdlib.h>
#include <stddef.h>
#include <algorithm>
#include "BPF.h"
#include <inttypes.h>
#include <stdio.h>
#include <iostream>
#include <string>

const std::string BPF_PROGRAM = R"(

#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

struct stack_key_t {
  int pid;
  char name[16];
  int user_stack;
  int kernel_stack;
};

BPF_STACK_TRACE(stack_traces, 16384);
BPF_HASH(counts, struct stack_key_t, uint64_t);

int func(struct pt_regs *ctx) {
  struct stack_key_t key = {};
  key.pid = bpf_get_current_pid_tgid() >> 32;
  bpf_get_current_comm(&key.name, sizeof(key.name));
  key.kernel_stack = stack_traces.get_stackid(ctx, 0);
  key.user_stack = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

  u64 zero = 0, *val;
  val = counts.lookup_or_init(&key, &zero);
  (*val)++;

  bpf_trace_printk("Hello World, Here I accessed the address!\n");

  return 0;

}

)";

struct stack_key_t {
  int pid;
  char name[16];
  int user_stack;
  int kernel_stack;
};

int main(int argc, char** argv) {
  
  ebpf::BPF bpf;
  auto init_res = bpf.init(BPF_PROGRAM);
  if (init_res.code() != 0) {
    std::cerr << init_res.msg() << std::endl;
    return 1;
  }

  std::ifstream pipe("/sys/kernel/debug/tracing/trace_pipe");
  std::string line;
  
  uint64_t symbol_addr; 
  char *end; 
  long int num;
  num = strtoull(argv[1], &end, 16);
  int pid;
  char chara = argv[3][0];
  int c = chara - '0';
  pid = std::stoi(argv[2]); //check only for a certain process
  
  auto attach_res = bpf.attach_breakpoint(num, pid, "func", c);

  if (attach_res.code() != 0) {
    std::cerr << attach_res.msg() << std::endl;
    return 1;
  }
  
  while (true) {
    if (std::getline(pipe, line)) {
      std::cout << line << std::endl;
      printf("Got something in the trace pipe so breaking \n");
      break;
    } else {
      std::cout << "Waiting for a perf hit" << std::endl;
      sleep(1);
    }
  }

  auto table =
      bpf.get_hash_table<stack_key_t, uint64_t>("counts").get_table_offline();
  std::sort(
      table.begin(), table.end(),
      [](std::pair<stack_key_t, uint64_t> a,
         std::pair<stack_key_t, uint64_t> b) { return a.second < b.second; });
  auto stacks = bpf.get_stack_table("stack_traces");

  int lost_stacks = 0;
  for (auto it : table) {
    std::cout << "PID: " << it.first.pid << " (" << it.first.name << ") "
              << "did " << it.second
              << " access from following stack: " << std::endl;
    if (it.first.kernel_stack >= 0) {
      std::cout << "  Kernel Stack:" << std::endl;
      auto syms = stacks.get_stack_symbol(it.first.kernel_stack, -1);
      for (auto sym : syms)
        std::cout << "    " << sym << std::endl;
    } else {
      // -EFAULT normally means the stack is not availiable and not an error
      if (it.first.kernel_stack != -EFAULT) {
        lost_stacks++;
        std::cout << "    [Lost Kernel Stack" << it.first.kernel_stack << "]"
                  << std::endl;
      }
    }
    if (it.first.user_stack >= 0) {
      std::cout << "  User Stack:" << std::endl;
      auto syms = stacks.get_stack_symbol(it.first.user_stack, it.first.pid);
      for (auto sym : syms)
        std::cout << "    " << sym << std::endl;
    } else {
      // -EFAULT normally means the stack is not availiable and not an error
      if (it.first.user_stack != -EFAULT) {
        lost_stacks++;
        std::cout << "    [Lost User Stack " << it.first.user_stack << "]"
                  << std::endl;
      }
    }
  }

  if (lost_stacks > 0)
    std::cout << "Total " << lost_stacks << " stack-traces lost due to "
              << "hash collision or stack table full" << std::endl;

  bpf.detach_breakpoint("func");

  return 0;
}
