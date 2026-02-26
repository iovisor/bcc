/* execsnoop-cpp - Trace new processes via exec() syscalls.
*
* Inspired by Brendan Gregg's execsnoop (bcc/tools/execsnoop.py)
*
* USAGE: ./execsnoop
*
* Copyright (C) 2026 drapl0n
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <bcc/BPF.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <sstream>
#include <unordered_map>
#include <queue>
#include <mutex>

// Define the eBPF program
const std::string BPF_PROGRAM = R"(
#include<linux/ptrace.h>
#include<linux/sched.h>
#include<linux/fs.h>

enum event_type {
  EVENT_ARG = 0,
  EVENT_RET = 1,
};

struct data_t {
  u32 pid;
  u32 ppid;
  char comm[TASK_COMM_LEN];
  char pcomm[TASK_COMM_LEN];
  char argv[128];
  enum event_type type;
  int8_t retval;
};

BPF_PERF_OUTPUT(events);

static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data){
  bpf_probe_read_user(data->argv, sizeof(data->argv), ptr);
  events.perf_submit(ctx, data, sizeof(struct data_t));
  return 1;
}

static int submit_args(struct pt_regs *ctx, void *ptr, struct data_t *data){
  const char *argp = NULL;
  bpf_probe_read_user(&argp, sizeof(argp), ptr);

  if (argp) {
    return __submit_arg(ctx, (void *)(argp), data);
  }
  return 0;
}

int syscall__execve(struct pt_regs *ctx,
  const char __user *filename,
  const char __user *const __user *__argv,
  const char __user *const __user *__envp) {

  struct data_t data = {};
  struct task_struct *task;

  data.pid = bpf_get_current_pid_tgid() >> 32;
  task = (struct task_struct *)bpf_get_current_task();
  data.ppid = task->real_parent->tgid;
  bpf_probe_read_kernel_str(&data.pcomm, sizeof(data.pcomm), task->real_parent->comm);
  
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.type = EVENT_ARG;
  __submit_arg(ctx, (void *)filename, &data);

  for (int i = 1; i < 10; i++) {
    if (submit_args(ctx, (void *)&__argv[i], &data) == 0) {
      goto out;
    }
  }

  char ellipsis[] = "...";
  __submit_arg(ctx, (void *)ellipsis, &data);

out:
  return 0;
}

int do_ret_execve(struct pt_regs *ctx) {
  struct data_t data = {};
  struct task_struct *task;

  data.pid = bpf_get_current_pid_tgid();
  task = (struct task_struct *)bpf_get_current_task();
  data.ppid = task->real_parent->tgid;
  bpf_probe_read_kernel_str(&data.pcomm, sizeof(data.pcomm), task->real_parent->comm);
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  data.type = EVENT_RET;
  data.retval = PT_REGS_RC(ctx);

  events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}

)";

enum event_type {
  EVENT_ARG = 0,
  EVENT_RET = 1,
};

struct data_t {
  uint32_t pid;
  uint32_t ppid;
  char comm[16];
  char pcomm[16];
  char args[128];
  enum event_type type;
  int8_t retval;
};

std::queue<std::string> args;

// Args handeling routine
int get_args(struct data_t* event) {
  while (!args.empty()) {
    std::cout << args.front() << " ";
    args.pop();
  }
  std::cout << std::endl;
  return 0;
}

void handle_event(void *ctx, void *data, int data_size) {
  auto *event = static_cast<data_t *>(data);
  
  if (event->type == EVENT_ARG) {
    args.push(event->args);
  } else if (event->type == EVENT_RET) {
    std::cout << "PID: " << event->pid
              << "\tPPID:  " << event->ppid
              << "\tCOMM: " << event->comm 
              << "\tARGS: ";
    get_args(event);
  }
}

int main() {
  ebpf::BPF bpf;

  // Initialize BPF program
  auto init_res = bpf.init(BPF_PROGRAM);
  if (!init_res.ok()) {
    std::cerr << init_res.msg() << std::endl;
    return 1;
  }

  // Attach kprobe to execve syscall
  std::string execve_fnname = bpf.get_syscall_fnname("execve");
  auto attach_res = bpf.attach_kprobe(execve_fnname, "syscall__execve");
  if (!attach_res.ok()) {
    std::cerr << attach_res.msg() << std::endl;
    return 1;
  }

  // Attach kretprobe to execve syscall
  auto attach_ret = bpf.attach_kprobe(execve_fnname, "do_ret_execve", 0, BPF_PROBE_RETURN, 0);
  if (!attach_ret.ok()) {
    std::cerr << attach_ret.msg() << std::endl;
    return 1;
  }

  // Open perf buffer to receive events
  auto perf_buffer = bpf.open_perf_buffer("events", handle_event);
  if (!perf_buffer.ok()) {
    std::cerr << perf_buffer.msg() << std::endl;
    return 1;
  }

  std::cout << "Tracing execve syscalls... Press Ctrl+C to stop." << std::endl;
  
  // Poll events
  while (true) {
    bpf.poll_perf_buffer("events", 100);
  }

  return 0;
}
