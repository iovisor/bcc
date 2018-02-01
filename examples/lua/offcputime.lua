#!/usr/bin/env bcc-lua
--[[
Copyright 2016 GitHub, Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]]

local program = [[
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MINBLOCK_US	1

struct key_t {
    char name[TASK_COMM_LEN];
    int stack_id;
};
BPF_HASH(counts, struct key_t);
BPF_HASH(start, u32);
BPF_STACK_TRACE(stack_traces, 10240);

int oncpu(struct pt_regs *ctx, struct task_struct *prev) {
    u32 pid;
    u64 ts, *tsp;

    // record previous thread sleep time
    if (FILTER) {
        pid = prev->pid;
        ts = bpf_ktime_get_ns();
        start.update(&pid, &ts);
    }

    // calculate current thread's delta time
    pid = bpf_get_current_pid_tgid();
    tsp = start.lookup(&pid);
    if (tsp == 0)
        return 0;        // missed start or filtered
    u64 delta = bpf_ktime_get_ns() - *tsp;
    start.delete(&pid);
    delta = delta / 1000;
    if (delta < MINBLOCK_US)
        return 0;

    // create map key
    u64 zero = 0, *val;
    struct key_t key = {};
    int stack_flags = BPF_F_REUSE_STACKID;

    /*
    if (!(prev->flags & PF_KTHREAD))
      stack_flags |= BPF_F_USER_STACK;
    */

    bpf_get_current_comm(&key.name, sizeof(key.name));
    key.stack_id = stack_traces.get_stackid(ctx, stack_flags);

    val = counts.lookup_or_init(&key, &zero);
    (*val) += delta;
    return 0;
}
]]

return function(BPF, utils)
  local ffi = require("ffi")

  local parser = utils.argparse("offcputime", "Summarize off-cpu time")
  parser:flag("-u --user-only")
  parser:option("-p --pid"):convert(tonumber)
  parser:flag("-f --folded")
  parser:option("-d --duration", "duration to trace for", 9999999):convert(tonumber)

  local args = parser:parse()
  local ksym = BPF.SymbolCache()
  local filter = "1"
  local MAXDEPTH = 20

  if args.pid then
    filter = "pid == %d" % args.pid
  elseif args.user_only then
    filter = "!(prev->flags & PF_KTHREAD)"
  end

  local text = program:gsub("FILTER", filter)
  local b = BPF:new{text=text}
  b:attach_kprobe{event="finish_task_switch", fn_name="oncpu"}

  if BPF.num_open_kprobes() == 0 then
    print("no functions matched. quitting...")
    return
  end

  print("Sleeping for %d seconds..." % args.duration)
  pcall(utils.posix.sleep, args.duration)
  print("Tracing...")

  local counts = b:get_table("counts")
  local stack_traces = b:get_table("stack_traces")

  for k, v in counts:items() do
    for addr in stack_traces:walk(tonumber(k.stack_id)) do
      print("    %-16p %s" % {addr, ksym:resolve(addr)})
    end
    print("    %-16s %s" % {"-", ffi.string(k.name)})
    print("        %d\n" % tonumber(v))
  end
end
