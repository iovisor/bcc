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
--]]

local program = [[
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u64 stack_id;
    u32 pid;
    char comm[TASK_COMM_LEN];
};

BPF_STACK_TRACE(stack_traces, 128);
BPF_PERF_OUTPUT(events);

void trace_stack(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    FILTER
    struct data_t data = {};
    data.stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID),
    data.pid = pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));
}
]]

local ffi = require("ffi")

return function(BPF, utils)
  local parser = utils.argparse("stacksnoop",
      "Trace and print kernel stack traces for a kernel function")
  parser:flag("-s --offset")
  parser:flag("-v --verbose")
  parser:option("-p --pid"):convert(tonumber)
  parser:argument("function", "kernel function name"):target("fn")

  local args = parser:parse()
  local ksym = BPF.SymbolCache()
  local filter = ""

  if args.pid then
    filter = "if (pid != %d) { return; }" % args.pid
  end

  local text = program:gsub("FILTER", filter)
  local bpf = BPF:new{text=text}
  bpf:attach_kprobe{event=args.fn, fn_name="trace_stack"}

  if BPF.num_open_kprobes() == 0 then
    print("Function \"%s\" not found. Exiting." % {args.fn})
    return
  end

  if args.verbose then
    print("%-18s %-12s %-6s %-3s %s" %
        {"TIME(s)", "COMM", "PID", "CPU", "FUNCTION"})
  else
    print("%-18s %s" % {"TIME(s)", "FUNCTION"})
  end

  local stack_traces = bpf:get_table("stack_traces")
  local start_ts = utils.posix.time_ns()

  local function print_event(cpu, event)
    local ts = (utils.posix.time_ns() - start_ts) / 1e9

    if args.verbose then
      print("%-18.9f %-12.12s %-6d %-3d %s" %
          {ts, ffi.string(event.comm), event.pid, cpu, args.fn})
    else
      print("%-18.9f %s" % {ts, args.fn})
    end

    for addr in stack_traces:walk(tonumber(event.stack_id)) do
      local sym, offset = ksym:resolve(addr)
      if args.offset then
        print("\t%-16p %s+0x%x" % {addr, sym, tonumber(offset)})
      else
        print("\t%-16p %s" % {addr, sym})
      end
    end

    print()
  end

  local TASK_COMM_LEN = 16 -- linux/sched.h

  bpf:get_table("events"):open_perf_buffer(print_event,
    "struct { uint64_t stack_id; uint32_t pid; char comm[$]; }",
    {TASK_COMM_LEN})
  bpf:perf_buffer_poll_loop()
end
