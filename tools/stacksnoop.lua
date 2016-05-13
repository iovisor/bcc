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

BPF_STACK_TRACE(stack_traces, 128)

void trace_stack(struct pt_regs *ctx) {
    FILTER
    int stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
    if (stack_id >= 0)
        bpf_trace_printk("stack_id=%d\n", stack_id);
}
]]

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
    filter = [[
      u32 pid;
      pid = bpf_get_current_pid_tgid();
      if (pid != %d) { return; }
    ]] % args.pid
  end

  local text = program:gsub("FILTER", filter)
  local bpf = BPF:new{text=text}
  bpf:attach_kprobe{event=args.fn, fn_name="trace_stack"}

  if BPF.num_open_kprobes() == 0 then
    print("Function \"%s\" not found. Exiting." % args.fn)
    return
  end

  if args.verbose then
    print("%-18s %-12s %-6s %-3s %s" %
        {"TIME(s)", "COMM", "PID", "CPU", "SYSCALL"})
  else
    print("%-18s %s" % {"TIME(s)", "SYSCALL"})
  end

  local stack_traces = bpf:get_table("stack_traces")
  local pipe = bpf:pipe()

  while true do
    local task, pid, cpu, flags, ts, msg = pipe:trace_fields()
    local stack_id = string.match(msg, "stack_id=(%d+)")

    if stack_id then
      if args.verbose then
        print("%-18.9f %-12.12s %-6d %-3d %s" % {ts, task, pid, cpu, args.fn})
      else
        print("%-18.9f %s" % {ts, args.fn})
      end

      for addr in stack_traces:walk(tonumber(stack_id)) do
        local sym, offset = ksym:resolve(addr)
        if args.offset then
          print("\t%-16p %s+0x%x" % {addr, sym, tonumber(offset)})
        else
          print("\t%-16p %s" % {addr, sym})
        end
      end
    end
    print()
  end
end
