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

assert(arg[1], "usage: strlen_count PID")

local program = string.gsub([[
#include <uapi/linux/ptrace.h>
int printarg(struct pt_regs *ctx) {
  if (!PT_REGS_PARM1(ctx))
    return 0;
  u32 pid = bpf_get_current_pid_tgid();
  if (pid != PID)
    return 0;
  char str[128] = {};
  bpf_probe_read(&str, sizeof(str), (void *)PT_REGS_PARM1(ctx));
  bpf_trace_printk("strlen(\"%s\")\n", &str);
  return 0;
};
]], "PID", arg[1])

return function(BPF)
  local b = BPF:new{text=program, debug=0}
  b:attach_uprobe{name="c", sym="strlen", fn_name="printarg"}

  local pipe = b:pipe()
  while true do
    local task, pid, cpu, flags, ts, msg = pipe:trace_fields()
    print("%-18.9f %-16s %-6d %s" % {ts, task, pid, msg})
  end
end
