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
int trace_method(struct pt_regs *ctx) {
  uint64_t addr;
  bpf_usdt_readarg(2, ctx, &addr);

  char fn_name[128] = {};
  bpf_probe_read(&fn_name, sizeof(fn_name), (void *)addr);

  bpf_trace_printk("%s(...)\n", fn_name);
  return 0;
};
]]

return function(BPF, util)
  if not arg[1] then
    print("usage: rubysyms.lua PID")
    return
  end

  local u = util.USDT:new{pid=tonumber(arg[1])}
  u:enable_probe{probe="method__entry", fn_name="trace_method"}

  local b = BPF:new{text=program, usdt=u}
  local pipe = b:pipe()
  while true do
    print(pipe:trace_fields())
  end
end
