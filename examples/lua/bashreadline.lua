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
local ffi = require("ffi")

return function(BPF)
  local b = BPF:new{src_file="bashreadline.c", debug=0}
  b:attach_uprobe{name="/bin/bash", sym="readline", fn_name="printret", retprobe=true}

  local function print_readline(cpu, event)
    print("%-9s %-6d %s" % {os.date("%H:%M:%S"), tonumber(event.pid), ffi.string(event.str)})
  end

  b:get_table("events"):open_perf_buffer(print_readline, "struct { uint64_t pid; char str[80]; }", nil)

  print("%-9s %-6s %s" % {"TIME", "PID", "COMMAND"})
  b:perf_buffer_poll_loop()
end
