#!/usr/bin/env bcc-lua
--[[
Copyright 2016 Marek Vavrusa <mvavrusa@cloudflare.com>

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
-- Trace readline() call from all bash instances (print bash commands from all running shells).
-- This is rough equivallent to `bashreadline` with output through perf event API.
-- Source: http://www.brendangregg.com/blog/2016-02-08/linux-ebpf-bcc-uprobes.html
local ffi = require('ffi')
local bpf = require('bpf')
local S = require('syscall')
-- Perf event map
local sample_t = 'struct { uint64_t pid; char str[80]; }'
local events = bpf.map('perf_event_array')
-- Kernel-space part of the program
local probe = bpf.uprobe('/bin/bash:readline', function (ptregs)
	local sample = ffi.new(sample_t)
	sample.pid = pid_tgid()
	ffi.copy(sample.str, ffi.cast('char *', ptregs.ax)) -- Cast `ax` to string pointer and copy to buffer
	perf_submit(events, sample)                         -- Write buffer to perf event map
end, true, -1, 0)
-- User-space part of the program
local log = events:reader(nil, 0, sample_t) -- Must specify PID or CPU_ID to observe
print('            TASK-PID         TIMESTAMP  FUNCTION')
print('               | |               |         |')
while true do
	log:block()               -- Wait until event reader is readable
	for _,e in log:read() do  -- Collect available reader events
		print(string.format('%12s%-16s %-10s %s', '', tonumber(e.pid), os.date("%H:%M:%S"), ffi.string(e.str)))
	end
end
