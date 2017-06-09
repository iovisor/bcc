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
-- This is rough equivallent to `bashreadline`
-- Source: http://www.brendangregg.com/blog/2016-02-08/linux-ebpf-bcc-uprobes.html
local ffi = require('ffi')
local bpf = require('bpf')
local S = require('syscall')
-- Kernel-space part of the program
local probe = bpf.uprobe('/bin/bash:readline', function (ptregs)
	local line = ffi.new('char [40]')              -- Create a 40 byte buffer on stack
	ffi.copy(line, ffi.cast('char *', ptregs.ax))  -- Cast `ax` to string pointer and copy to buffer
	print('%s\n', line)                            -- Print to trace_pipe
end, true, -1, 0)
-- User-space part of the program
local ok, err = pcall(function()
	local log = bpf.tracelog()
	print('            TASK-PID   CPU#         TIMESTAMP  FUNCTION')
	print('               | |      |               |         |')
	while true do
		print(log:read())
	end
end)
