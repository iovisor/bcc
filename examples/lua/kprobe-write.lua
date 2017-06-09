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
-- Simple tracing example that executes a program on
-- return from sys_write() and tracks the number of hits
local ffi = require('ffi')
local bpf = require('bpf')
local S = require('syscall')

-- Shared part of the program
local map = bpf.map('array', 1)
-- Kernel-space part of the program
local probe = bpf.kprobe('myprobe:sys_write', function (ptregs)
   xadd(map[0], 1)
end, true)
-- User-space part of the program
pcall(function()
	for _ = 1, 10 do
	   print('hits: ', tonumber(map[0]))
	   S.sleep(1)
	end
end)
