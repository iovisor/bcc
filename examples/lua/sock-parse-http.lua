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
-- Simple parsing example of TCP/HTTP that counts frequency of types of requests
-- and shows more complicated pattern matching constructions and slices.
-- Rewrite of a BCC example:
-- https://github.com/iovisor/bcc/blob/master/examples/networking/http_filter/http-parse-simple.c
local ffi = require("ffi")
local bpf = require("bpf")
local S = require("syscall")

-- Shared part of the program
local map = bpf.map('hash', 64)
-- Kernel-space part of the program
local prog = bpf.socket('lo', function (skb)
	-- Only ingress so we don't count twice on loopback
	if skb.ingress_ifindex == 0 then return end
	local data = pkt.ip.tcp.data  -- Get TCP protocol dissector
	-- Continue only if we have 7 bytes of TCP data
	if data + 7 > skb.len then return end
	-- Fetch 4 bytes of TCP data and compare
	local h = data(0, 4)
	if h == 'HTTP' or h == 'GET ' or
	   h == 'POST' or h == 'PUT ' or
	   h == 'HEAD' or h == 'DELE' then
	   	-- If hash key doesn't exist, create it
	   	-- otherwise increment counter
	   local v = map[h]
	   if not v then map[h] = 1
	   else          xadd(map[h], 1)
	   end
	end
end)
-- User-space part of the program
for _ = 1, 10 do
	local strkey = ffi.new('uint32_t [1]')
	local s = ''
	for k,v in map.pairs,map,0 do
		strkey[0] = bpf.ntoh(k)
		s = s..string.format('%s %d ', ffi.string(strkey, 4):match '^%s*(.-)%s*$', tonumber(v))
	end
	if #s > 0 then print(s..'messages') end
	S.sleep(1)
end