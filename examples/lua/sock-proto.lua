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
-- This program looks at IP, UDP and ICMP packets and
-- increments counter for each packet of given type seen
-- Rewrite of https://github.com/torvalds/linux/blob/master/samples/bpf/sock_example.c
local ffi = require("ffi")
local bpf = require("bpf")
local S = require("syscall")

-- Shared part of the program
local map = bpf.map('hash', 256)
map[1], map[6], map[17] = 0, 0, 0
-- Kernel-space part of the program
bpf.socket('lo', function (skb)
   local proto = pkt.ip.proto  -- Get byte (ip.proto) from frame at [23]
   xadd(map[proto], 1)         -- Atomic `map[proto] += 1`
end)
-- User-space part of the program
for _ = 1, 10 do
   local icmp, udp, tcp = map[1], map[17], map[6]
   print(string.format('TCP %d UDP %d ICMP %d packets',
   	     tonumber(tcp or 0), tonumber(udp or 0), tonumber(icmp or 0)))
   S.sleep(1)
end