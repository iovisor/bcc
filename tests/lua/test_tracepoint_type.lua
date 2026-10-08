-- SPDX-License-Identifier: Apache-2.0
package.path = "../../src/lua/?.lua;" .. package.path

local ffi = require("ffi")
local tracepoint_type = require("bpf.tracepoint_type")

local format = [[
name: test_event
format:
	field:int common; offset:0; size:4; signed:1;
	field:char comm[4]; offset:4; size:4; signed:1;
	field:__data_loc char[] filename; offset:8; size:4; signed:0;
	field:int pid; offset:12; size:4; signed:1;
]]

local event_type = ffi.typeof(tracepoint_type.from_format(format))

-- __data_loc occupies its encoded 32-bit offset/length word. Modeling it as
-- char * would widen the field on 64-bit systems and shift the following pid.
assert(ffi.sizeof(event_type) == 16)
assert(ffi.sizeof("unsigned int") == 4)
assert(ffi.offsetof(event_type, "comm") == 4)
assert(ffi.offsetof(event_type, "filename") == 8)
assert(ffi.offsetof(event_type, "pid") == 12)
