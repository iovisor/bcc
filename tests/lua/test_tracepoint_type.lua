-- SPDX-License-Identifier: Apache-2.0
package.path = "../../src/lua/?.lua;" .. package.path

local ffi = require("ffi")
local tracepoint_type = require("bpf.tracepoint_type")

-- pid_t is an int in the kernel ABI. The event fields below come from
-- sched_process_exec in include/trace/events/sched.h. The common fields are
-- struct trace_entry from include/linux/trace_events.h.
ffi.cdef("typedef int pid_t;")

local exec_format = [[
name: sched_process_exec
format:
	field:unsigned short common_type; offset:0; size:2; signed:0;
	field:unsigned char common_flags; offset:2; size:1; signed:0;
	field:unsigned char common_preempt_count; offset:3; size:1; signed:0;
	field:int common_pid; offset:4; size:4; signed:1;
	field:__data_loc char[] filename; offset:8; size:4; signed:0;
	field:pid_t pid; offset:12; size:4; signed:1;
	field:pid_t old_pid; offset:16; size:4; signed:1;
]]

local exec_type = ffi.typeof(tracepoint_type.from_format(exec_format))

-- Kernel trace metadata defines __data_loc fields as 4-byte values. Verify
-- both the field width and the offsets of the fields that follow it.
assert(ffi.sizeof(exec_type) == 20)
assert(ffi.offsetof(exec_type, "filename") == 8)
assert(ffi.offsetof(exec_type, "pid") == 12)
assert(ffi.offsetof(exec_type, "old_pid") == 16)

-- sched_wakeup_template uses a fixed char array; the conversion must leave it
-- untouched and retain the following fields' layout.
local wakeup_format = [[
name: sched_wakeup
format:
	field:unsigned short common_type; offset:0; size:2; signed:0;
	field:unsigned char common_flags; offset:2; size:1; signed:0;
	field:unsigned char common_preempt_count; offset:3; size:1; signed:0;
	field:int common_pid; offset:4; size:4; signed:1;
	field:char comm[16]; offset:8; size:16; signed:0;
	field:pid_t pid; offset:24; size:4; signed:1;
	field:int prio; offset:28; size:4; signed:1;
	field:int target_cpu; offset:32; size:4; signed:1;
]]

local wakeup_type = ffi.typeof(tracepoint_type.from_format(wakeup_format))
assert(ffi.sizeof(wakeup_type) == 36)
assert(ffi.offsetof(wakeup_type, "comm") == 8)
assert(ffi.offsetof(wakeup_type, "pid") == 24)
assert(ffi.offsetof(wakeup_type, "target_cpu") == 32)
