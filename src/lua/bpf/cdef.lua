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
local ffi = require('ffi')
local bit = require('bit')
local has_syscall, S = pcall(require, 'syscall')
local M = {}

ffi.cdef [[
struct bpf {
	/* Instruction classes */
	static const int LD   = 0x00;
	static const int LDX  = 0x01;
	static const int ST   = 0x02;
	static const int STX  = 0x03;
	static const int ALU  = 0x04;
	static const int JMP  = 0x05;
	static const int ALU64 = 0x07;
	/* ld/ldx fields */
	static const int W    = 0x00;
	static const int H    = 0x08;
	static const int B    = 0x10;
	static const int ABS  = 0x20;
	static const int IND  = 0x40;
	static const int MEM  = 0x60;
	static const int LEN  = 0x80;
	static const int MSH  = 0xa0;
	/* alu/jmp fields */
	static const int ADD  = 0x00;
	static const int SUB  = 0x10;
	static const int MUL  = 0x20;
	static const int DIV  = 0x30;
	static const int OR   = 0x40;
	static const int AND  = 0x50;
	static const int LSH  = 0x60;
	static const int RSH  = 0x70;
	static const int NEG  = 0x80;
	static const int MOD  = 0x90;
	static const int XOR  = 0xa0;
	static const int JA   = 0x00;
	static const int JEQ  = 0x10;
	static const int JGT  = 0x20;
	static const int JGE  = 0x30;
	static const int JSET = 0x40;
	static const int K    = 0x00;
	static const int X    = 0x08;
	static const int JNE  = 0x50;	/* jump != */
	static const int JSGT = 0x60;	/* SGT is signed '>', GT in x86 */
	static const int JSGE = 0x70;	/* SGE is signed '>=', GE in x86 */
	static const int CALL = 0x80;	/* function call */
	static const int EXIT = 0x90;	/* function return */
	/* ld/ldx fields */
	static const int DW    = 0x18;	/* double word */
	static const int XADD  = 0xc0;	/* exclusive add */
	/* alu/jmp fields */
	static const int MOV   = 0xb0;	/* mov reg to reg */
	static const int ARSH  = 0xc0;	/* sign extending arithmetic shift right */
	/* change endianness of a register */
	static const int END   = 0xd0;	/* flags for endianness conversion: */
	static const int TO_LE = 0x00;	/* convert to little-endian */
	static const int TO_BE = 0x08;	/* convert to big-endian */
	/* misc */
	static const int PSEUDO_MAP_FD = 0x01;
	/* helper functions */
	static const int F_CURRENT_CPU    = 0xffffffff;
	static const int F_USER_STACK     = 1 << 8;
	static const int F_FAST_STACK_CMP = 1 << 9;
	static const int F_REUSE_STACKID  = 1 << 10;
	/* special offsets for ancillary data */
	static const int NET_OFF          = -0x100000;
	static const int LL_OFF           = -0x200000;
};
/* eBPF commands */
struct bpf_cmd {
	static const int MAP_CREATE       = 0;
	static const int MAP_LOOKUP_ELEM  = 1;
	static const int MAP_UPDATE_ELEM  = 2;
	static const int MAP_DELETE_ELEM  = 3;
	static const int MAP_GET_NEXT_KEY = 4;
	static const int PROG_LOAD        = 5;
	static const int OBJ_PIN          = 6;
	static const int OBJ_GET          = 7;
};
/* eBPF helpers */
struct bpf_func_id {
	static const int unspec               = 0;
	static const int map_lookup_elem      = 1;
	static const int map_update_elem      = 2;
	static const int map_delete_elem      = 3;
	static const int probe_read           = 4;
	static const int ktime_get_ns         = 5;
	static const int trace_printk         = 6;
	static const int get_prandom_u32      = 7;
	static const int get_smp_processor_id = 8;
	static const int skb_store_bytes      = 9;
	static const int l3_csum_replace      = 10;
	static const int l4_csum_replace      = 11;
	static const int tail_call            = 12;
	static const int clone_redirect       = 13;
	static const int get_current_pid_tgid = 14;
	static const int get_current_uid_gid  = 15;
	static const int get_current_comm     = 16;
	static const int get_cgroup_classid   = 17;
	static const int skb_vlan_push        = 18;
	static const int skb_vlan_pop         = 19;
	static const int skb_get_tunnel_key   = 20;
	static const int skb_set_tunnel_key   = 21;
	static const int perf_event_read      = 22;
	static const int redirect             = 23;
	static const int get_route_realm      = 24;
	static const int perf_event_output    = 25;
	static const int skb_load_bytes       = 26;
	static const int get_stackid          = 27;
};
/* BPF_MAP_STACK_TRACE structures and constants */
static const int BPF_MAX_STACK_DEPTH = 127;
struct bpf_stacktrace {
	uint64_t ip[BPF_MAX_STACK_DEPTH];
};
]]

-- Compatibility: ljsyscall doesn't have support for BPF syscall
if not has_syscall or not S.bpf then
	error("ljsyscall doesn't support bpf(), must be updated")
else
	local strflag = require('syscall.helpers').strflag
	-- Compatibility: ljsyscall<=0.12
	if not S.c.BPF_MAP.LRU_HASH then
		S.c.BPF_MAP = strflag {
			UNSPEC           = 0,
			HASH             = 1,
			ARRAY            = 2,
			PROG_ARRAY       = 3,
			PERF_EVENT_ARRAY = 4,
			PERCPU_HASH      = 5,
			PERCPU_ARRAY     = 6,
			STACK_TRACE      = 7,
			CGROUP_ARRAY     = 8,
			LRU_HASH         = 9,
			LRU_PERCPU_HASH  = 10,
			LPM_TRIE         = 11,
			ARRAY_OF_MAPS    = 12,
			HASH_OF_MAPS     = 13,
			DEVMAP           = 14,
			SOCKMAP          = 15,
			CPUMAP           = 16,
		}
	end
	if not S.c.BPF_PROG.TRACEPOINT then
		S.c.BPF_PROG = strflag {
			UNSPEC           = 0,
			SOCKET_FILTER    = 1,
			KPROBE           = 2,
			SCHED_CLS        = 3,
			SCHED_ACT        = 4,
			TRACEPOINT       = 5,
			XDP              = 6,
			PERF_EVENT       = 7,
			CGROUP_SKB       = 8,
			CGROUP_SOCK      = 9,
			LWT_IN           = 10,
			LWT_OUT          = 11,
			LWT_XMIT         = 12,
			SOCK_OPS         = 13,
			SK_SKB           = 14,
			CGROUP_DEVICE    = 15,
			SK_MSG           = 16,
			RAW_TRACEPOINT   = 17,
			CGROUP_SOCK_ADDR = 18,
		}
	end
end

-- Compatibility: metatype for stacktrace
local function stacktrace_iter(t, i)
	i = i + 1
	if i < #t and t.ip[i] > 0 then
		return i, t.ip[i]
	end
end
ffi.metatype('struct bpf_stacktrace', {
	__len = function (t) return ffi.sizeof(t.ip) / ffi.sizeof(t.ip[0]) end,
	__ipairs = function (t) return stacktrace_iter, t, -1 end,
})

-- Reflect cdata type
function M.typename(v)
	if not v or type(v) ~= 'cdata' then return nil end
	return string.match(tostring(ffi.typeof(v)), '<([^>]+)')
end

-- Reflect if cdata type can be pointer (accepts array or pointer)
function M.isptr(v, noarray)
	local ctname = M.typename(v)
	if ctname then
		ctname = string.sub(ctname, -1)
		ctname = ctname == '*' or (not noarray and ctname == ']')
	end
	return ctname
end

-- Return true if variable is a non-nil constant that can be used as immediate value
-- e.g. result of KSHORT and KNUM
function M.isimmconst(v)
	return (type(v.const) == 'number' and not ffi.istype(v.type, ffi.typeof('void')))
		or type(v.const) == 'cdata' and ffi.istype(v.type, ffi.typeof('uint64_t')) -- Lua numbers are at most 52 bits
		or type(v.const) == 'cdata' and ffi.istype(v.type, ffi.typeof('int64_t'))
end

function M.osversion()
	-- We have no better way to extract current kernel hex-string other
	-- than parsing headers, compiling a helper function or reading /proc
	local ver_str, count = S.sysctl('kernel.version'):match('%d+.%d+.%d+'), 2
	if not ver_str then -- kernel.version is freeform, fallback to kernel.osrelease
		ver_str = S.sysctl('kernel.osrelease'):match('%d+.%d+.%d+')
	end
	local version = 0
	for i in ver_str:gmatch('%d+') do -- Convert 'X.Y.Z' to 0xXXYYZZ
		version = bit.bor(version, bit.lshift(tonumber(i), 8*count))
		count = count - 1
	end
	return version
end

function M.event_reader(reader, event_type)
	-- Caller can specify event message binary format
	if event_type then
		assert(type(event_type) == 'string' and ffi.typeof(event_type), 'not a valid type for event reader')
		event_type = ffi.typeof(event_type .. '*') -- Convert type to pointer-to-type
	end
	-- Wrap reader in interface that can interpret read event messages
	return setmetatable({reader=reader,type=event_type}, {__index = {
		block = function(_ --[[self]])
			return S.select { readfds = {reader.fd} }
		end,
		next = function(_ --[[self]], k)
			local len, ev = reader:next(k)
			-- Filter out only sample frames
			while ev and ev.type ~= S.c.PERF_RECORD.SAMPLE do
				len, ev = reader:next(len)
			end
			if ev and event_type then
				-- The perf event reader returns framed data with header and variable length
				-- This is going skip the frame header and cast data to given type
				ev = ffi.cast(event_type, ffi.cast('char *', ev) + ffi.sizeof('struct perf_event_header') + ffi.sizeof('uint32_t'))
			end
			return len, ev
		end,
		read = function(self)
			return self.next, self, nil
		end,
	}})
end

function M.tracepoint_type(tp)
	-- Read tracepoint format string
	local fp = assert(io.open('/sys/kernel/debug/tracing/events/'..tp..'/format', 'r'))
	local fmt = fp:read '*a'
	fp:close()
	-- Parse struct fields
	local fields = {}
	for f in fmt:gmatch 'field:([^;]+;)' do
		table.insert(fields, f)
	end
	return string.format('struct { %s }', table.concat(fields))
end

return M
