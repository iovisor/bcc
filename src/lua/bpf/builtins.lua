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
local cdef = require('bpf.cdef')

local BPF, HELPER = ffi.typeof('struct bpf'), ffi.typeof('struct bpf_func_id')
local const_width = {
	[1] = BPF.B, [2] = BPF.H, [4] = BPF.W, [8] = BPF.DW,
}
local const_width_type = {
	[1] = ffi.typeof('uint8_t'), [2] = ffi.typeof('uint16_t'), [4] = ffi.typeof('uint32_t'), [8] = ffi.typeof('uint64_t'),
}

-- Built-ins that will be translated into BPF instructions
-- i.e. bit.bor(0xf0, 0x0f) becomes {'alu64, or, k', reg(0xf0), reg(0x0f), 0, 0}
local builtins = {
	[bit.lshift]  = 'LSH',
	[bit.rshift]  = 'RSH',
	[bit.band]    = 'AND',
	[bit.bnot]    = 'NEG',
	[bit.bor]     = 'OR',
	[bit.bxor]    = 'XOR',
	[bit.arshift] = 'ARSH',
	-- Extensions and intrinsics
}

local function width_type(w)
	-- Note: ffi.typeof doesn't accept '?' as template
	return const_width_type[w] or ffi.typeof(string.format('uint8_t [%d]', w))
end
builtins.width_type = width_type

-- Return struct member size/type (requires LuaJIT 2.1+)
-- I am ashamed that there's no easier way around it.
local function sizeofattr(ct, name)
	if not ffi.typeinfo then error('LuaJIT 2.1+ is required for ffi.typeinfo') end
	local cinfo = ffi.typeinfo(ct)
	while true do
		cinfo = ffi.typeinfo(cinfo.sib)
		if not cinfo then return end
		if cinfo.name == name then break end
	end
	local size = math.max(1, ffi.typeinfo(cinfo.sib or ct).size - cinfo.size)
	-- Guess type name
	return size, builtins.width_type(size)
end
builtins.sizeofattr = sizeofattr

-- Byte-order conversions for little endian
local function ntoh(x, w)
	if w then x = ffi.cast(const_width_type[w/8], x) end
	return bit.bswap(x)
end
local function hton(x, w) return ntoh(x, w) end
builtins.ntoh = ntoh
builtins.hton = hton
builtins[ntoh] = function (e, dst, a, w)
	-- This is trickery, but TO_LE means cpu_to_le(),
	-- and we want exactly the opposite as network is always 'be'
	w = w or ffi.sizeof(e.V[a].type)*8
	if w == 8 then return end -- NOOP
	assert(w <= 64, 'NYI: hton(a[, width]) - operand larger than register width')
	-- Allocate registers and execute
	e.vcopy(dst, a)
	e.emit(BPF.ALU + BPF.END + BPF.TO_BE, e.vreg(dst), 0, 0, w)
end
builtins[hton] = function (e, dst, a, w)
	w = w or ffi.sizeof(e.V[a].type)*8
	if w == 8 then return end -- NOOP
	assert(w <= 64, 'NYI: hton(a[, width]) - operand larger than register width')
	-- Allocate registers and execute
	e.vcopy(dst, a)
	e.emit(BPF.ALU + BPF.END + BPF.TO_LE, e.vreg(dst), 0, 0, w)
end
-- Byte-order conversions for big endian are no-ops
if ffi.abi('be') then
	ntoh = function (x, w)
		return w and ffi.cast(const_width_type[w/8], x) or x
	end
	hton = ntoh
	builtins[ntoh] = function(_, _, _) return end
	builtins[hton] = function(_, _, _) return end
end
-- Other built-ins
local function xadd() error('NYI') end
builtins.xadd = xadd
builtins[xadd] = function (e, ret, a, b, off)
	local vinfo = e.V[a].const
	assert(vinfo and vinfo.__dissector, 'xadd(a, b[, offset]) called on non-pointer')
	local w = ffi.sizeof(vinfo.__dissector)
	-- Calculate structure attribute offsets
	if e.V[off] and type(e.V[off].const) == 'string' then
		local ct, field = vinfo.__dissector, e.V[off].const
		off = ffi.offsetof(ct, field)
		assert(off, 'xadd(a, b, offset) - offset is not valid in given structure')
		w = sizeofattr(ct, field)
	end
	assert(w == 4 or w == 8, 'NYI: xadd() - 1 and 2 byte atomic increments are not supported')
	-- Allocate registers and execute
	local src_reg = e.vreg(b)
	local dst_reg = e.vreg(a)
	-- Set variable for return value and call
	e.vset(ret)
	e.vreg(ret, 0, true, ffi.typeof('int32_t'))
	-- Optimize the NULL check away if provably not NULL
	if not e.V[a].source or e.V[a].source:find('_or_null', 1, true) then
		e.emit(BPF.JMP + BPF.JEQ + BPF.K, dst_reg, 0, 1, 0) -- if (dst != NULL)
	end
	e.emit(BPF.XADD + BPF.STX + const_width[w], dst_reg, src_reg, off or 0, 0)
end

local function probe_read() error('NYI') end
builtins.probe_read = probe_read
builtins[probe_read] = function (e, ret, dst, src, vtype, ofs)
	e.reg_alloc(e.tmpvar, 1)
	-- Load stack pointer to dst, since only load to stack memory is supported
	-- we have to use allocated stack memory or create a new allocation and convert
	-- to pointer type
	e.emit(BPF.ALU64 + BPF.MOV + BPF.X, 1, 10, 0, 0)
	if not e.V[dst].const or not e.V[dst].const.__base > 0 then
		builtins[ffi.new](e, dst, vtype) -- Allocate stack memory
	end
	e.emit(BPF.ALU64 + BPF.ADD + BPF.K, 1, 0, 0, -e.V[dst].const.__base)
	-- Set stack memory maximum size bound
	e.reg_alloc(e.tmpvar, 2)
	if not vtype then
		vtype = cdef.typename(e.V[dst].type)
		-- Dereference pointer type to pointed type for size calculation
		if vtype:sub(-1) == '*' then vtype = vtype:sub(0, -2) end
	end
	local w = ffi.sizeof(vtype)
	e.emit(BPF.ALU64 + BPF.MOV + BPF.K, 2, 0, 0, w)
	-- Set source pointer
	if e.V[src].reg then
		e.reg_alloc(e.tmpvar, 3) -- Copy from original register
		e.emit(BPF.ALU64 + BPF.MOV + BPF.X, 3, e.V[src].reg, 0, 0)
	else
		e.vreg(src, 3)
		e.reg_spill(src) -- Spill to avoid overwriting
	end
	if ofs and ofs > 0 then
		e.emit(BPF.ALU64 + BPF.ADD + BPF.K, 3, 0, 0, ofs)
	end
	-- Call probe read helper
	ret = ret or e.tmpvar
	e.vset(ret)
	e.vreg(ret, 0, true, ffi.typeof('int32_t'))
	e.emit(BPF.JMP + BPF.CALL, 0, 0, 0, HELPER.probe_read)
	e.V[e.tmpvar].reg = nil  -- Free temporary registers
end

builtins[ffi.cast] = function (e, dst, ct, x)
	assert(e.V[ct].const, 'ffi.cast(ctype, x) called with bad ctype')
	e.vcopy(dst, x)
	if e.V[x].const and type(e.V[x].const) == 'table' then
		e.V[dst].const.__dissector = ffi.typeof(e.V[ct].const)
	end
	e.V[dst].type = ffi.typeof(e.V[ct].const)
	-- Specific types also encode source of the data
	-- This is because BPF has different helpers for reading
	-- different data sources, so variables must track origins.
	-- struct pt_regs - source of the data is probe
	-- struct skb     - source of the data is socket buffer
	-- struct X       - source of the data is probe/tracepoint
	if ffi.typeof(e.V[ct].const) == ffi.typeof('struct pt_regs') then
		e.V[dst].source = 'ptr_to_probe'
	end
end

builtins[ffi.new] = function (e, dst, ct, x)
	if type(ct) == 'number' then
		ct = ffi.typeof(e.V[ct].const) -- Get ctype from variable
	end
	assert(not x, 'NYI: ffi.new(ctype, ...) - initializer is not supported')
	assert(not cdef.isptr(ct, true), 'NYI: ffi.new(ctype, ...) - ctype MUST NOT be a pointer')
	e.vset(dst, nil, ct)
	e.V[dst].source = 'ptr_to_stack'
	e.V[dst].const = {__base = e.valloc(ffi.sizeof(ct), true), __dissector = ct}
	-- Set array dissector if created an array
	-- e.g. if ct is 'char [2]', then dissector is 'char'
	local elem_type = tostring(ct):match('ctype<(.+)%s%[(%d+)%]>')
	if elem_type then
		e.V[dst].const.__dissector = ffi.typeof(elem_type)
	end
end

builtins[ffi.copy] = function (e, ret, dst, src)
	assert(cdef.isptr(e.V[dst].type), 'ffi.copy(dst, src) - dst MUST be a pointer type')
	assert(cdef.isptr(e.V[src].type), 'ffi.copy(dst, src) - src MUST be a pointer type')
	-- Specific types also encode source of the data
	-- struct pt_regs - source of the data is probe
	-- struct skb     - source of the data is socket buffer
	if e.V[src].source and e.V[src].source:find('ptr_to_probe', 1, true) then
		e.reg_alloc(e.tmpvar, 1)
		-- Load stack pointer to dst, since only load to stack memory is supported
		-- we have to either use spilled variable or allocated stack memory offset
		e.emit(BPF.ALU64 + BPF.MOV + BPF.X, 1, 10, 0, 0)
		if e.V[dst].spill then
			e.emit(BPF.ALU64 + BPF.ADD + BPF.K, 1, 0, 0, -e.V[dst].spill)
		elseif e.V[dst].const.__base then
			e.emit(BPF.ALU64 + BPF.ADD + BPF.K, 1, 0, 0, -e.V[dst].const.__base)
		else error('ffi.copy(dst, src) - can\'t get stack offset of dst') end
		-- Set stack memory maximum size bound
		local dst_tname = cdef.typename(e.V[dst].type)
		if dst_tname:sub(-1) == '*' then dst_tname = dst_tname:sub(0, -2) end
		e.reg_alloc(e.tmpvar, 2)
		e.emit(BPF.ALU64 + BPF.MOV + BPF.K, 2, 0, 0, ffi.sizeof(dst_tname))
		-- Set source pointer
		if e.V[src].reg then
			e.reg_alloc(e.tmpvar, 3) -- Copy from original register
			e.emit(BPF.ALU64 + BPF.MOV + BPF.X, 3, e.V[src].reg, 0, 0)
		else
			e.vreg(src, 3)
			e.reg_spill(src) -- Spill to avoid overwriting
		end
		-- Call probe read helper
		e.vset(ret)
		e.vreg(ret, 0, true, ffi.typeof('int32_t'))
		e.emit(BPF.JMP + BPF.CALL, 0, 0, 0, HELPER.probe_read)
		e.V[e.tmpvar].reg = nil  -- Free temporary registers
	elseif e.V[src].const and e.V[src].const.__map then
		error('NYI: ffi.copy(dst, src) - src is backed by BPF map')
	elseif e.V[src].const and e.V[src].const.__dissector then
		error('NYI: ffi.copy(dst, src) - src is backed by socket buffer')
	else
		-- TODO: identify cheap register move
		-- TODO: identify copy to/from stack
		error('NYI: ffi.copy(dst, src) - src is neither BPF map/socket buffer or probe')
	end
end
-- print(format, ...) builtin changes semantics from Lua print(...)
-- the first parameter has to be format and only reduced set of conversion specificers
-- is allowed: %d %u %x %ld %lu %lx %lld %llu %llx %p %s
builtins[print] = function (e, ret, fmt, a1, a2, a3)
	-- Load format string and length
	e.reg_alloc(e.V[e.tmpvar], 1)
	e.reg_alloc(e.V[e.tmpvar+1], 1)
	if type(e.V[fmt].const) == 'string' then
		local src = e.V[fmt].const
		local len = #src + 1
		local dst = e.valloc(len, src)
		-- TODO: this is materialize step
		e.V[fmt].const = {__base=dst}
		e.V[fmt].type = ffi.typeof('char ['..len..']')
	elseif e.V[fmt].const.__base then -- luacheck: ignore
		-- NOP
	else error('NYI: print(fmt, ...) - format variable is not literal/stack memory') end
	-- Prepare helper call
	e.emit(BPF.ALU64 + BPF.MOV + BPF.X, 1, 10, 0, 0)
	e.emit(BPF.ALU64 + BPF.ADD + BPF.K, 1, 0, 0, -e.V[fmt].const.__base)
	e.emit(BPF.ALU64 + BPF.MOV + BPF.K, 2, 0, 0, ffi.sizeof(e.V[fmt].type))
	if a1 then
		local args = {a1, a2, a3}
		assert(#args <= 3, 'print(fmt, ...) - maximum of 3 arguments supported')
		for i, arg in ipairs(args) do
			e.vcopy(e.tmpvar, arg)  -- Copy variable
			e.vreg(e.tmpvar, 3+i-1) -- Materialize it in arg register
		end
	end
	-- Call helper
	e.vset(ret)
	e.vreg(ret, 0, true, ffi.typeof('int32_t')) -- Return is integer
	e.emit(BPF.JMP + BPF.CALL, 0, 0, 0, HELPER.trace_printk)
	e.V[e.tmpvar].reg = nil  -- Free temporary registers
end

-- Implements bpf_perf_event_output(ctx, map, flags, var, vlen) on perf event map
local function perf_submit(e, dst, map_var, src)
	-- Set R2 = map fd (indirect load)
	local map = e.V[map_var].const
	e.vcopy(e.tmpvar, map_var)
	e.vreg(e.tmpvar, 2, true, ffi.typeof('uint64_t'))
	e.LD_IMM_X(2, BPF.PSEUDO_MAP_FD, map.fd, ffi.sizeof('uint64_t'))
	-- Set R1 = ctx
	e.reg_alloc(e.tmpvar, 1) -- Spill anything in R1 (unnamed tmp variable)
	e.emit(BPF.ALU64 + BPF.MOV + BPF.X, 1, 6, 0, 0) -- CTX is always in R6, copy
	-- Set R3 = flags
	e.vset(e.tmpvar, nil, 0) -- BPF_F_CURRENT_CPU
	e.vreg(e.tmpvar, 3, false, ffi.typeof('uint64_t'))
	-- Set R4 = pointer to src on stack
	assert(e.V[src].const.__base, 'NYI: submit(map, var) - variable is not on stack')
	e.emit(BPF.ALU64 + BPF.MOV + BPF.X, 4, 10, 0, 0)
	e.emit(BPF.ALU64 + BPF.ADD + BPF.K, 4, 0, 0, -e.V[src].const.__base)
	-- Set R5 = src length
	e.emit(BPF.ALU64 + BPF.MOV + BPF.K, 5, 0, 0, ffi.sizeof(e.V[src].type))
	-- Set R0 = ret and call
	e.vset(dst)
	e.vreg(dst, 0, true, ffi.typeof('int32_t')) -- Return is integer
	e.emit(BPF.JMP + BPF.CALL, 0, 0, 0, HELPER.perf_event_output)
	e.V[e.tmpvar].reg = nil  -- Free temporary registers
end

-- Implements bpf_skb_load_bytes(ctx, off, var, vlen) on skb->data
local function load_bytes(e, dst, off, var)
	-- Set R2 = offset
	e.vset(e.tmpvar, nil, off)
	e.vreg(e.tmpvar, 2, false, ffi.typeof('uint64_t'))
	-- Set R1 = ctx
	e.reg_alloc(e.tmpvar, 1) -- Spill anything in R1 (unnamed tmp variable)
	e.emit(BPF.ALU64 + BPF.MOV + BPF.X, 1, 6, 0, 0) -- CTX is always in R6, copy
	-- Set R3 = pointer to var on stack
	assert(e.V[var].const.__base, 'NYI: load_bytes(off, var, len) - variable is not on stack')
	e.emit(BPF.ALU64 + BPF.MOV + BPF.X, 3, 10, 0, 0)
	e.emit(BPF.ALU64 + BPF.ADD + BPF.K, 3, 0, 0, -e.V[var].const.__base)
	-- Set R4 = var length
	e.emit(BPF.ALU64 + BPF.MOV + BPF.K, 4, 0, 0, ffi.sizeof(e.V[var].type))
	-- Set R0 = ret and call
	e.vset(dst)
	e.vreg(dst, 0, true, ffi.typeof('int32_t')) -- Return is integer
	e.emit(BPF.JMP + BPF.CALL, 0, 0, 0, HELPER.skb_load_bytes)
	e.V[e.tmpvar].reg = nil  -- Free temporary registers
end

-- Implements bpf_get_stack_id()
local function stack_id(e, ret, map_var, key)
	-- Set R2 = map fd (indirect load)
	local map = e.V[map_var].const
	e.vcopy(e.tmpvar, map_var)
	e.vreg(e.tmpvar, 2, true, ffi.typeof('uint64_t'))
	e.LD_IMM_X(2, BPF.PSEUDO_MAP_FD, map.fd, ffi.sizeof('uint64_t'))
	-- Set R1 = ctx
	e.reg_alloc(e.tmpvar, 1) -- Spill anything in R1 (unnamed tmp variable)
	e.emit(BPF.ALU64 + BPF.MOV + BPF.X, 1, 6, 0, 0) -- CTX is always in R6, copy
	-- Load flags in R2 (immediate value or key)
	local imm = e.V[key].const
	assert(tonumber(imm), 'NYI: stack_id(map, var), var must be constant number')
	e.reg_alloc(e.tmpvar, 3) -- Spill anything in R2 (unnamed tmp variable)
	e.LD_IMM_X(3, 0, imm, 8)
	-- Return R0 as signed integer
	e.vset(ret)
	e.vreg(ret, 0, true, ffi.typeof('int32_t'))
	e.emit(BPF.JMP + BPF.CALL, 0, 0, 0, HELPER.get_stackid)
	e.V[e.tmpvar].reg = nil  -- Free temporary registers
end

-- table.insert(table, value) keeps semantics with the exception of BPF maps
-- map `perf_event` -> submit inserted value
builtins[table.insert] = function (e, dst, map_var, value)
	assert(e.V[map_var].const.__map, 'NYI: table.insert() supported only on BPF maps')
	return perf_submit(e, dst, map_var, value)
end

-- bpf_get_current_comm(buffer) - write current process name to byte buffer
local function comm() error('NYI') end
builtins[comm] = function (e, ret, dst)
	-- Set R1 = buffer
	assert(e.V[dst].const.__base, 'NYI: comm(buffer) - buffer variable is not on stack')
	e.reg_alloc(e.tmpvar, 1) -- Spill
	e.emit(BPF.ALU64 + BPF.MOV + BPF.X, 1, 10, 0, 0)
	e.emit(BPF.ALU64 + BPF.ADD + BPF.K, 1, 0, 0, -e.V[dst].const.__base)
	-- Set R2 = length
	e.reg_alloc(e.tmpvar, 2) -- Spill
	e.emit(BPF.ALU64 + BPF.MOV + BPF.K, 2, 0, 0, ffi.sizeof(e.V[dst].type))
	-- Return is integer
	e.vset(ret)
	e.vreg(ret, 0, true, ffi.typeof('int32_t'))
	e.emit(BPF.JMP + BPF.CALL, 0, 0, 0, HELPER.get_current_comm)
	e.V[e.tmpvar].reg = nil  -- Free temporary registers
end

-- Math library built-ins
math.log2 = function () error('NYI') end
builtins[math.log2] = function (e, dst, x)
	-- Classic integer bits subdivison algorithm to find the position
	-- of the highest bit set, adapted for BPF bytecode-friendly operations.
	-- https://graphics.stanford.edu/~seander/bithacks.html
	-- r = 0
	local r = e.vreg(dst, nil, true)
	e.emit(BPF.ALU64 + BPF.MOV + BPF.K, r, 0, 0, 0)
	-- v = x
	e.vcopy(e.tmpvar, x)
	local v = e.vreg(e.tmpvar, 2)
	if cdef.isptr(e.V[x].const) then -- No pointer arithmetics, dereference
		e.vderef(v, v, {const = {__dissector=ffi.typeof('uint64_t')}})
	end
	-- Invert value to invert all tests, otherwise we would need and+jnz
	e.emit(BPF.ALU64 + BPF.NEG + BPF.K, v, 0, 0, 0)        -- v = ~v
	-- Unrolled test cases, converted masking to arithmetic as we don't have "if !(a & b)"
	-- As we're testing inverted value, we have to use arithmetic shift to copy MSB
	for i=4,0,-1 do
		local k = bit.lshift(1, i)
		e.emit(BPF.JMP + BPF.JGT + BPF.K, v, 0, 2, bit.bnot(bit.lshift(1, k))) -- if !upper_half(x)
		e.emit(BPF.ALU64 + BPF.ARSH + BPF.K, v, 0, 0, k)                       --     v >>= k
		e.emit(BPF.ALU64 + BPF.OR + BPF.K, r, 0, 0, k)                         --     r |= k
	end
	-- No longer constant, cleanup tmpvars
	e.V[dst].const = nil
	e.V[e.tmpvar].reg = nil
end
builtins[math.log10] = function (e, dst, x)
	-- Compute log2(x) and transform
	builtins[math.log2](e, dst, x)
	-- Relationship: log10(v) = log2(v) / log2(10)
	local r = e.V[dst].reg
	e.emit(BPF.ALU64 + BPF.ADD + BPF.K, r, 0, 0, 1)    -- Compensate round-down
	e.emit(BPF.ALU64 + BPF.MUL + BPF.K, r, 0, 0, 1233) -- log2(10) ~ 1233>>12
	e.emit(BPF.ALU64 + BPF.RSH + BPF.K, r, 0, 0, 12)
end
builtins[math.log] = function (e, dst, x)
	-- Compute log2(x) and transform
	builtins[math.log2](e, dst, x)
	-- Relationship: ln(v) = log2(v) / log2(e)
	local r = e.V[dst].reg
	e.emit(BPF.ALU64 + BPF.ADD + BPF.K, r, 0, 0, 1)    -- Compensate round-down
	e.emit(BPF.ALU64 + BPF.MUL + BPF.K, r, 0, 0, 2839) -- log2(e) ~ 2839>>12
	e.emit(BPF.ALU64 + BPF.RSH + BPF.K, r, 0, 0, 12)
end

-- Call-type helpers
local function call_helper(e, dst, h, vtype)
	e.vset(dst)
	e.vreg(dst, 0, true, vtype or ffi.typeof('uint64_t'))
	e.emit(BPF.JMP + BPF.CALL, 0, 0, 0, h)
	e.V[dst].const = nil -- Target is not a function anymore
end
local function cpu() error('NYI') end
local function rand() error('NYI') end
local function time() error('NYI') end
local function pid_tgid() error('NYI') end
local function uid_gid() error('NYI') end

-- Export helpers and builtin variants
builtins.cpu = cpu
builtins.time = time
builtins.pid_tgid = pid_tgid
builtins.uid_gid = uid_gid
builtins.comm = comm
builtins.perf_submit = perf_submit
builtins.stack_id = stack_id
builtins.load_bytes = load_bytes
builtins[cpu] = function (e, dst) return call_helper(e, dst, HELPER.get_smp_processor_id) end
builtins[rand] = function (e, dst) return call_helper(e, dst, HELPER.get_prandom_u32, ffi.typeof('uint32_t')) end
builtins[time] = function (e, dst) return call_helper(e, dst, HELPER.ktime_get_ns) end
builtins[pid_tgid] = function (e, dst) return call_helper(e, dst, HELPER.get_current_pid_tgid) end
builtins[uid_gid] = function (e, dst) return call_helper(e, dst, HELPER.get_current_uid_gid) end
builtins[perf_submit] = function (e, dst, map, value) return perf_submit(e, dst, map, value) end
builtins[stack_id] = function (e, dst, map, key) return stack_id(e, dst, map, key) end
builtins[load_bytes] = function (e, dst, off, var, len) return load_bytes(e, dst, off, var, len) end

return builtins
