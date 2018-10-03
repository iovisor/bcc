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
-- LuaJIT to BPF bytecode compiler.
--
-- The code generation phase is currently one-pass and produces:
-- * Compiled code in BPF bytecode format (https://www.kernel.org/doc/Documentation/networking/filter.txt)
-- * Variables with liveness analysis and other meta (spill information, compile-time value)
--
-- The code generator optimises as much as possible in single pass:
-- * Fold compile-time expressions and constant propagation
-- * Basic control flow analysis with dead code elimination (based on compile-time expressions)
-- * Single-pass optimistic register allocation
--
-- The first pass doesn't have variable lifetime visibility yet, so it relies on rewriter for further
-- optimisations such as:
-- * Dead store elimination (first-pass doesn't know if/when the variable is going to be used)
-- * Common sub-expression elimination (relies on DCE and liveness analysis)
-- * Orphan JMP elimination (removing this in first pass would break previous JMP targets)
-- * Better register allocation (needs to be recomputed after optimisations)

local ffi = require('ffi')
local bit = require('bit')
local S = require('syscall')
local bytecode = require('bpf.ljbytecode')
local cdef = require('bpf.cdef')
local proto = require('bpf.proto')
local builtins = require('bpf.builtins')

-- Constants
local ALWAYS, NEVER = -1, -2
local BPF = ffi.typeof('struct bpf')
local HELPER = ffi.typeof('struct bpf_func_id')

-- Symbolic table of constant expressions over numbers
local const_expr = {
	ADD = function (a, b) return a + b end,
	SUB = function (a, b) return a - b end,
	DIV = function (a, b) return a / b end,
	MOD = function (a, b) return a % b end,
	JEQ = function (a, b) return a == b end,
	JNE = function (a, b) return a ~= b end,
	JGE = function (a, b) return a >= b end,
	JGT = function (a, b) return a > b end,
}

local const_width = {
	[1] = BPF.B, [2] = BPF.H, [4] = BPF.W, [8] = BPF.DW,
}

-- Built-ins that are strict only (never compile-time expandable)
local builtins_strict = {
	[ffi.new] = true,
	[print]   = true,
}

-- Deep copy a table
local function table_copy(t)
	local copy = {}
	for n,v in pairs(t) do
		if type(v) == 'table' then
			v = table_copy(v)
		end
		copy[n] = v
	end
	return copy
end

-- Return true if the constant part is a proxy
local function is_proxy(x)
	return type(x) == 'table' and (x.__dissector or x.__map or x.__base)
end

-- Create compiler closure
local function create_emitter(env, stackslots, params, param_types)

local V = {}   -- Variable tracking / register allocator
local code = { -- Generated code
	pc = 0, bc_pc = 0,
	insn = ffi.new('struct bpf_insn[4096]'),
	fixup = {},
	reachable = true,
	seen_cmp = nil,
}
local Vstate = {} -- Track variable layout at basic block exits

-- Anything below this stack offset is free to use by caller
-- @note: There is no tracking memory allocator, so the caller may
-- lower it for persistent objects, but such memory will never
-- be reclaimed and the caller is responsible for resetting stack
-- top whenever the memory below is free to be reused
local stack_top = (stackslots + 1) * ffi.sizeof('uint64_t')

local function emit(op, dst, src, off, imm)
	local ins = code.insn[code.pc]
	ins.code = op
	ins.dst_reg = dst
	ins.src_reg = src
	ins.off = off
	ins.imm = imm
	code.pc = code.pc + 1
end

local function reg_spill(var)
	local vinfo = V[var]
	assert(vinfo.reg, 'attempt to spill VAR that doesn\'t have an allocated register')
	vinfo.spill = (var + 1) * ffi.sizeof('uint64_t') -- Index by (variable number) * (register width)
	emit(BPF.MEM + BPF.STX + BPF.DW, 10, vinfo.reg, -vinfo.spill, 0)
	vinfo.reg = nil
end

local function reg_fill(var, reg)
	local vinfo = V[var]
	assert(reg, 'attempt to fill variable to register but not register is allocated')
	assert(vinfo.spill, 'attempt to fill register with a VAR that isn\'t spilled')
	emit(BPF.MEM + BPF.LDX + BPF.DW, reg, 10, -vinfo.spill, 0)
	vinfo.reg = reg
	vinfo.spill = nil
end

-- Allocate a register (lazy simple allocator)
local function reg_alloc(var, reg)
	-- Specific register requested, must spill/move existing variable
	if reg then
		for k,v in pairs(V) do -- Spill any variable that has this register
			if v.reg == reg and not v.shadow then
				reg_spill(k)
				break
			end
		end
		return reg
	end
	-- Find free or least recently used slot
	local last, last_seen, used = nil, 0xffff, 0
	for k,v in pairs(V) do
		if v.reg then
			if not v.live_to or v.live_to < last_seen then
				last, last_seen = k, v.live_to or last_seen
			end
			used = bit.bor(used, bit.lshift(1, v.reg))
		end
	end
	-- Attempt to select a free register from R7-R9 (callee saved)
	local free = bit.bnot(used)
	if     bit.band(free, 0x80) ~= 0 then reg = 7
	elseif bit.band(free,0x100) ~= 0 then reg = 8
	elseif bit.band(free,0x200) ~= 0 then reg = 9
	end
	-- Select another variable to be spilled
	if not reg then
		assert(last)
		reg = V[last].reg
		reg_spill(last)
	end
	assert(reg, 'VAR '..var..'fill/spill failed')
	return reg
end

-- Set new variable
local function vset(var, reg, const, vtype)
	-- Must materialise all variables shadowing this variable slot, as it will be overwritten
	if V[var] and V[var].reg then
		for _, vinfo in pairs(V) do
			-- Shadowing variable MUST share the same type and attributes,
			-- but the register assignment may have changed
			if vinfo.shadow == var then
				vinfo.reg = V[var].reg
				vinfo.shadow = nil
			end
		end
	end
	-- Get precise type for CDATA or attempt to narrow numeric constant
	if not vtype and type(const) == 'cdata' then
		vtype = ffi.typeof(const)
	end
	V[var] = {reg=reg, const=const, type=vtype}
	-- Track variable source
	if V[var].const and type(const) == 'table' then
		V[var].source = V[var].const.source
	end
end

-- Materialize (or register) a variable in a register
-- If the register is nil, then the a new register is assigned (if not already assigned)
local function vreg(var, reg, reserve, vtype)
	local vinfo = V[var]
	assert(vinfo, 'VAR '..var..' not registered')
	vinfo.live_to = code.pc-1
	if (vinfo.reg and not reg) and not vinfo.shadow then return vinfo.reg end
	reg = reg_alloc(var, reg)
	-- Materialize variable shadow copy
	local src = vinfo
	while src.shadow do src = V[src.shadow] end
	if reserve then -- luacheck: ignore
		-- No load to register occurs
	elseif src.reg then
		emit(BPF.ALU64 + BPF.MOV + BPF.X, reg, src.reg, 0, 0)
	elseif src.spill then
		vinfo.spill = src.spill
		reg_fill(var, reg)
	elseif src.const then
		vtype = vtype or src.type
		if type(src.const) == 'table' and src.const.__base then
			-- Load pointer type
			emit(BPF.ALU64 + BPF.MOV + BPF.X, reg, 10, 0, 0)
			emit(BPF.ALU64 + BPF.ADD + BPF.K, reg, 0, 0, -src.const.__base)
		elseif type(src.const) == 'table' and src.const.__dissector then
			-- Load dissector offset (imm32), but keep the constant part (dissector proxy)
			emit(BPF.ALU64 + BPF.MOV + BPF.K, reg, 0, 0, src.const.off or 0)
		elseif vtype and ffi.sizeof(vtype) == 8 then
			-- IMM64 must be done in two instructions with imm64 = (lo(imm32), hi(imm32))
			emit(BPF.LD + BPF.DW, reg, 0, 0, ffi.cast('uint32_t', src.const))
			emit(0, 0, 0, 0, ffi.cast('uint32_t', bit.rshift(bit.rshift(src.const, 16), 16)))
			vinfo.const = nil -- The variable is live
		else
			emit(BPF.ALU64 + BPF.MOV + BPF.K, reg, 0, 0, src.const)
			vinfo.const = nil -- The variable is live
		end
	else assert(false, 'VAR '..var..' has neither register nor constant value') end
	vinfo.reg = reg
	vinfo.shadow = nil
	vinfo.live_from = code.pc-1
	vinfo.type = vtype or vinfo.type
	return reg
end

-- Copy variable
local function vcopy(dst, src)
	if dst == src then return end
	V[dst] = {reg=V[src].reg, const=V[src].const, shadow=src, source=V[src].source, type=V[src].type}
end

-- Dereference variable of pointer type
local function vderef(dst_reg, src_reg, vinfo)
	-- Dereference map pointers for primitive types
	-- BPF doesn't allow pointer arithmetics, so use the entry value
	assert(type(vinfo.const) == 'table' and vinfo.const.__dissector, 'cannot dereference a non-pointer variable')
	local vtype = vinfo.const.__dissector
	local w = ffi.sizeof(vtype)
	assert(const_width[w], 'NYI: sizeof('..tostring(vtype)..') not 1/2/4/8 bytes')
	if dst_reg ~= src_reg then
		emit(BPF.ALU64 + BPF.MOV + BPF.X, dst_reg, src_reg, 0, 0)    -- dst = src
	end
	-- Optimize the NULL check away if provably not NULL
	if not vinfo.source or vinfo.source:find('_or_null', 1, true) then
		emit(BPF.JMP + BPF.JEQ + BPF.K, src_reg, 0, 1, 0)            -- if (src != NULL)
	end
	emit(BPF.MEM + BPF.LDX + const_width[w], dst_reg, src_reg, 0, 0) --     dst = *src;
end

-- Allocate a space for variable
local function valloc(size, blank)
	local base = stack_top
	assert(stack_top + size < 512 * 1024, 'exceeded maximum stack size of 512kB')
	stack_top = stack_top + size
	-- Align to 8 byte boundary
	stack_top = math.ceil(stack_top/8)*8
	-- Current kernel version doesn't support ARG_PTR_TO_RAW_STACK
	-- so we always need to have memory initialized, remove this when supported
	if blank then
		if type(blank) == 'string' then
			local sp = 0
			while sp < size do
				-- TODO: no BPF_ST + BPF_DW instruction yet
				local as_u32 = ffi.new('uint32_t [1]')
				local sub = blank:sub(sp+1, sp+ffi.sizeof(as_u32))
				ffi.copy(as_u32, sub, #sub)
				emit(BPF.MEM + BPF.ST + BPF.W, 10, 0, -(stack_top-sp), as_u32[0])
				sp = sp + ffi.sizeof(as_u32)
			end
		elseif type(blank) == 'boolean' then
			reg_alloc(stackslots, 0)
			emit(BPF.ALU64 + BPF.MOV + BPF.K, 0, 0, 0, 0)
			for sp = base+8,stack_top,8 do
				emit(BPF.MEM + BPF.STX + BPF.DW, 10, 0, -sp, 0)
			end
		else error('NYI: will with unknown type '..type(blank)) end
	end
	return stack_top
end

-- Turn variable into scalar in register (or constant)
local function vscalar(a, w)
	assert(const_width[w], 'sizeof(scalar variable) must be 1/2/4/8')
	local src_reg
	-- If source is a pointer, we must dereference it first
	if cdef.isptr(V[a].type) then
		src_reg = vreg(a)
		local tmp_reg = reg_alloc(stackslots, 1) -- Clone variable in tmp register
		emit(BPF.ALU64 + BPF.MOV + BPF.X, tmp_reg, src_reg, 0, 0)
		vderef(tmp_reg, tmp_reg, V[a])
		src_reg = tmp_reg -- Materialize and dereference it
	-- Source is a value on stack, we must load it first
	elseif type(V[a].const) == 'table' and V[a].const.__base > 0 then
		src_reg = vreg(a)
		emit(BPF.MEM + BPF.LDX + const_width[w], src_reg, 10, -V[a].const.__base, 0)
		V[a].type = V[a].const.__dissector
		V[a].const = nil -- Value is dereferenced
	-- If source is an imm32 number, avoid register load
	elseif type(V[a].const) == 'number' and w < 8 then
		return nil, V[a].const
	-- Load variable from any other source
	else
		src_reg = vreg(a)
	end

	return src_reg, nil
end

-- Emit compensation code at the end of basic block to unify variable set layout on all block exits
-- 1. we need to free registers by spilling
-- 2. fill registers to match other exits from this BB
local function bb_end(Vcomp)
	for i,v in pairs(V) do
		if Vcomp[i] and Vcomp[i].spill and not v.spill then
			-- Materialize constant or shadowing variable to be able to spill
			if not v.reg and (v.shadow or cdef.isimmconst(v)) then
				vreg(i)
			end
			reg_spill(i)
		end
	end
	for i,v in pairs(V) do
		if Vcomp[i] and Vcomp[i].reg and not v.reg then
			vreg(i, Vcomp[i].reg)
		end
		-- Compensate variable metadata change
		if Vcomp[i] and Vcomp[i].source then
			V[i].source = Vcomp[i].source
		end
	end
end

local function CMP_STR(a, b, op)
	assert(op == 'JEQ' or op == 'JNE', 'NYI: only equivallence stack/string only supports == or ~=')
	-- I have no better idea how to implement it than unrolled XOR loop, as we can fixup only one JMP
	-- So: X(a,b) = a[0] ^ b[0] | a[1] ^ b[1] | ...
	--     EQ(a,b) <=> X == 0
	-- This could be optimised by placing early exits by rewriter in second phase for long strings
	local base, size = V[a].const.__base, math.min(#b, ffi.sizeof(V[a].type))
	local acc, tmp = reg_alloc(stackslots, 0), reg_alloc(stackslots+1, 1)
	local sp = 0
	emit(BPF.ALU64 + BPF.MOV + BPF.K, acc, 0, 0, 0)
	while sp < size do
		-- Load string chunk as imm32
		local as_u32 = ffi.new('uint32_t [1]')
		local sub = b:sub(sp+1, sp+ffi.sizeof(as_u32))
		ffi.copy(as_u32, sub, #sub)
		-- TODO: make this faster by interleaved load/compare steps with DW length
		emit(BPF.MEM + BPF.LDX + BPF.W, tmp, 10, -(base-sp), 0)
		emit(BPF.ALU64 + BPF.XOR + BPF.K, tmp, 0, 0, as_u32[0])
		emit(BPF.ALU64 + BPF.OR + BPF.X, acc, tmp, 0, 0)
		sp = sp + ffi.sizeof(as_u32)
	end
	emit(BPF.JMP + BPF[op] + BPF.K, acc, 0, 0xffff, 0)
	code.seen_cmp = code.pc-1
end

local function CMP_REG(a, b, op)
	-- Fold compile-time expressions
	if V[a].const and V[b].const and not (is_proxy(V[a].const) or is_proxy(V[b].const)) then
		code.seen_cmp = const_expr[op](V[a].const, V[b].const) and ALWAYS or NEVER
	else
		-- Comparison against compile-time string or stack memory
		if V[b].const and type(V[b].const) == 'string' then
			return CMP_STR(a, V[b].const, op)
		end
		-- The 0xFFFF target here has no significance, it's just a placeholder for
		-- compiler to replace it's absolute offset to LJ bytecode insn with a relative
		-- offset in BPF program code, verifier will accept only programs with valid JMP targets
		local a_reg, b_reg = vreg(a), vreg(b)
		emit(BPF.JMP + BPF[op] + BPF.X, a_reg, b_reg, 0xffff, 0)
		code.seen_cmp = code.pc-1
	end
end

local function CMP_IMM(a, b, op)
	local c = V[a].const
	if c and not is_proxy(c) then -- Fold compile-time expressions
		code.seen_cmp = const_expr[op](c, b) and ALWAYS or NEVER
	else
		-- Convert imm32 to number
		if type(b) == 'string' then
			if     #b == 1 then b = b:byte()
			elseif cdef.isptr(V[a].type) then
				-- String comparison between stack/constant string
				return CMP_STR(a, b, op)
			elseif #b <= 4 then
				-- Convert to u32 with network byte order
				local imm = ffi.new('uint32_t[1]')
				ffi.copy(imm, b, #b)
				b = builtins.hton(imm[0])
			else error('NYI: compare register with string, where #string > sizeof(u32)') end
		end
		-- The 0xFFFF target here has no significance, it's just a placeholder for
		-- compiler to replace it's absolute offset to LJ bytecode insn with a relative
		-- offset in BPF program code, verifier will accept only programs with valid JMP targets
		local reg = vreg(a)
		emit(BPF.JMP + BPF[op] + BPF.K, reg, 0, 0xffff, b)
		code.seen_cmp = code.pc-1
		-- Remember NULL pointer checks as BPF prohibits pointer comparisons
		-- and repeated checks wouldn't pass the verifier, only comparisons
		-- against constants are checked.
		if op == 'JEQ' and tonumber(b) == 0 and V[a].source then
			local pos = V[a].source:find('_or_null', 1, true)
			if pos then
				code.seen_null_guard = a
			end
		-- Inverse NULL pointer check (if a ~= nil)
		elseif op == 'JNE' and tonumber(b) == 0 and V[a].source then
			local pos = V[a].source:find('_or_null', 1, true)
			if pos then
				code.seen_null_guard = a
				code.seen_null_guard_inverse = true
			end
		end
	end
end

local function ALU_IMM(dst, a, b, op)
	-- Fold compile-time expressions
	if V[a].const and not is_proxy(V[a].const) then
			assert(cdef.isimmconst(V[a]), 'VAR '..a..' must be numeric')
			vset(dst, nil, const_expr[op](V[a].const, b))
	-- Now we need to materialize dissected value at DST, and add it
	else
		vcopy(dst, a)
		local dst_reg = vreg(dst)
		if cdef.isptr(V[a].type) then
			vderef(dst_reg, dst_reg, V[a])
			V[dst].type = V[a].const.__dissector
		else
			V[dst].type = V[a].type
		end
		emit(BPF.ALU64 + BPF[op] + BPF.K, dst_reg, 0, 0, b)
	end
end

local function ALU_REG(dst, a, b, op)
	-- Fold compile-time expressions
	if V[a].const and not (is_proxy(V[a].const) or is_proxy(V[b].const)) then
		assert(cdef.isimmconst(V[a]), 'VAR '..a..' must be numeric')
		assert(cdef.isimmconst(V[b]), 'VAR '..b..' must be numeric')
		if type(op) == 'string' then op = const_expr[op] end
		vcopy(dst, a)
		V[dst].const = op(V[a].const, V[b].const)
	else
		local src_reg = b and vreg(b) or 0 -- SRC is optional for unary operations
		if b and cdef.isptr(V[b].type) then
			-- We have to allocate a temporary register for dereferencing to preserve
			-- pointer in source variable that MUST NOT be altered
			reg_alloc(stackslots, 2)
			vderef(2, src_reg, V[b])
			src_reg = 2
		end
		vcopy(dst, a) -- DST may alias B, so copy must occur after we materialize B
		local dst_reg = vreg(dst)
		if cdef.isptr(V[a].type) then
			vderef(dst_reg, dst_reg, V[a])
			V[dst].type = V[a].const.__dissector
		end
		emit(BPF.ALU64 + BPF[op] + BPF.X, dst_reg, src_reg, 0, 0)
		V[stackslots].reg = nil  -- Free temporary registers
	end
end

local function ALU_IMM_NV(dst, a, b, op)
	-- Do DST = IMM(a) op VAR(b) where we can't invert because
	-- the registers are u64 but immediates are u32, so complement
	-- arithmetics wouldn't work
	vset(stackslots+1, nil, a)
	ALU_REG(dst, stackslots+1, b, op)
end

local function LD_ABS(dst, w, off)
	assert(off, 'LD_ABS called without offset')
	if w < 8 then
		local dst_reg = vreg(dst, 0, true, builtins.width_type(w)) -- Reserve R0
		emit(BPF.LD + BPF.ABS + const_width[w], dst_reg, 0, 0, off)
		if w > 1 and ffi.abi('le') then -- LD_ABS has htonl() semantics, reverse
			emit(BPF.ALU + BPF.END + BPF.TO_BE, dst_reg, 0, 0, w * 8)
		end
	elseif w == 8 then
		-- LD_ABS|IND prohibits DW, we need to do two W loads and combine them
		local tmp_reg = vreg(stackslots, 0, true, builtins.width_type(w)) -- Reserve R0
		emit(BPF.LD + BPF.ABS + const_width[4], tmp_reg, 0, 0, off + 4)
		if ffi.abi('le') then -- LD_ABS has htonl() semantics, reverse
			emit(BPF.ALU + BPF.END + BPF.TO_BE, tmp_reg, 0, 0, 32)
		end
		ALU_IMM(stackslots, stackslots, 32, 'LSH')
		local dst_reg = vreg(dst, 0, true, builtins.width_type(w)) -- Reserve R0, spill tmp variable
		emit(BPF.LD + BPF.ABS + const_width[4], dst_reg, 0, 0, off)
		if ffi.abi('le') then -- LD_ABS has htonl() semantics, reverse
			emit(BPF.ALU + BPF.END + BPF.TO_BE, dst_reg, 0, 0, 32)
		end
		ALU_REG(dst, dst, stackslots, 'OR')
		V[stackslots].reg = nil -- Free temporary registers
	else
		assert(w < 8, 'NYI: only LD_ABS of 1/2/4/8 is supported')
	end
end

local function LD_IND(dst, src, w, off)
	local src_reg = vreg(src) -- Must materialize first in case dst == src
	local dst_reg = vreg(dst, 0, true, builtins.width_type(w)) -- Reserve R0
	emit(BPF.LD + BPF.IND + const_width[w], dst_reg, src_reg, 0, off or 0)
	if w > 1 and ffi.abi('le') then -- LD_ABS has htonl() semantics, reverse
		emit(BPF.ALU + BPF.END + BPF.TO_BE, dst_reg, 0, 0, w * 8)
	end
end

local function LD_MEM(dst, src, w, off)
	local src_reg = vreg(src) -- Must materialize first in case dst == src
	local dst_reg = vreg(dst, nil, true, builtins.width_type(w)) -- Reserve R0
	emit(BPF.MEM + BPF.LDX + const_width[w], dst_reg, src_reg, off or 0, 0)
end

-- @note: This is specific now as it expects registers reserved
local function LD_IMM_X(dst_reg, src_type, imm, w)
	if w == 8 then -- IMM64 must be done in two instructions with imm64 = (lo(imm32), hi(imm32))
		emit(BPF.LD + const_width[w], dst_reg, src_type, 0, ffi.cast('uint32_t', imm))
		-- Must shift in two steps as bit.lshift supports [0..31]
		emit(0, 0, 0, 0, ffi.cast('uint32_t', bit.lshift(bit.lshift(imm, 16), 16)))
	else
		emit(BPF.LD + const_width[w], dst_reg, src_type, 0, imm)
	end
end

local function BUILTIN(func, ...)
	local builtin_export = {
		-- Compiler primitives (work with variable slots, emit instructions)
		V=V, vreg=vreg, vset=vset, vcopy=vcopy, vderef=vderef, valloc=valloc, emit=emit,
		reg_alloc=reg_alloc, reg_spill=reg_spill, tmpvar=stackslots, const_width=const_width,
		-- Extensions and helpers (use with care)
		LD_IMM_X = LD_IMM_X,
	}
	func(builtin_export, ...)
end

local function LOAD(dst, src, off, vtype)
	local base = V[src].const
	assert(base and base.__dissector, 'NYI: load() on variable that doesn\'t have dissector')
	assert(V[src].source, 'NYI: load() on variable with unknown source')
	-- Cast to different type if requested
	vtype = vtype or base.__dissector
	local w = ffi.sizeof(vtype)
	assert(const_width[w], 'NYI: load() supports 1/2/4/8 bytes at a time only, wanted ' .. tostring(w))
	-- Packet access with a dissector (use BPF_LD)
	if V[src].source:find('ptr_to_pkt', 1, true) then
		if base.off then -- Absolute address to payload
			LD_ABS(dst, w, off + base.off)
		else -- Indirect address to payload
			LD_IND(dst, src, w, off)
		end
	-- Direct access to first argument (skb fields, pt regs, ...)
	elseif V[src].source:find('ptr_to_ctx', 1, true) then
		LD_MEM(dst, src, w, off)
	-- Direct skb access with a dissector (use BPF_MEM)
	elseif V[src].source:find('ptr_to_skb', 1, true) then
		LD_MEM(dst, src, w, off)
	-- Pointer to map-backed memory (use BPF_MEM)
	elseif V[src].source:find('ptr_to_map_value', 1, true) then
		LD_MEM(dst, src, w, off)
	-- Indirect read using probe (uprobe or kprobe, uses helper)
	elseif V[src].source:find('ptr_to_probe', 1, true) then
		BUILTIN(builtins[builtins.probe_read], nil, dst, src, vtype, off)
		V[dst].source = V[src].source -- Builtin handles everything
	else
		error('NYI: load() on variable from ' .. V[src].source)
	end
	V[dst].type = vtype
	V[dst].const = nil -- Dissected value is not constant anymore
end

local function CALL(a, b, d)
	assert(b-1 <= 1, 'NYI: CALL with >1 return values')
	-- Perform either compile-time, helper, or builtin
	local func = V[a].const
	-- Gather all arguments and check if they're constant
	local args, const, nargs = {}, true, d - 1
	for i = a+1, a+d-1 do
		table.insert(args, V[i].const)
		if not V[i].const or is_proxy(V[i].const) then const = false end
	end
	local builtin = builtins[func]
	if not const or nargs == 0 then
		if builtin and type(builtin) == 'function' then
			args = {a}
			for i = a+1, a+nargs do table.insert(args, i) end
			BUILTIN(builtin, unpack(args))
		elseif V[a+2] and V[a+2].const then -- var OP imm
			ALU_IMM(a, a+1, V[a+2].const, builtin)
		elseif nargs <= 2 then              -- var OP var
			ALU_REG(a, a+1, V[a+2] and a+2, builtin)
		else
			error('NYI: CALL non-builtin with 3 or more arguments')
		end
	-- Call on dissector implies slice retrieval
	elseif type(func) == 'table' and func.__dissector then
		assert(nargs >= 2, 'NYI: <dissector>.slice(a, b) must have at least two arguments')
		assert(V[a+1].const and V[a+2].const, 'NYI: slice() arguments must be constant')
		local off = V[a+1].const
		local vtype = builtins.width_type(V[a+2].const - off)
		-- Access to packet via packet (use BPF_LD)
		if V[a].source and V[a].source:find('ptr_to_', 1, true) then
			LOAD(a, a, off, vtype)
		else
			error('NYI: <dissector>.slice(a, b) on non-pointer memory ' .. (V[a].source or 'unknown'))
		end
	-- Strict builtins cannot be expanded on compile-time
	elseif builtins_strict[func] and builtin then
		args = {a}
		for i = a+1, a+nargs do table.insert(args, i) end
		BUILTIN(builtin, unpack(args))
	-- Attempt compile-time call expansion (expects all argument compile-time known)
	else
		assert(const, 'NYI: CALL attempted on constant arguments, but at least one argument is not constant')
		V[a].const = func(unpack(args))
	end
end

local function MAP_INIT(map_var, key, imm)
	local map = V[map_var].const
	vreg(map_var, 1, true, ffi.typeof('uint64_t'))
	-- Reserve R1 and load ptr for process-local map fd
	LD_IMM_X(1, BPF.PSEUDO_MAP_FD, map.fd, ffi.sizeof(V[map_var].type))
	V[map_var].reg = nil -- R1 will be invalidated after CALL, forget register allocation
	-- Reserve R2 and load R2 = key pointer
	local key_size = ffi.sizeof(map.key_type)
	local w = const_width[key_size] or BPF.DW
	local pod_type = const_width[key_size]
	local sp = stack_top + key_size -- Must use stack below spill slots
	-- Store immediate value on stack
	reg_alloc(stackslots, 2) -- Spill anything in R2 (unnamed tmp variable)
	local key_base = key and V[key].const
	imm = imm or key_base
	if imm and (not key or not is_proxy(key_base)) then
		assert(pod_type, 'NYI: map[const K], K width must be 1/2/4/8')
		emit(BPF.MEM + BPF.ST + w, 10, 0, -sp, imm)
	-- Key is in register, spill it
	elseif V[key].reg and pod_type then
		if cdef.isptr(V[key].type) then
			-- There is already pointer in register, dereference before spilling
			emit(BPF.MEM + BPF.LDX + w, 2, V[key].reg, 0, 0)
			emit(BPF.MEM + BPF.STX + w, 10, 2, -sp, 0)
		else -- Variable in register is POD, spill it on the stack
			emit(BPF.MEM + BPF.STX + w, 10, V[key].reg, -sp, 0)
		end
	-- Key is spilled from register to stack
	elseif V[key].spill then
		sp = V[key].spill
	-- Key is already on stack, write to base-relative address
	elseif key_base.__base then
		assert(key_size == ffi.sizeof(V[key].type), 'VAR '..key..' type incompatible with BPF map key type')
		sp = key_base.__base
	else
		error('VAR '..key..' is neither const-expr/register/stack/spilled')
	end
	-- If [FP+K] addressing, emit it
	if sp then
		emit(BPF.ALU64 + BPF.MOV + BPF.X, 2, 10, 0, 0)
		emit(BPF.ALU64 + BPF.ADD + BPF.K, 2, 0, 0, -sp)
	end
end

local function MAP_GET(dst, map_var, key, imm)
	local map = V[map_var].const
	MAP_INIT(map_var, key, imm)
	-- Flag as pointer type and associate dissector for map value type
	vreg(dst, 0, true, ffi.typeof('uint8_t *'))
	V[dst].const = {__dissector=map.val_type}
	V[dst].source = 'ptr_to_map_value_or_null'
	emit(BPF.JMP + BPF.CALL, 0, 0, 0, HELPER.map_lookup_elem)
	V[stackslots].reg = nil -- Free temporary registers
end

local function MAP_DEL(map_var, key, key_imm)
	-- Set R0, R1 (map fd, preempt R0)
	reg_alloc(stackslots, 0) -- Spill anything in R0 (unnamed tmp variable)
	MAP_INIT(map_var, key, key_imm)
	emit(BPF.JMP + BPF.CALL, 0, 0, 0, HELPER.map_delete_elem)
	V[stackslots].reg = nil -- Free temporary registers
end

local function MAP_SET(map_var, key, key_imm, src)
	local map = V[map_var].const
	-- Delete when setting nil
	if V[src].type == ffi.typeof('void') then
		return MAP_DEL(map_var, key, key_imm)
	end
	-- Set R0, R1 (map fd, preempt R0)
	reg_alloc(stackslots, 0) -- Spill anything in R0 (unnamed tmp variable)
	MAP_INIT(map_var, key, key_imm)
	reg_alloc(stackslots, 4) -- Spill anything in R4 (unnamed tmp variable)
	emit(BPF.ALU64 + BPF.MOV + BPF.K, 4, 0, 0, 0) -- BPF_ANY, create new element or update existing
	-- Reserve R3 for value pointer
	reg_alloc(stackslots, 3) -- Spill anything in R3 (unnamed tmp variable)
	local val_size = ffi.sizeof(map.val_type)
	local w = const_width[val_size] or BPF.DW
	local pod_type = const_width[val_size]
	-- Stack pointer must be aligned to both key/value size and have enough headroom for (key, value)
	local sp = stack_top + ffi.sizeof(map.key_type) + val_size
	sp = sp + (sp % val_size)
	local base = V[src].const
	if base and not is_proxy(base) then
		assert(pod_type, 'NYI: MAP[K] = imm V; V width must be 1/2/4/8')
		emit(BPF.MEM + BPF.ST + w, 10, 0, -sp, base)
	-- Value is in register, spill it
	elseif V[src].reg and pod_type then
		-- Value is a pointer, derefernce it and spill it
		if cdef.isptr(V[src].type) then
			vderef(3, V[src].reg, V[src])
			emit(BPF.MEM + BPF.STX + w, 10, 3, -sp, 0)
		else
			emit(BPF.MEM + BPF.STX + w, 10, V[src].reg, -sp, 0)
		end
	-- We get a pointer to spilled register on stack
	elseif V[src].spill then
		-- If variable is a pointer, we can load it to R3 directly (save "LEA")
		if cdef.isptr(V[src].type) then
			reg_fill(src, 3)
			-- If variable is a stack pointer, we don't have to check it
			if base.__base then
				emit(BPF.JMP + BPF.CALL, 0, 0, 0, HELPER.map_update_elem)
				return
			end
			vderef(3, V[src].reg, V[src])
			emit(BPF.MEM + BPF.STX + w, 10, 3, -sp, 0)
		else
			sp = V[src].spill
		end
	-- Value is already on stack, write to base-relative address
	elseif base.__base then
		if val_size ~= ffi.sizeof(V[src].type) then
			local err = string.format('VAR %d type (%s) incompatible with BPF map value type (%s): expected %d, got %d',
				src, V[src].type, map.val_type, val_size, ffi.sizeof(V[src].type))
			error(err)
		end
		sp = base.__base
	-- Value is constant, materialize it on stack
	else
		error('VAR '.. src ..' is neither const-expr/register/stack/spilled')
	end
	emit(BPF.ALU64 + BPF.MOV + BPF.X, 3, 10, 0, 0)
	emit(BPF.ALU64 + BPF.ADD + BPF.K, 3, 0, 0, -sp)
	emit(BPF.JMP + BPF.CALL, 0, 0, 0, HELPER.map_update_elem)
	V[stackslots].reg = nil -- Free temporary registers
end

-- Finally - this table translates LuaJIT bytecode into code emitter actions.
local BC = {
	-- Constants
	KNUM = function(a, _, c, _) -- KNUM
		if c < 2147483648 then
			vset(a, nil, c, ffi.typeof('int32_t'))
		else
			vset(a, nil, c, ffi.typeof('uint64_t'))
		end
	end,
	KSHORT = function(a, _, _, d) -- KSHORT
		vset(a, nil, d, ffi.typeof('int16_t'))
	end,
	KCDATA = function(a, _, c, _) -- KCDATA
		-- Coerce numeric types if possible
		local ct = ffi.typeof(c)
		if ffi.istype(ct, ffi.typeof('uint64_t')) or ffi.istype(ct, ffi.typeof('int64_t')) then
			vset(a, nil, c, ct)
		elseif tonumber(c) ~= nil then
			-- TODO: this should not be possible
			vset(a, nil, tonumber(c), ct)
		else
			error('NYI: cannot use CDATA constant of type ' .. ct)
		end
	end,
	KPRI = function(a, _, _, d) -- KPRI
		-- KNIL is 0, must create a special type to identify it
		local vtype = (d < 1) and ffi.typeof('void') or ffi.typeof('uint8_t')
		vset(a, nil, (d < 2) and 0 or 1, vtype)
	end,
	KSTR = function(a, _, c, _) -- KSTR
		vset(a, nil, c, ffi.typeof('const char[?]'))
	end,
	MOV = function(a, _, _, d) -- MOV var, var
		vcopy(a, d)
	end,

	-- Comparison ops
	-- Note: comparisons are always followed by JMP opcode, that
	--       will fuse following JMP to JMP+CMP instruction in BPF
	-- Note:  we're narrowed to integers, so operand/operator inversion is legit
	ISLT = function(a, _, _, d) return CMP_REG(d, a, 'JGE') end, -- (a < d) (inverted)
	ISGE = function(a, _, _, d) return CMP_REG(a, d, 'JGE') end, -- (a >= d)
	ISGT = function(a, _, _, d) return CMP_REG(a, d, 'JGT') end, -- (a > d)
	ISEQV = function(a, _, _, d) return CMP_REG(a, d, 'JEQ') end, -- (a == d)
	ISNEV = function(a, _, _, d) return CMP_REG(a, d, 'JNE') end, -- (a ~= d)
	ISEQS = function(a, _, c, _) return CMP_IMM(a, c, 'JEQ') end, -- (a == str(c))
	ISNES = function(a, _, c, _) return CMP_IMM(a, c, 'JNE') end, -- (a ~= str(c))
	ISEQN = function(a, _, c, _) return CMP_IMM(a, c, 'JEQ') end, -- (a == c)
	ISNEN = function(a, _, c, _) return CMP_IMM(a, c, 'JNE') end, -- (a ~= c)
	IST = function(_, _, _, d) return CMP_IMM(d, 0, 'JNE') end, -- (d)
	ISF = function(_, _, _, d) return CMP_IMM(d, 0, 'JEQ') end, -- (not d)
	ISEQP = function(a, _, c, _) return CMP_IMM(a, c, 'JEQ') end, -- ISEQP (a == c)
	-- Binary operations with RHS constants
	ADDVN = function(a, b, c, _) return ALU_IMM(a, b, c, 'ADD') end,
	SUBVN = function(a, b, c, _) return ALU_IMM(a, b, c, 'SUB') end,
	MULVN = function(a, b, c, _) return ALU_IMM(a, b, c, 'MUL') end,
	DIVVN = function(a, b, c, _) return ALU_IMM(a, b, c, 'DIV') end,
	MODVN = function(a, b, c, _) return ALU_IMM(a, b, c, 'MOD') end,
	-- Binary operations with LHS constants
	-- Cheat code: we're narrowed to integer arithmetic, so MUL+ADD are commutative
	ADDNV = function(a, b, c, _) return ALU_IMM(a, b, c, 'ADD') end, -- ADDNV
	MULNV = function(a, b, c, _) return ALU_IMM(a, b, c, 'MUL') end, -- MULNV
	SUBNV = function(a, b, c, _) return ALU_IMM_NV(a, c, b, 'SUB') end, -- SUBNV
	DIVNV = function(a, b, c, _) return ALU_IMM_NV(a, c, b, 'DIV') end, -- DIVNV
	-- Binary operations between registers
	ADDVV = function(a, b, _, d) return ALU_REG(a, b, d, 'ADD') end,
	SUBVV = function(a, b, _, d) return ALU_REG(a, b, d, 'SUB') end,
	MULVV = function(a, b, _, d) return ALU_REG(a, b, d, 'MUL') end,
	DIVVV = function(a, b, _, d) return ALU_REG(a, b, d, 'DIV') end,
	MODVV = function(a, b, _, d) return ALU_REG(a, b, d, 'MOD') end,
	-- Strings
	CAT = function(a, b, _, d) -- CAT A = B ~ D
		assert(V[b].const and V[d].const, 'NYI: CAT only works on compile-time expressions')
		assert(type(V[b].const) == 'string' and type(V[d].const) == 'string',
			'NYI: CAT only works on compile-time strings')
		vset(a, nil, V[b].const .. V[d].const)
	end,
	-- Tables
	GGET = function (a, _, c, _) -- GGET (A = GLOBAL[c])
		if env[c] ~= nil then
			vset(a, nil, env[c])
		else error(string.format("undefined global '%s'", c)) end
	end,
	UGET = function (a, _, c, _) -- UGET (A = UPVALUE[c])
		if env[c] ~= nil then
			vset(a, nil, env[c])
		else error(string.format("undefined upvalue '%s'", c)) end
	end,
	TSETB = function (a, b, _, d) -- TSETB (B[D] = A)
		assert(V[b] and type(V[b].const) == 'table', 'NYI: B[D] where B is not Lua table, BPF map, or pointer')
		local vinfo = V[b].const
		if vinfo.__map then -- BPF map read (constant)
			return MAP_SET(b, nil, d, a) -- D is literal
		elseif vinfo.__dissector then
			assert(vinfo.__dissector, 'NYI: B[D] where B does not have a known element size')
			local w = ffi.sizeof(vinfo.__dissector)
			-- TODO: support vectorized moves larger than register width
			assert(const_width[w], 'B[C] = A, sizeof(A) must be 1/2/4/8')
			local src_reg, const = vscalar(a, w)
			-- If changing map value, write to absolute address + offset
			if V[b].source and V[b].source:find('ptr_to_map_value', 1, true) then
				local dst_reg = vreg(b)
				-- Optimization: immediate values (imm32) can be stored directly
				if type(const) == 'number' then
					emit(BPF.MEM + BPF.ST + const_width[w], dst_reg, 0, d, const)
				else
					emit(BPF.MEM + BPF.STX + const_width[w], dst_reg, src_reg, d, 0)
				end
			-- Table is already on stack, write to vinfo-relative address
			elseif vinfo.__base then
				-- Optimization: immediate values (imm32) can be stored directly
				if type(const) == 'number' then
					emit(BPF.MEM + BPF.ST + const_width[w], 10, 0, -vinfo.__base + (d * w), const)
				else
					emit(BPF.MEM + BPF.STX + const_width[w], 10, src_reg, -vinfo.__base + (d * w), 0)
				end
			else
				error('NYI: B[D] where B is not Lua table, BPF map, or pointer')
			end
		elseif vinfo and vinfo and V[a].const then
			vinfo[V[d].const] = V[a].const
		else
			error('NYI: B[D] where B is not Lua table, BPF map, or pointer')
		end
	end,
	TSETV = function (a, b, _, d) -- TSETV (B[D] = A)
		assert(V[b] and type(V[b].const) == 'table', 'NYI: B[D] where B is not Lua table, BPF map, or pointer')
		local vinfo = V[b].const
		if vinfo.__map then -- BPF map read (constant)
			return MAP_SET(b, d, nil, a) -- D is variable
		elseif vinfo.__dissector then
			assert(vinfo.__dissector, 'NYI: B[D] where B does not have a known element size')
			local w = ffi.sizeof(vinfo.__dissector)
			-- TODO: support vectorized moves larger than register width
			assert(const_width[w], 'B[C] = A, sizeof(A) must be 1/2/4/8')
			local src_reg, const = vscalar(a, w)
			-- If changing map value, write to absolute address + offset
			if V[b].source and V[b].source:find('ptr_to_map_value', 1, true) then
				-- Calculate variable address from two registers
				local tmp_var = stackslots + 1
				vset(tmp_var, nil, d)
				ALU_REG(tmp_var, tmp_var, b, 'ADD')
				local dst_reg = vreg(tmp_var)
				V[tmp_var].reg = nil -- Only temporary allocation
				-- Optimization: immediate values (imm32) can be stored directly
				if type(const) == 'number' and w < 8 then
					emit(BPF.MEM + BPF.ST + const_width[w], dst_reg, 0, 0, const)
				else
					emit(BPF.MEM + BPF.STX + const_width[w], dst_reg, src_reg, 0, 0)
				end
			-- Table is already on stack, write to vinfo-relative address
			elseif vinfo.__base then
				-- Calculate variable address from two registers
				local tmp_var = stackslots + 1
				vcopy(tmp_var, d)                       -- Element position
				if w > 1 then
					ALU_IMM(tmp_var, tmp_var, w, 'MUL') -- multiply by element size
				end
				local dst_reg = vreg(tmp_var)           -- add R10 (stack pointer)
				emit(BPF.ALU64 + BPF.ADD + BPF.X, dst_reg, 10, 0, 0)
				V[tmp_var].reg = nil -- Only temporary allocation
				-- Optimization: immediate values (imm32) can be stored directly
				if type(const) == 'number' and w < 8 then
					emit(BPF.MEM + BPF.ST + const_width[w], dst_reg, 0, -vinfo.__base, const)
				else
					emit(BPF.MEM + BPF.STX + const_width[w], dst_reg, src_reg, -vinfo.__base, 0)
				end
			else
				error('NYI: B[D] where B is not Lua table, BPF map, or pointer')
			end
		elseif vinfo and V[d].const and V[a].const then
			vinfo[V[d].const] = V[a].const
		else
			error('NYI: B[D] where B is not Lua table, BPF map, or pointer')
		end
	end,
	TSETS = function (a, b, c, _) -- TSETS (B[C] = A)
		assert(V[b] and V[b].const, 'NYI: B[D] where B is not Lua table, BPF map, or pointer')
		local base = V[b].const
		if base.__dissector then
			local ofs,bpos = ffi.offsetof(base.__dissector, c)
			assert(not bpos, 'NYI: B[C] = A, where C is a bitfield')
			local w = builtins.sizeofattr(base.__dissector, c)
			-- TODO: support vectorized moves larger than register width
			assert(const_width[w], 'B[C] = A, sizeof(A) must be 1/2/4/8')
			local src_reg, const = vscalar(a, w)
			-- If changing map value, write to absolute address + offset
			if V[b].source and V[b].source:find('ptr_to_map_value', 1, true) then
				local dst_reg = vreg(b)
				-- Optimization: immediate values (imm32) can be stored directly
				if type(const) == 'number' and w < 8 then
					emit(BPF.MEM + BPF.ST + const_width[w], dst_reg, 0, ofs, const)
				else
					emit(BPF.MEM + BPF.STX + const_width[w], dst_reg, src_reg, ofs, 0)
				end
			-- Table is already on stack, write to base-relative address
			elseif base.__base then
				-- Optimization: immediate values (imm32) can be stored directly
				if type(const) == 'number' and w < 8 then
					emit(BPF.MEM + BPF.ST + const_width[w], 10, 0, -base.__base + ofs, const)
				else
					emit(BPF.MEM + BPF.STX + const_width[w], 10, src_reg, -base.__base + ofs, 0)
				end
			else
				error('NYI: B[C] where B is not Lua table, BPF map, or pointer')
			end
		elseif V[a].const then
			base[c] = V[a].const
		else
			error('NYI: B[C] where B is not Lua table, BPF map, or pointer')
		end
	end,
	TGETB = function (a, b, _, d) -- TGETB (A = B[D])
		local base = V[b].const
		assert(type(base) == 'table', 'NYI: B[C] where C is string and B not Lua table or BPF map')
		if a ~= b then vset(a) end
		if base.__map then -- BPF map read (constant)
			MAP_GET(a, b, nil, d)
		-- Pointer access with a dissector (traditional uses BPF_LD, direct uses BPF_MEM)
		elseif V[b].source and V[b].source:find('ptr_to_') then
			local vtype = base.__dissector and base.__dissector or ffi.typeof('uint8_t')
			LOAD(a, b, d, vtype)
		-- Specialise PTR[0] as dereference operator
		elseif cdef.isptr(V[b].type) and d == 0 then
			vcopy(a, b)
			local dst_reg = vreg(a)
			vderef(dst_reg, dst_reg, V[a])
			V[a].type = V[a].const.__dissector
		else
			error('NYI: A = B[D], where B is not Lua table or packet dissector or pointer dereference')
		end
	end,
	TGETV = function (a, b, _, d) -- TGETV (A = B[D])
		local base = V[b].const
		assert(type(base) == 'table', 'NYI: B[C] where C is string and B not Lua table or BPF map')
		if a ~= b then vset(a) end
		if base.__map then -- BPF map read
			MAP_GET(a, b, d)
		-- Pointer access with a dissector (traditional uses BPF_LD, direct uses BPF_MEM)
		elseif V[b].source and V[b].source:find('ptr_to_') then
			local vtype = base.__dissector and base.__dissector or ffi.typeof('uint8_t')
			LOAD(a, b, d, vtype)
		-- Constant dereference
		elseif type(V[d].const) == 'number' then
			V[a].const = base[V[d].const]
		else
			error('NYI: A = B[D], where B is not Lua table or packet dissector or pointer dereference')
		end
	end,
	TGETS = function (a, b, c, _) -- TGETS (A = B[C])
		local base = V[b].const
		assert(type(base) == 'table', 'NYI: B[C] where C is string and B not Lua table or BPF map')
		if a ~= b then vset(a) end
		if base.__dissector then
			local ofs,bpos,bsize = ffi.offsetof(base.__dissector, c)
			-- Resolve table key using metatable
			if not ofs and type(base.__dissector[c]) == 'string' then
				c = base.__dissector[c]
				ofs,bpos,bsize = ffi.offsetof(base.__dissector, c)
			end
			if not ofs and proto[c] then -- Load new dissector on given offset
				BUILTIN(proto[c], a, b, c)
			else
				-- Loading register from offset is a little bit tricky as there are
				-- several data sources and value loading modes with different restrictions
				-- such as checking pointer values for NULL compared to using stack.
				assert(ofs, tostring(base.__dissector)..'.'..c..' attribute not exists')
				if a ~= b then vset(a) end
				-- Dissected value is probably not constant anymore
				local new_const = nil
				local w, atype = builtins.sizeofattr(base.__dissector, c)
				-- [SP+K] addressing using R10 (stack pointer)
				-- Doesn't need to be checked for NULL
				if base.__base and base.__base > 0 then
					if cdef.isptr(atype) then -- If the member is pointer type, update base pointer with offset
						new_const = {__base = base.__base-ofs}
					else
						local dst_reg = vreg(a, nil, true)
						emit(BPF.MEM + BPF.LDX + const_width[w], dst_reg, 10, -base.__base+ofs, 0)
					end
				-- Pointer access with a dissector (traditional uses BPF_LD, direct uses BPF_MEM)
				elseif V[b].source and V[b].source:find('ptr_to_') then
					LOAD(a, b, ofs, atype)
				else
					error('NYI: B[C] where B is not Lua table, BPF map, or pointer')
				end
				-- Bitfield, must be further narrowed with a bitmask/shift
				if bpos then
					local mask = 0
					for i=bpos+1,bpos+bsize do
						mask = bit.bor(mask, bit.lshift(1, w*8-i))
					end
					emit(BPF.ALU64 + BPF.AND + BPF.K, vreg(a), 0, 0, mask)
					-- Free optimization: single-bit values need just boolean result
					if bsize > 1 then
						local shift = w*8-bsize-bpos
						if shift > 0 then
							emit(BPF.ALU64 + BPF.RSH + BPF.K, vreg(a), 0, 0, shift)
						end
					end
				end
				V[a].type = atype
				V[a].const = new_const
				V[a].source = V[b].source
				-- Track direct access to skb data
				-- see https://www.kernel.org/doc/Documentation/networking/filter.txt "Direct packet access"
				if ffi.istype(base.__dissector, ffi.typeof('struct sk_buff')) then
					-- Direct access to skb uses skb->data and skb->data_end
					-- which are encoded as u32, but are actually pointers
					if c == 'data' or c == 'data_end' then
						V[a].const = {__dissector = ffi.typeof('uint8_t')}
						V[a].source = 'ptr_to_skb'
					end
				end
			end
		else
			V[a].const = base[c]
		end
	end,
	-- Loops and branches
	CALLM = function (a, b, _, d) -- A = A(A+1, ..., A+D+MULTRES)
		-- NYI: Support single result only
		CALL(a, b, d+2)
	end,
	CALL = function (a, b, _, d) -- A = A(A+1, ..., A+D-1)
		CALL(a, b, d)
	end,
	JMP = function (a, _, c, _) -- JMP
		-- Discard unused slots after jump
		for i, _ in pairs(V) do
			if i >= a and i < stackslots then
				V[i] = nil
			end
		end
		-- Cross basic block boundary if the jump target isn't provably unreachable
		local val = code.fixup[c] or {}
		if code.seen_cmp and code.seen_cmp ~= ALWAYS then
			if code.seen_cmp ~= NEVER then -- Do not emit the jump or fixup
				-- Store previous CMP insn for reemitting after compensation code
				local jmpi = ffi.new('struct bpf_insn', code.insn[code.pc-1])
				code.pc = code.pc - 1
				-- First branch point, emit compensation code
				local Vcomp = Vstate[c]
				if not Vcomp then
					-- Select scratch register (R0-5) that isn't used as operand
					-- in the CMP instruction, as the variable may not be live, after
					-- the JMP, but it may be used in the JMP+CMP instruction itself
					local tmp_reg = 0
					for reg = 0, 5 do
						if reg ~= jmpi.dst_reg and reg ~= jmpi.src_reg then
							tmp_reg = reg
							break
						end
					end
					-- Force materialization of constants at the end of BB
					for i, v in pairs(V) do
						if not v.reg and cdef.isimmconst(v) then
							vreg(i, tmp_reg) -- Load to TMP register (not saved)
							reg_spill(i) -- Spill caller-saved registers
						end
					end
					-- Record variable state
					Vstate[c] = V
					Vcomp = V
					V = table_copy(V)
				-- Variable state already set, emit specific compensation code
				else
					bb_end(Vcomp)
				end
				-- Record pointer NULL check from condition
				-- If the condition checks pointer variable against NULL,
				-- we can assume it will not be NULL in the fall-through block
				if code.seen_null_guard then
					local var = code.seen_null_guard
					-- The null guard can have two forms:
					--   if x == nil then goto
					--   if x ~= nil then goto
					-- First form guarantees that the variable will be non-nil on the following instruction
					-- Second form guarantees that the variable will be non-nil at the jump target
					local vinfo = code.seen_null_guard_inverse and Vcomp[var] or V[var]
					if vinfo.source then
						local pos = vinfo.source:find('_or_null', 1, true)
						if pos then
							vinfo.source = vinfo.source:sub(1, pos - 1)
						end
					end
				end
				-- Reemit CMP insn
				emit(jmpi.code, jmpi.dst_reg, jmpi.src_reg, jmpi.off, jmpi.imm)
				-- Fuse JMP into previous CMP opcode, mark JMP target for fixup
				-- as we don't knot the relative offset in generated code yet
				table.insert(val, code.pc-1)
				code.fixup[c] = val
			end
			code.seen_cmp = nil
			code.seen_null_guard = nil
			code.seen_null_guard_inverse = nil
		elseif c == code.bc_pc + 1 then -- luacheck: ignore 542
			-- Eliminate jumps to next immediate instruction
			-- e.g. 0002    JMP      1 => 0003
		else
			-- We need to synthesise a condition that's always true, however
			-- BPF prohibits pointer arithmetic to prevent pointer leaks
			-- so we have to clear out one register and use it for cmp that's always true
			local dst_reg = reg_alloc(stackslots)
			V[stackslots].reg = nil -- Only temporary allocation
			-- First branch point, emit compensation code
			local Vcomp = Vstate[c]
			if not Vcomp then
				-- Force materialization of constants at the end of BB
				for i, v in pairs(V) do
					if not v.reg and cdef.isimmconst(v) then
						vreg(i, dst_reg) -- Load to TMP register (not saved)
						reg_spill(i) -- Spill caller-saved registers
					end
				end
				-- Record variable state
				Vstate[c] = V
				V = table_copy(V)
			-- Variable state already set, emit specific compensation code
			else
				bb_end(Vcomp)
			end
			emit(BPF.ALU64 + BPF.MOV + BPF.K, dst_reg, 0, 0, 0)
			emit(BPF.JMP + BPF.JEQ + BPF.K, dst_reg, 0, 0xffff, 0)
			table.insert(val, code.pc-1) -- Fixup JMP target
			code.reachable = false -- Code following the JMP is not reachable
			code.fixup[c] = val
		end
	end,
	RET1 = function (a, _, _, _) -- RET1
		-- Free optimisation: spilled variable will not be filled again
		for i, v in pairs(V) do
			if i ~= a then v.reg = nil end
		end
		if V[a].reg ~= 0 then vreg(a, 0) end
		-- Convenience: dereference pointer variables
		-- e.g. 'return map[k]' will return actual map value, not pointer
		if cdef.isptr(V[a].type) then
			vderef(0, 0, V[a])
		end
		emit(BPF.JMP + BPF.EXIT, 0, 0, 0, 0)
		code.reachable = false
	end,
	RET0 = function (_, _, _, _) -- RET0
		emit(BPF.ALU64 + BPF.MOV + BPF.K, 0, 0, 0, 0)
		emit(BPF.JMP + BPF.EXIT, 0, 0, 0, 0)
		code.reachable = false
	end,
	compile = function ()
		return code
	end
}

-- Composite instructions
function BC.CALLT(a, _, _, d) -- Tailcall: return A(A+1, ..., A+D-1)
	CALL(a, 1, d)
	BC.RET1(a)
end

-- Always initialize R6 with R1 context
emit(BPF.ALU64 + BPF.MOV + BPF.X, 6, 1, 0, 0)
-- Register R6 as context variable (first argument)
if params and params > 0 then
	vset(0, 6, param_types[1] or proto.skb)
	assert(V[0].source == V[0].const.source) -- Propagate source annotation from typeinfo
end
-- Register tmpvars
vset(stackslots)
vset(stackslots+1)
return setmetatable(BC, {
	__index = function (_, k, _)
		if type(k) == 'number' then
			local op_str = string.sub(require('jit.vmdef').bcnames, 6*k+1, 6*k+6)
			error(string.format("NYI: opcode '0x%02x' (%-04s)", k, op_str))
		end
	end,
	__call = function (t, op, a, b, c, d)
		code.bc_pc = code.bc_pc + 1
		-- Exitting BB straight through, emit compensation code
		if Vstate[code.bc_pc] then
			if code.reachable then
				-- Instruction is reachable from previous line
				-- so we must make the variable allocation consistent
				-- with the variable allocation at the jump source
				-- e.g. 0001 x:R0 = 5
				--      0002 if rand() then goto 0005
				--      0003 x:R0 -> x:stack
				--      0004 y:R0 = 5
				--      0005 x:? = 10 <-- x was in R0 before jump, and stack after jump
				bb_end(Vstate[code.bc_pc])
			else
				-- Instruction isn't reachable from previous line, restore variable layout
				-- e.g. RET or condition-less JMP on previous line
				V = table_copy(Vstate[code.bc_pc])
			end
		end
		-- Perform fixup of jump targets
		-- We need to do this because the number of consumed and emitted
		-- bytecode instructions is different
		local fixup = code.fixup[code.bc_pc]
		if fixup ~= nil then
			-- Patch JMP source insn with relative offset
			for _,pc in ipairs(fixup) do
				code.insn[pc].off = code.pc - 1 - pc
			end
			code.fixup[code.bc_pc] = nil
			code.reachable = true
		end
		-- Execute
		if code.reachable then
			assert(t[op], string.format('NYI: instruction %s, parameters: %s,%s,%s,%s', op,a,b,c,d))
			return t[op](a, b, c, d)
		end
	end,
})
end

-- Emitted code dump
local function dump_mem(cls, ins, _, fuse)
	-- This is a very dense MEM instruction decoder without much explanation
	-- Refer to https://www.kernel.org/doc/Documentation/networking/filter.txt for instruction format
	local mode = bit.band(ins.code, 0xe0)
	if mode == BPF.XADD then cls = 5 end -- The only mode
	local op_1 = {'LD', 'LDX', 'ST', 'STX', '', 'XADD'}
	local op_2 = {[0]='W', [8]='H', [16]='B', [24]='DW'}
	local name = op_1[cls+1] .. op_2[bit.band(ins.code, 0x18)]
	local off = tonumber(ffi.cast('int16_t', ins.off)) -- Reinterpret as signed
	local dst = cls < 2 and 'R'..ins.dst_reg or string.format('[R%d%+d]', ins.dst_reg, off)
	local src = cls % 2 == 0 and '#'..ins.imm or 'R'..ins.src_reg
	if cls == BPF.LDX then src = string.format('[R%d%+d]', ins.src_reg, off) end
	if mode == BPF.ABS then src = string.format('skb[%d]', ins.imm) end
	if mode == BPF.IND then src = string.format('skb[R%d%+d]', ins.src_reg, ins.imm) end
	return string.format('%s\t%s\t%s', fuse and '' or name, fuse and '' or dst, src)
end

local function dump_alu(cls, ins, pc)
	local alu = {'ADD', 'SUB', 'MUL', 'DIV', 'OR', 'AND', 'LSH', 'RSH', 'NEG', 'MOD', 'XOR', 'MOV', 'ARSH', 'END' }
	local jmp = {'JA', 'JEQ', 'JGT', 'JGE', 'JSET', 'JNE', 'JSGT', 'JSGE', 'CALL', 'EXIT'}
	local helper = {'unspec', 'map_lookup_elem', 'map_update_elem', 'map_delete_elem', 'probe_read', 'ktime_get_ns',
					'trace_printk', 'get_prandom_u32', 'get_smp_processor_id', 'skb_store_bytes',
					'l3_csum_replace', 'l4_csum_replace', 'tail_call', 'clone_redirect', 'get_current_pid_tgid',
					'get_current_uid_gid', 'get_current_comm', 'get_cgroup_classid', 'skb_vlan_push', 'skb_vlan_pop',
					'skb_get_tunnel_key', 'skb_set_tunnel_key', 'perf_event_read', 'redirect', 'get_route_realm',
					'perf_event_output', 'skb_load_bytes'}
	local op = 0
	-- This is a very dense ALU instruction decoder without much explanation
	-- Refer to https://www.kernel.org/doc/Documentation/networking/filter.txt for instruction format
	for i = 0,13 do if 0x10 * i == bit.band(ins.code, 0xf0) then op = i + 1 break end end
	local name = (cls == 5) and jmp[op] or alu[op]
	local src = (bit.band(ins.code, 0x08) == BPF.X) and 'R'..ins.src_reg or '#'..ins.imm
	local target = (cls == 5 and op < 9) and string.format('\t=> %04d', pc + ins.off + 1) or ''
	if cls == 5 and op == 9 then target = string.format('\t; %s', helper[ins.imm + 1] or tostring(ins.imm)) end
	return string.format('%s\t%s\t%s%s', name, 'R'..ins.dst_reg, src, target)
end

local function dump_string(code, off, hide_counter)
	if not code then return end
	local cls_map = {
		[0] = dump_mem, [1] = dump_mem, [2] = dump_mem, [3] = dump_mem,
		[4] = dump_alu, [5] = dump_alu, [7] = dump_alu,
	}
	local result = {}
	local fused = false
	for i = off or 0, code.pc - 1 do
		local ins = code.insn[i]
		local cls = bit.band(ins.code, 0x07)
		local line = cls_map[cls](cls, ins, i, fused)
		if hide_counter then
			table.insert(result, line)
		else
			table.insert(result, string.format('%04u\t%s', i, line))
		end
		fused = string.find(line, 'LDDW', 1)
	end
	return table.concat(result, '\n')
end

local function dump(code)
	if not code then return end
	print(string.format('-- BPF %s:0-%u', code.insn, code.pc))
	print(dump_string(code))
end

local function compile(prog, params)
	-- Create code emitter sandbox, include caller locals
	local env = { pkt=proto.pkt, eth=proto.pkt, BPF=BPF, ffi=ffi }
	-- Include upvalues up to 4 nested scopes back
	-- the narrower scope overrides broader scope
	for k = 5, 2, -1 do
		local i = 1
		while true do
			local ok, n, v = pcall(debug.getlocal, k, i)
			if not ok or not n then break end
			env[n] = v
			i = i + 1
		end
	end
	setmetatable(env, {
		__index = function (_, k)
			return proto[k] or builtins[k] or _G[k]
		end
	})
	-- Create code emitter and compile LuaJIT bytecode
	if type(prog) == 'string' then prog = loadstring(prog) end
	-- Create error handler to print traceback
	local funci, pc = bytecode.funcinfo(prog), 0
	local E = create_emitter(env, funci.stackslots, funci.params, params or {})
	local on_err = function (e)
			funci = bytecode.funcinfo(prog, pc)
			local from, to = 0, 0
			for _ = 1, funci.currentline do
				from = to
				to = string.find(funci.source, '\n', from+1, true) or 0
			end
			print(funci.loc..':'..string.sub(funci.source, from+1, to-1))
			print('error: '..e)
			print(debug.traceback())
	end
	for _,op,a,b,c,d in bytecode.decoder(prog) do
		local ok, _, err = xpcall(E,on_err,op,a,b,c,d)
		if not ok then
			return nil, err
		end
	end
	return E:compile()
end

-- BPF map interface
local bpf_map_mt = {
	__gc = function (map) S.close(map.fd) end,
	__len = function(map) return map.max_entries end,
	__index = function (map, k)
		if type(k) == 'string' then
			-- Return iterator
			if k == 'pairs' then
				return function(t, key)
					-- Get next key
					local next_key = ffi.new(ffi.typeof(t.key))
					local cur_key
					if key then
						cur_key = t.key
						t.key[0] = key
					else
						cur_key = ffi.new(ffi.typeof(t.key))
					end
					local ok, err = S.bpf_map_op(S.c.BPF_CMD.MAP_GET_NEXT_KEY, map.fd, cur_key, next_key)
					if not ok then return nil, err end
					-- Get next value
					assert(S.bpf_map_op(S.c.BPF_CMD.MAP_LOOKUP_ELEM, map.fd, next_key, map.val))
					return next_key[0], map.val[0]
				end, map, nil
			-- Read for perf event map
			elseif k == 'reader' then
				return function (pmap, pid, cpu, event_type)
					-- Caller must either specify PID or CPU
					if not pid or pid < 0 then
						assert((cpu and cpu >= 0), 'NYI: creating composed reader for all CPUs')
						pid = -1
					end
					-- Create BPF output reader
					local pe = S.t.perf_event_attr1()
					pe[0].type = 'software'
					pe[0].config = 'sw_bpf_output'
					pe[0].sample_type = 'raw'
					pe[0].sample_period = 1
					pe[0].wakeup_events = 1
					local reader, err = S.t.perf_reader(S.perf_event_open(pe, pid, cpu or -1))
					if not reader then return nil, tostring(err) end
					-- Register event reader fd in BPF map
					assert(cpu < pmap.max_entries, string.format('BPF map smaller than read CPU %d', cpu))
					pmap[cpu] = reader.fd
					-- Open memory map and start reading
					local ok, err = reader:start()
					assert(ok, tostring(err))
					ok, err = reader:mmap()
					assert(ok, tostring(err))
					return cdef.event_reader(reader, event_type)
				end
			-- Signalise this is a map type
			end
			return k == '__map'
		end
		-- Retrieve key
		map.key[0] = k
		local ok, err = S.bpf_map_op(S.c.BPF_CMD.MAP_LOOKUP_ELEM, map.fd, map.key, map.val)
		if not ok then return nil, err end
		return ffi.new(map.val_type, map.val[0])
	end,
	__newindex = function (map, k, v)
		map.key[0] = k
		if v == nil then
			return S.bpf_map_op(map.fd, S.c.BPF_CMD.MAP_DELETE_ELEM, map.key, nil)
		end
		map.val[0] = v
		return S.bpf_map_op(S.c.BPF_CMD.MAP_UPDATE_ELEM, map.fd, map.key, map.val)
	end,
}

-- Linux tracing interface
local function trace_check_enabled(path)
	path = path or '/sys/kernel/debug/tracing'
	if S.statfs(path) then return true end
	return nil, 'debugfs not accessible: "mount -t debugfs nodev /sys/kernel/debug"? missing sudo?'
end

-- Tracepoint interface
local tracepoint_mt = {
	__index = {
		bpf = function (t, prog)
			if type(prog) ~= 'table' then
				-- Create protocol parser with source probe
				prog = compile(prog, {proto.type(t.type, {source='ptr_to_probe'})})
			end
			-- Load the BPF program
			local prog_fd, err, log = S.bpf_prog_load(S.c.BPF_PROG.TRACEPOINT, prog.insn, prog.pc)
			assert(prog_fd, tostring(err)..': '..tostring(log))
			-- Open tracepoint and attach
			t.reader:setbpf(prog_fd:getfd())
			table.insert(t.progs, prog_fd)
			return prog_fd
		end,
	}
}
-- Open tracepoint
local function tracepoint_open(path, pid, cpu, group_fd)
	-- Open tracepoint and compile tracepoint type
	local tp = assert(S.perf_tracepoint('/sys/kernel/debug/tracing/events/'..path))
	local tp_type = assert(cdef.tracepoint_type(path))
	-- Open tracepoint reader and create interface
	local reader = assert(S.perf_attach_tracepoint(tp, pid, cpu, group_fd))
	return setmetatable({tp=tp,type=tp_type,reader=reader,progs={}}, tracepoint_mt)
end

local function trace_bpf(ptype, pname, pdef, retprobe, prog, pid, cpu, group_fd)
	-- Load BPF program
	if type(prog) ~= 'table' then
		prog = compile(prog, {proto.pt_regs})
	end
	local prog_fd, err, log = S.bpf_prog_load(S.c.BPF_PROG.KPROBE, prog.insn, prog.pc)
	assert(prog_fd, tostring(err)..': '..tostring(log))
	-- Open tracepoint and attach
	local tp, err = S.perf_probe(ptype, pname, pdef, retprobe)
	if not tp then
		prog_fd:close()
		return nil, tostring(err)
	end
	local reader, err = S.perf_attach_tracepoint(tp, pid, cpu, group_fd, {sample_type='raw, callchain'})
	if not reader then
		prog_fd:close()
		S.perf_probe(ptype, pname, false)
		return nil, tostring(err)
	end
	local ok, err = reader:setbpf(prog_fd:getfd())
	if not ok then
		prog_fd:close()
		reader:close()
		S.perf_probe(ptype, pname, false)
		return nil, tostring(err)..' (kernel version should be at least 4.1)'
	end
	-- Create GC closure for reader to close BPF program
	-- and detach probe in correct order
	ffi.gc(reader, function ()
		prog_fd:close()
		reader:close()
		S.perf_probe(ptype, pname, false)
	end)
	return {reader=reader, prog=prog_fd, probe=pname, probe_type=ptype}
end

-- Module interface
return setmetatable({
	new = create_emitter,
	dump = dump,
	dump_string = dump_string,
	maps = {},
	map = function (type, max_entries, key_ctype, val_ctype)
		if not key_ctype then key_ctype = ffi.typeof('uint32_t') end
		if not val_ctype then val_ctype = ffi.typeof('uint32_t') end
		if not max_entries then max_entries = 4096 end
		-- Special case for BPF_MAP_STACK_TRACE
		if S.c.BPF_MAP[type] == S.c.BPF_MAP.STACK_TRACE then
			key_ctype = ffi.typeof('int32_t')
			val_ctype = ffi.typeof('struct bpf_stacktrace')
		end
		local fd, err = S.bpf_map_create(S.c.BPF_MAP[type], ffi.sizeof(key_ctype), ffi.sizeof(val_ctype), max_entries)
		if not fd then return nil, tostring(err) end
		local map = setmetatable({
			max_entries = max_entries,
			key = ffi.new(ffi.typeof('$ [1]', key_ctype)),
			val = ffi.new(ffi.typeof('$ [1]', val_ctype)),
			map_type = S.c.BPF_MAP[type],
			key_type = key_ctype,
			val_type = val_ctype,
			fd = fd:nogc():getfd(),
		}, bpf_map_mt)
		return map
	end,
	socket = function (sock, prog)
		-- Expect socket type, if sock is string then assume it's
		-- an interface name (e.g. 'lo'), if it's a number then typecast it as a socket
		local ok, err
		if type(sock) == 'string' then
			local iface = assert(S.nl.getlink())[sock]
			assert(iface, sock..' is not interface name')
			sock, err = S.socket('packet', 'raw')
			assert(sock, tostring(err))
			ok, err = sock:bind(S.t.sockaddr_ll({protocol='all', ifindex=iface.index}))
			assert(ok, tostring(err))
		elseif type(sock) == 'number' then
			sock = S.t.fd(sock):nogc()
		elseif ffi.istype(S.t.fd, sock) then -- luacheck: ignore
			-- No cast required
		else
			return nil, 'socket must either be an fd number, an interface name, or an ljsyscall socket'
		end
		-- Load program and attach it to socket
		if type(prog) ~= 'table' then
			prog = compile(prog, {proto.skb})
		end
		local prog_fd, err, log = S.bpf_prog_load(S.c.BPF_PROG.SOCKET_FILTER, prog.insn, prog.pc)
		assert(prog_fd, tostring(err)..': '..tostring(log))
		assert(sock:setsockopt('socket', 'attach_bpf', prog_fd:getfd()))
		return prog_fd, err
	end,
	tracepoint = function(tp, prog, pid, cpu, group_fd)
		assert(trace_check_enabled())
		-- Return tracepoint instance if no program specified
		-- this allows free specialisation of arg0 to tracepoint type
		local probe = tracepoint_open(tp, pid, cpu, group_fd)
		-- Load the BPF program
		if prog then
			probe:bpf(prog)
		end
		return probe
	end,
	kprobe = function(tp, prog, retprobe, pid, cpu, group_fd)
		assert(trace_check_enabled())
		-- Open tracepoint and attach
		local pname, pdef = tp:match('([^:]+):(.+)')
		return trace_bpf('kprobe', pname, pdef, retprobe, prog, pid, cpu, group_fd)
	end,
	uprobe = function(tp, prog, retprobe, pid, cpu, group_fd)
		assert(trace_check_enabled())
		-- Translate symbol to address
		local obj, sym_want = tp:match('([^:]+):(.+)')
		if not S.statfs(obj) then return nil, S.t.error(S.c.E.NOENT) end
		-- Resolve Elf object (no support for anything else)
		local elf = require('bpf.elf').open(obj)
		local sym = elf:resolve(sym_want)
		if not sym then return nil, 'no such symbol' end
		sym = sym.st_value - elf:loadaddr()
		local sym_addr = string.format('%x%04x', tonumber(bit.rshift(sym, 32)),
		                                         tonumber(ffi.cast('uint32_t', sym)))
		-- Convert it to expected uprobe format
		local pname = string.format('%s_%s', obj:gsub('.*/', ''), sym_addr)
		local pdef = obj..':0x'..sym_addr
		return trace_bpf('uprobe', pname, pdef, retprobe, prog, pid, cpu, group_fd)
	end,
	tracelog = function(path)
		assert(trace_check_enabled())
		path = path or '/sys/kernel/debug/tracing/trace_pipe'
		return io.open(path, 'r')
	end,
	ntoh = builtins.ntoh, hton = builtins.hton,
}, {
	__call = function (_, prog) return compile(prog) end,
})
