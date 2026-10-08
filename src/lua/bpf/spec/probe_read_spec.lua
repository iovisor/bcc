local ffi = require("ffi")
local S = require("syscall")
local bpf = require("bpf")
local BPF = ffi.typeof("struct bpf")
local HELPER = ffi.typeof("struct bpf_func_id")

local function compile(callback_factory)
	local old_statfs = S.statfs
	local old_prog_load = S.bpf_prog_load
	local old_probe = S.perf_probe
	local old_attach = S.perf_attach_tracepoint
	local old_kprobe = S.c.BPF_PROG.KPROBE
	local map = {
		__map = true,
		key_type = ffi.typeof("uint64_t"),
		val_type = ffi.typeof("uint64_t"),
		fd = 42,
	}
	local code

	S.statfs = function () return true end
	S.c.BPF_PROG.KPROBE = 2
	S.bpf_prog_load = function (_, insn, pc)
		code = {insn = insn, pc = pc}
		return {getfd = function () return 1 end, close = function () end}
	end
	S.perf_probe = function () return {} end
	S.perf_attach_tracepoint = function () return nil, "mock attach" end

	local ok, err = pcall(bpf.kprobe, "test:probe", callback_factory(map), false)
	S.statfs = old_statfs
	S.bpf_prog_load = old_prog_load
	S.perf_probe = old_probe
	S.perf_attach_tracepoint = old_attach
	S.c.BPF_PROG.KPROBE = old_kprobe
	assert(ok, tostring(err))
	assert(code)
	return code
end

local function find_call(code, helper, start)
	for i = start or 0, code.pc - 1 do
		local ins = code.insn[i]
		if ins.code == BPF.JMP + BPF.CALL and ins.imm == helper then return i end
	end
end

local function stack_offset_before(code, call, arg_reg)
	for i = call - 1, 1, -1 do
		local ins = code.insn[i]
		if ins.code == BPF.ALU64 + BPF.ADD + BPF.K and ins.dst_reg == arg_reg then
			for j = i - 1, 0, -1 do
				local prev = code.insn[j]
				if prev.code == BPF.ALU64 + BPF.MOV + BPF.X
					and prev.dst_reg == arg_reg and prev.src_reg == 10 then
					return ins.imm
				end
			end
		end
	end
end

describe("probe_read", function ()
	it("keeps a kprobe argument available as a hash-map key", function ()
		local code = compile(function (map)
			return function (ptregs)
				map[ptregs.parm1] = time()
				local delta = time() - map[ptregs.parm1]
			end
		end)

		local probe = find_call(code, HELPER.probe_read)
		local update = find_call(code, HELPER.map_update_elem)
		assert(probe and update and probe < update)
		assert(find_call(code, HELPER.map_lookup_elem))
		local probe_dst = stack_offset_before(code, probe, 1)
		local map_key = stack_offset_before(code, update, 2)
		assert(probe_dst and map_key and probe_dst == map_key,
			"map key must point to probe_read's stack buffer")
	end)

	it("loads 64-bit stack-backed values before arithmetic and branches", function ()
		local code = compile(function (map)
			return function (ptregs)
				local value = ptregs.parm1
				local adjusted = value + 1
				if adjusted > value then map[value] = adjusted end
			end
		end)

		local scalar_load, scalar_add, conditional
		for i = 0, code.pc - 1 do
			local ins = code.insn[i]
			if ins.code == BPF.MEM + BPF.LDX + BPF.DW and ins.src_reg == 10 and ins.off ~= 0 then
				local next_ins = code.insn[i + 1]
				if next_ins.code == BPF.ALU64 + BPF.ADD + BPF.K and next_ins.imm == 1
					and next_ins.dst_reg == ins.dst_reg then
					scalar_load, scalar_add = i, i + 1
				end
			end
			if ins.code == BPF.JMP + BPF.JGE + BPF.X then conditional = i end
		end
		assert(scalar_load and scalar_add, "arithmetic must use the loaded scalar, not its stack address")
		assert(conditional, "conditional branch must compare scalar registers")
		assert(find_call(code, HELPER.map_update_elem))
	end)

	it("uses distinct stack buffers for consecutive probe reads", function ()
		local code = compile(function (map)
			return function (ptregs)
				map[ptregs.parm1] = ptregs.parm2
			end
		end)

		local probe1 = find_call(code, HELPER.probe_read)
		local probe2 = probe1 and find_call(code, HELPER.probe_read, probe1 + 1)
		assert(probe1 and probe2, "both probe_read helpers must be emitted")
		local dst1 = stack_offset_before(code, probe1, 1)
		local dst2 = stack_offset_before(code, probe2, 1)
		assert(dst1 and dst2 and dst1 ~= dst2, "probe_read calls must have separate destinations")
		assert(find_call(code, HELPER.map_update_elem))
	end)
end)
