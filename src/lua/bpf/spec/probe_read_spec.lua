local ffi = require("ffi")
local S = require("syscall")
local bpf = require("bpf")

describe("probe_read", function ()
	it("keeps a kprobe argument available as a hash-map key", function ()
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

		local ok, err = pcall(bpf.kprobe, "test:probe", function (ptregs)
			map[ptregs.parm1] = time()
			local delta = time() - map[ptregs.parm1]
		end, false)
		S.statfs = old_statfs
		S.bpf_prog_load = old_prog_load
		S.perf_probe = old_probe
		S.perf_attach_tracepoint = old_attach
		S.c.BPF_PROG.KPROBE = old_kprobe
		assert(ok, tostring(err))
		assert(code)
		local dump = bpf.dump_string(code)
		assert(dump:find("probe_read", 1, true))
		assert(dump:find("map_update_elem", 1, true))
		assert(dump:find("map_lookup_elem", 1, true))
		local probe_call = dump:find("CALL	R0	#4	; probe_read", 1, true)
		local map_call = dump:find("CALL	R0	#2	; map_update_elem", 1, true)
		assert(probe_call and map_call and probe_call < map_call)
		local probe_end = dump:find(string.char(10), probe_call, true) or #dump
		local key_reg = dump:find("MOV	R2	R10", probe_end, true)
		assert(key_reg and key_reg < map_call)
		local probe_key_offset = dump:match("ADD	R1	#(%d+)", 1)
		local map_key_offset = dump:match("ADD	R2	#(%d+)", key_reg)
		assert(probe_key_offset and probe_key_offset == map_key_offset,
			"map key must point to probe_read's stack buffer")
	end)
end)
