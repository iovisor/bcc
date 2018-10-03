local ffi = require('ffi')

-- Define basic ctypes
ffi.cdef [[
	struct bpf_insn {
	  uint8_t code;   /* opcode */
	  uint8_t dst_reg:4;  /* dest register */
	  uint8_t src_reg:4;  /* source register */
	  uint16_t off;   /* signed offset */
	  uint32_t imm;   /* signed immediate constant */
	};
]]

-- Inject mock ljsyscall for tests
package.loaded['syscall'] = {
	bpf = function() error('mock') end,
	c = { BPF_MAP = {}, BPF_PROG = {} },
	abi = { arch = 'x64' },
}

package.loaded['syscall.helpers'] = {
	strflag = function (tab)
		local function flag(cache, str)
			if type(str) ~= "string" then return str end
			if #str == 0 then return 0 end
			local s = str:upper()
			if #s == 0 then return 0 end
			local val = rawget(tab, s)
			if not val then return nil end
			cache[str] = val
			return val
		end
		return setmetatable(tab, {__index = setmetatable({}, {__index = flag}), __call = function(t, a) return t[a] end})
	end
}