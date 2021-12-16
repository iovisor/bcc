describe('compile', function()
	local ffi = require('ffi')
	local bpf = require('bpf')

	it('can compile socket filter', function()
		-- Create mock BPF map
		local mock_map = {
			max_entries = 16,
			key_type = ffi.typeof('uint64_t [1]'),
			val_type = ffi.typeof('uint64_t [1]'),
			fd = 1,
			__map = true,
		}
		-- Compile small code example
		local code = bpf(function ()
		   local proto = pkt.ip.proto
		   xadd(mock_map[proto], 1)
		end)
		assert.truthy(code)
		assert.same(type(code), 'table')
		assert.same(code.pc, 15)
	end)
end)
