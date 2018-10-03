describe('decoder', function()

	-- Decode simple function
	local bytecode = require('bpf.ljbytecode')
	local f = function (x) return x + 1 end

	it('should decode functions', function()
		-- Make sure it calls LJ decoder
		local bc = bytecode.decoder(f)
		assert.truthy(bc)
		-- Decode bytecode bytecode to instructions
		local jutil = require("jit.util")
		spy.on(jutil, 'funcbc')
		local pc, op = bc()
		-- Check bytecode for sanity (starts with ADDVN(x, 1))
		assert.equal(pc, 1)
		assert.equal(op, 'ADDVN')
		for pc, op in bc do
			assert.truthy(pc and op)
		end
		assert.spy(jutil.funcbc).was.called()
	end)
	it('should fail on bad input', function()
		assert.has_error(function() bytecode.decoder(nil)() end)
		assert.has_error(function() bytecode.decoder(5)() end)
		assert.has_error(function() bytecode.decoder('test')() end)
	end)
	it('should dump bytecode', function()
		bytecode.dump(f)
	end)
end)
