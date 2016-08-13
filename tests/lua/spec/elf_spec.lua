describe('elf reader', function()

	local ok, elf = pcall(require, 'bpf.elf')
	if not ok then return end

	it('should handle C library', function()
		-- Open libc
		local sh = elf.open('/bin/sh')
		assert.truthy(sh)
		-- Find load address
		local base = sh:loadaddr()
		assert.truthy(base)
		-- Find something from ISO C
		local malloc_addr = sh:resolve('malloc')
		assert.truthy(malloc_addr)
		-- Find something that doesn't exist
		local bad_addr = sh:resolve('thisnotexists')
		assert.falsy(bad_addr)
	end)
	it('should fail on bad input', function()
		assert.falsy(elf.open(nil))
		assert.falsy(elf.open('/tmp'):loadaddr())
	end)
end)
