local ffi = require('ffi')
local S = require('syscall')

-- Normalize whitespace and remove empty lines
local function normalize_code(c)
	local res = {}
	for line in string.gmatch(c,'[^\r\n]+') do
		local op, d, s, t = line:match('(%S+)%s+(%S+)%s+(%S+)%s*([^-]*)')
		if op then
			t = t and t:match('^%s*(.-)%s*$')
			table.insert(res, string.format('%s\t%s %s %s', op, d, s, t))
		end
	end
	return table.concat(res, '\n')
end

-- Compile code and check result
local function compile(t)
	local bpf = require('bpf')
	-- require('jit.bc').dump(t.input)
	local code, err = bpf(t.input)
	assert.truthy(code)
	assert.falsy(err)
	if code then
		if t.expect then
			local got = normalize_code(bpf.dump_string(code, 1, true))
			-- if normalize_code(t.expect) ~= got then print(bpf.dump_string(code, 1)) end
			assert.same(normalize_code(t.expect), got)
		end
	end
end

-- Make a mock map variable
local function makemap(type, max_entries, key_ctype, val_ctype)
	if not key_ctype then key_ctype = ffi.typeof('uint32_t') end
	if not val_ctype then val_ctype = ffi.typeof('uint32_t') end
	if not max_entries then max_entries = 4096 end
	return {
		__map = true,
		max_entries = max_entries,
		key = ffi.new(ffi.typeof('$ [1]', key_ctype)),
		val = ffi.new(ffi.typeof('$ [1]', val_ctype)),
		map_type = S.c.BPF_MAP[type],
		key_type = key_ctype,
		val_type = val_ctype,
		fd = 42,
	}
end

describe('codegen', function()
	-- luacheck: ignore 113 211 212 311 511

	describe('constants', function()
		it('remove dead constant store', function()
			compile {
				input = function ()
					local proto = 5
				end,
				expect = [[
					MOV		R0	#0
					EXIT	R0	#0
				]]
			}
		end)
		it('materialize constant', function()
			compile {
				input = function ()
					return 5
				end,
				expect = [[
					MOV		R0	#5
					EXIT	R0	#0
				]]
			}
		end)
		it('materialize constant longer than i32', function()
			compile {
				input = function ()
					return 4294967295
				end,
				expect = [[
					LDDW	R0	#4294967295
					EXIT	R0	#0
				]]
			}
		end)
		it('materialize cdata constant', function()
			compile {
				input = function ()
					return 5ULL
				end,
				expect = [[
					LDDW	R0	#5 -- composed instruction
					EXIT	R0	#0
				]]
			}
		end)
		it('materialize signed cdata constant', function()
			compile {
				input = function ()
					return 5LL
				end,
				expect = [[
					LDDW	R0	#5 -- composed instruction
					EXIT	R0	#0
				]]
			}
		end)
		it('materialize coercible numeric cdata constant', function()
			compile {
				input = function ()
					return 0x00005
				end,
				expect = [[
					MOV		R0	#5
					EXIT	R0	#0
				]]
			}
		end)
		it('materialize constant through variable', function()
		compile {
			input = function ()
				local proto = 5
				return proto
			end,
			expect = [[
				MOV		R0	#5
				EXIT	R0	#0
			]]
		}
		end)
		it('eliminate constant expressions', function()
			compile {
				input = function ()
					return 2 + 3 - 0
				end,
				expect = [[
					MOV		R0	#5
					EXIT	R0	#0
				]]
			}
		end)
		it('eliminate constant expressions (if block)', function()
			compile {
				input = function ()
					local proto = 5
					if proto == 5 then
						proto = 1
					end
					return proto
				end,
				expect = [[
					MOV		R0	#1
					EXIT	R0	#0
				]]
			}
		end)
		it('eliminate negative constant expressions (if block) NYI', function()
			-- always negative condition is not fully eliminated
			compile {
				input = function ()
					local proto = 5
					if false then
						proto = 1
					end
					return proto
				end,
				expect = [[
					MOV		R7		#5
					STXDW	[R10-8] R7
					MOV		R7		#0
					JEQ		R7		#0 => 0005
					LDXDW	R0 		[R10-8]
					EXIT	R0		#0
				]]
			}
		end)
	end)

	describe('variables', function()
		it('classic packet access (fold constant offset)', function()
			compile {
				input = function (skb)
					return eth.ip.tos -- constant expression will fold
				end,
				expect = [[
					LDB		R0	skb[15]
					EXIT	R0	#0
				]]
			}
		end)
		it('classic packet access (load non-constant offset)', function()
			compile {
				input = function (skb)
					return eth.ip.udp.src_port -- need to skip variable-length header
				end,
				expect = [[
					LDB		R0			skb[14]
					AND		R0			#15
					LSH		R0			#2
					ADD		R0 			#14
					STXDW	[R10-16]	R0 -- NYI: erase dead store
					LDH		R0 			skb[R0+0]
					END		R0 			R0
					EXIT	R0 			#0
				]]
			}
		end)
		it('classic packet access (manipulate dissector offset)', function()
			compile {
				input = function (skb)
					local ptr = eth.ip.udp.data + 1
					return ptr[0] -- dereference dissector pointer
				end,
				expect = [[
					LDB		R0			skb[14]
					AND		R0			#15
					LSH		R0			#2
					ADD		R0			#14 -- NYI: fuse commutative operations in second pass
					ADD		R0			#8
					ADD		R0			#1
					STXDW	[R10-16] 	R0
					LDB		R0			skb[R0+0]
					EXIT	R0			#0
				]]
			}
		end)
		it('classic packet access (multi-byte load)', function()
			compile {
				input = function (skb)
					local ptr = eth.ip.udp.data
					return ptr(1, 5) -- load 4 bytes
				end,
				expect = [[
					LDB		R0			skb[14]
					AND		R0			#15
					LSH		R0			#2
					ADD		R0			#14
					ADD		R0			#8
					MOV		R7			R0
					STXDW	[R10-16]	R0 -- NYI: erase dead store
					LDW		R0			skb[R7+1]
					END		R0			R0
					EXIT	R0			#0
				]]
			}
		end)
		it('direct skb field access', function()
			compile {
				input = function (skb)
					return skb.len
				end,
				expect = [[
					LDXW	R7	[R6+0]
					MOV		R0	R7
					EXIT	R0	#0
				]]
			}
		end)
		it('direct skb data access (manipulate offset)', function()
			compile {
				input = function (skb)
					local ptr = skb.data + 5
					return ptr[0]
				end,
				expect = [[
					LDXW	R7	[R6+76]
					ADD		R7	#5
					LDXB	R8 	[R7+0] -- NYI: transform LD + ADD to LD + offset addressing
					MOV		R0 	R8
					EXIT	R0	#0
				]]
			}
		end)
		it('direct skb data access (offset boundary check)', function()
			compile {
				input = function (skb)
					local ptr = skb.data + 5
					if ptr < skb.data_end then
						return ptr[0]
					end
				end,
				expect = [[
					LDXW	R7	[R6+76]
					ADD		R7	#5
					LDXW	R8	[R6+80]
					JGE		R7	R8 => 0008
					LDXB	R8	[R7+0]
					MOV		R0 	R8
					EXIT	R0	#0
					MOV		R0	#0
					EXIT	R0	#0
				]]
			}
		end)
		it('access stack memory (array, const load, const store)', function()
			compile {
				input = function (skb)
					local mem = ffi.new('uint8_t [16]')
					mem[0] = 5
				end,
				expect = [[
					MOV		R0 			#0
					STXDW	[R10-40] 	R0
					STXDW	[R10-48] 	R0 -- NYI: erase zero-fill on allocation when it's loaded later
					STB		[R10-48] 	#5
					MOV		R0 			#0
					EXIT	R0 			#0
				]]
			}
		end)
		it('access stack memory (array, const load, packet store)', function()
			compile {
				input = function (skb)
					local mem = ffi.new('uint8_t [7]')
					mem[0] = eth.ip.tos
				end,
				expect = [[
					MOV		R0 			#0
					STXDW	[R10-40] 	R0 -- NYI: erase zero-fill on allocation when it's loaded later
					LDB		R0 			skb[15]
					STXB	[R10-40] 	R0
					MOV		R0 			#0
					EXIT	R0 			#0
				]]
			}
		end)
		it('access stack memory (array, packet load, const store)', function()
			compile {
				input = function (skb)
					local mem = ffi.new('uint8_t [1]')
					mem[eth.ip.tos] = 5
				end,
				expect = [[
					MOV		R0 			#0
					STXDW	[R10-48] 	R0 -- NYI: erase zero-fill on allocation when it's loaded later
					LDB		R0 			skb[15]
					MOV		R7 			R0
					ADD		R7 			R10
					STB		[R7-48] 	#5
					MOV		R0 			#0
					EXIT	R0 			#0
				]]
			}
		end)
		it('access stack memory (array, packet load, packet store)', function()
			compile {
				input = function (skb)
					local mem = ffi.new('uint8_t [7]')
					local v = eth.ip.tos
					mem[v] = v
				end,
				expect = [[
					MOV		R0 			#0
					STXDW	[R10-40] 	R0 -- NYI: erase zero-fill on allocation when it's loaded later
					LDB		R0 			skb[15]
					MOV		R7 			R0
					ADD		R7 			R10
					STXB	[R7-40] 	R0
					MOV		R0 			#0
					EXIT	R0 			#0
				]]
			}
		end)
		it('access stack memory (struct, const/packet store)', function()
			local kv_t = 'struct { uint64_t a; uint64_t b; }'
			compile {
				input = function (skb)
					local mem = ffi.new(kv_t)
					mem.a = 5
					mem.b = eth.ip.tos
				end,
				expect = [[
					MOV		R0 			#0
					STXDW	[R10-40] 	R0
					STXDW	[R10-48] 	R0 -- NYI: erase zero-fill on allocation when it's loaded later
					MOV		R7 			#5
					STXDW	[R10-48] 	R7
					LDB		R0 			skb[15]
					STXDW	[R10-40] 	R0
					MOV		R0 			#0
					EXIT	R0 			#0
				]]
			}
		end)
		it('access stack memory (struct, const/stack store)', function()
			local kv_t = 'struct { uint64_t a; uint64_t b; }'
			compile {
				input = function (skb)
					local m1 = ffi.new(kv_t)
					local m2 = ffi.new(kv_t)
					m1.a = 5
					m2.b = m1.a
				end,
				expect = [[
					MOV		R0 			#0
					STXDW	[R10-48] 	R0
					STXDW	[R10-56] 	R0 -- NYI: erase zero-fill on allocation when it's loaded later
					MOV		R0 			#0
					STXDW	[R10-64] 	R0
					STXDW	[R10-72] 	R0 -- NYI: erase zero-fill on allocation when it's loaded later
					MOV		R7 			#5
					STXDW	[R10-56] 	R7
					LDXDW	R7 			[R10-56]
					STXDW	[R10-64] 	R7
					MOV		R0 			#0
					EXIT	R0 			#0
				]]
			}
		end)
		it('array map (u32, const key load)', function()
			local array_map = makemap('array', 256)
			compile {
				input = function (skb)
					return array_map[0]
				end,
				expect = [[
					LDDW	R1			#42
					STW		[R10-28]	#0
					MOV		R2			R10
					ADD		R2			#4294967268
					CALL	R0			#1 ; map_lookup_elem
					JEQ		R0			#0 => 0009
					LDXW	R0			[R0+0]
					EXIT	R0			#0
				]]
			}
		end)
		it('array map (u32, packet key load)', function()
			local array_map = makemap('array', 256)
			compile {
				input = function (skb)
					return array_map[eth.ip.tos]
				end,
				expect = [[
					LDB 	R0 			skb[15]
					LDDW	R1			#42
					STXW	[R10-36] 	R0
					MOV		R2			R10
					ADD		R2			#4294967260
					STXDW	[R10-24] 	R0 -- NYI: erase dead store
					CALL	R0			#1 ; map_lookup_elem
					JEQ		R0			#0 => 0011
					LDXW	R0			[R0+0]
					EXIT	R0			#0
				]]
			}
		end)
		it('array map (u32, const key store, const value)', function()
			local array_map = makemap('array', 256)
			compile {
				input = function (skb)
					array_map[0] = 5
				end,
				expect = [[
					LDDW	R1 			#42
					STW		[R10-36] 	#0
					MOV		R2 			R10
					ADD		R2 			#4294967260
					MOV		R4 			#0
					STW		[R10-40] 	#5
					MOV		R3 			R10
					ADD		R3 			#4294967256
					CALL	R0 			#2 ; map_update_elem
					MOV		R0 			#0
					EXIT	R0 			#0
				]]
			}
		end)
		it('array map (u32, const key store, packet value)', function()
			local array_map = makemap('array', 256)
			compile {
				input = function (skb)
					array_map[0] = eth.ip.tos
				end,
				expect = [[
					LDB		R0 			skb[15]
					STXDW	[R10-24] 	R0
					LDDW	R1 			#42
					STW		[R10-36] 	#0
					MOV		R2 			R10
					ADD		R2 			#4294967260
					MOV		R4 			#0
					MOV		R3 			R10
					ADD		R3 			#4294967272
					CALL	R0 			#2 ; map_update_elem
					MOV		R0 			#0
					EXIT	R0 			#0
				]]
			}
		end)
		it('array map (u32, const key store, map value)', function()
			local array_map = makemap('array', 256)
			compile {
				input = function (skb)
					array_map[0] = array_map[1]
				end,
				expect = [[
					LDDW	R1 			#42
					STW		[R10-36] 	#1
					MOV		R2 			R10
					ADD		R2 			#4294967260
					CALL	R0 			#1 ; map_lookup_elem
					STXDW	[R10-24] 	R0
					LDDW	R1 			#42
					STW		[R10-36]	#0
					MOV		R2			R10
					ADD		R2			#4294967260
					MOV		R4			#0
					LDXDW	R3			[R10-24]
					JEQ		R3			#0 => 0017
					LDXW	R3			[R3+0]
					STXW	[R10-40]	R3
					MOV		R3 			R10
					ADD		R3 			#4294967256
					CALL	R0 			#2 ; map_update_elem
					MOV		R0 			#0
					EXIT	R0 			#0
				]]
			}
		end)
		it('array map (u32, const key replace, const value)', function()
			local array_map = makemap('array', 256)
			compile {
				input = function (skb)
					local val = array_map[0]
					if val then
						val[0] = val[0] + 1
					else
						array_map[0] = 5
					end
				end,
				expect = [[
					LDDW	R1 			#42
					STW		[R10-44] 	#0
					MOV		R2 			R10
					ADD		R2 			#4294967252
					CALL	R0 			#1 ; map_lookup_elem
					JEQ		R0 			#0 => 0013 -- if (map_value ~= NULL)
					LDXW	R7 			[R0+0]
					ADD		R7 			#1
					STXW	[R0+0] 		R7
					MOV		R7 			#0
					JEQ		R7 			#0 => 0025 -- skip false branch
					STXDW	[R10-16] 	R0
					LDDW	R1 			#42
					STW		[R10-44] 	#0
					MOV		R2 			R10
					ADD		R2 			#4294967252
					MOV		R4 			#0
					STW		[R10-48] 	#5
					MOV		R3 			R10
					ADD		R3 			#4294967248
					CALL	R0 			#2 ; map_update_elem
					LDXDW	R0 			[R10-16]
					MOV		R0 			#0
					EXIT	R0 			#0
				]]
			}
		end)
		it('array map (u32, const key replace xadd, const value)', function()
			local array_map = makemap('array', 256)
			compile {
				input = function (skb)
					local val = array_map[0]
					if val then
						xadd(val, 1)
					else
						array_map[0] = 5
					end
				end,
				expect = [[
					LDDW	R1 			#42
					STW		[R10-52] 	#0
					MOV		R2 			R10
					ADD		R2 			#4294967244
					CALL	R0 			#1 ; map_lookup_elem
					JEQ		R0 			#0 => 0014 -- if (map_value ~= NULL)
					MOV		R7 			#1
					MOV		R8 			R0
					STXDW	[R10-16] 	R0
					XADDW	[R8+0] 		R7
					MOV		R7 			#0
					JEQ		R7 			#0 => 0025 -- skip false branch
					STXDW	[R10-16] 	R0
					LDDW	R1 			#42
					STW		[R10-52] 	#0
					MOV		R2 			R10
					ADD		R2 			#4294967244
					MOV		R4 			#0
					STW		[R10-56] 	#5
					MOV		R3 			R10
					ADD		R3 			#4294967240
					CALL	R0 			#2 ; map_update_elem
					MOV		R0 			#0
					EXIT	R0 			#0
				]]
			}
		end)
		it('array map (u32, const key replace xadd, const value) inverse nil check', function()
			local array_map = makemap('array', 256)
			compile {
				input = function (skb)
					local val = array_map[0]
					if not val then
						array_map[0] = 5
					else
						xadd(val, 1)
					end
				end,
				expect = [[
					LDDW	R1 			#42
					STW		[R10-52] 	#0
					MOV		R2 			R10
					ADD		R2 			#4294967244
					CALL	R0 			#1 ; map_lookup_elem
					JNE		R0 			#0 => 0021
					STXDW	[R10-16] 	R0
					LDDW	R1 			#42
					STW		[R10-52] 	#0
					MOV		R2 			R10
					ADD		R2 			#4294967244
					MOV		R4 			#0
					STW		[R10-56] 	#5
					MOV		R3 			R10
					ADD		R3 			#4294967240
					CALL	R0 			#2 ; map_update_elem
					MOV		R7 			#0
					JEQ		R7 			#0 => 0025
					MOV		R7 			#1
					MOV		R8 			R0
					STXDW	[R10-16] 	R0
					XADDW	[R8+0] 		R7
					MOV		R0 			#0
					EXIT	R0 			#0
				]]
			}
		end)
		it('array map (struct, stack key load)', function()
			local kv_t = 'struct { uint64_t a; uint64_t b; }'
			local array_map = makemap('array', 256, ffi.typeof(kv_t), ffi.typeof(kv_t))
			compile {
				input = function (skb)
					local key = ffi.new(kv_t)
					key.a = 2
					key.b = 3
					local val = array_map[key] -- Use composite key from stack memory
					if val then
						return val.a
					end
				end,
				expect = [[
					MOV		R0 			#0
					STXDW	[R10-48] 	R0
					STXDW	[R10-56] 	R0 -- NYI: erase zero-fill on allocation when it's loaded later
					MOV		R7 			#2
					STXDW	[R10-56] 	R7
					MOV		R7 			#3
					STXDW	[R10-48] 	R7
					LDDW	R1			#42
					MOV		R2			R10
					ADD		R2			#4294967240
					CALL	R0			#1 ; map_lookup_elem
					JEQ		R0 			#0 => 0017
					LDXDW	R7 			[R0+0]
					MOV		R0 			R7
					EXIT	R0 			#0
					MOV		R0 			#0
					EXIT	R0 			#0
				]]
			}
		end)
		it('array map (struct, stack key store)', function()
			local kv_t = 'struct { uint64_t a; uint64_t b; }'
			local array_map = makemap('array', 256, ffi.typeof(kv_t), ffi.typeof(kv_t))
			compile {
				input = function (skb)
					local key = ffi.new(kv_t)
					key.a = 2
					key.b = 3
					array_map[key] = key -- Use composite key from stack memory
				end,
				expect = [[
					MOV		R0 			#0
					STXDW	[R10-40] 	R0
					STXDW	[R10-48] 	R0 -- NYI: erase zero-fill on allocation when it's loaded later
					MOV		R7 			#2
					STXDW	[R10-48] 	R7
					MOV		R7 			#3
					STXDW	[R10-40] 	R7
					LDDW	R1 			#42
					MOV		R2 			R10
					ADD		R2 			#4294967248
					MOV		R4 			#0
					MOV		R3 			R10
					ADD		R3 			#4294967248
					CALL	R0 			#2 ; map_update_elem
					MOV		R0 			#0
					EXIT	R0 			#0
				]]
			}
		end)
		it('array map (struct, stack/packet key update, const value)', function()
			local kv_t = 'struct { uint64_t a; uint64_t b; }'
			local array_map = makemap('array', 256, ffi.typeof(kv_t), ffi.typeof(kv_t))
			compile {
				input = function (skb)
					local key = ffi.new(kv_t)
					key.a = eth.ip.tos   -- Load key part from dissector
					local val = array_map[key]
					if val then
						val.a = 5
					end
				end,
				expect = [[
					MOV		R0 			#0
					STXDW	[R10-48] 	R0
					STXDW	[R10-56] 	R0 -- NYI: erase zero-fill on allocation when it's loaded later
					LDB		R0 			skb[15]
					STXDW	[R10-56] 	R0
					LDDW	R1			#42
					MOV		R2			R10
					ADD		R2			#4294967240
					CALL	R0			#1 ; map_lookup_elem
					JEQ		R0 			#0 => 0014
					MOV		R7 			#5
					STXDW	[R0+0] 		R7
					MOV		R0 			#0
					EXIT	R0 			#0
				]]
			}
		end)
		it('array map (struct, stack/packet key update, map value)', function()
			local kv_t = 'struct { uint64_t a; uint64_t b; }'
			local array_map = makemap('array', 256, ffi.typeof(kv_t), ffi.typeof(kv_t))
			compile {
				input = function (skb)
					local key = ffi.new(kv_t)
					key.a = eth.ip.tos   -- Load key part from dissector
					local val = array_map[key]
					if val then
						val.a = val.b
					end
				end,
				expect = [[
					MOV		R0 			#0
					STXDW	[R10-48] 	R0
					STXDW	[R10-56] 	R0 -- NYI: erase zero-fill on allocation when it's loaded later
					LDB		R0 			skb[15]
					STXDW	[R10-56] 	R0
					LDDW	R1			#42
					MOV		R2			R10
					ADD		R2			#4294967240
					CALL	R0			#1 ; map_lookup_elem
					JEQ		R0 			#0 => 0014
					LDXDW	R7 			[R0+8]
					STXDW	[R0+0] 		R7
					MOV		R0 			#0
					EXIT	R0 			#0
				]]
			}
		end)
		it('array map (struct, stack/packet key update, stack value)', function()
			local kv_t = 'struct { uint64_t a; uint64_t b; }'
			local array_map = makemap('array', 256, ffi.typeof(kv_t), ffi.typeof(kv_t))
			compile {
				input = function (skb)
					local key = ffi.new(kv_t)
					key.a = eth.ip.tos   -- Load key part from dissector
					local val = array_map[key]
					if val then
						val.a = key.b
					end
				end,
				expect = [[
					MOV		R0 			#0
					STXDW	[R10-48] 	R0
					STXDW	[R10-56] 	R0 -- NYI: erase zero-fill on allocation when it's loaded later
					LDB		R0 			skb[15]
					STXDW	[R10-56] 	R0
					LDDW	R1			#42
					MOV		R2			R10
					ADD		R2			#4294967240
					CALL	R0			#1 ; map_lookup_elem
					JEQ		R0 			#0 => 0014
					LDXDW	R7 			[R10-48]
					STXDW	[R0+0] 		R7
					MOV		R0 			#0
					EXIT	R0 			#0
				]]
			}
		end)
		it('array map (struct, stack/packet key replace, stack value)', function()
			local kv_t = 'struct { uint64_t a; uint64_t b; }'
			local array_map = makemap('array', 256, ffi.typeof(kv_t), ffi.typeof(kv_t))
			compile {
				input = function (skb)
					local key = ffi.new(kv_t)
					key.a = eth.ip.tos   -- Load key part from dissector
					local val = array_map[key]
					if val then
						val.a = key.b
					else
						array_map[key] = key
					end
				end,
				expect = [[
					MOV		R0 			#0
					STXDW	[R10-48] 	R0
					STXDW	[R10-56] 	R0
					LDB		R0 			skb[15]
					STXDW	[R10-56] 	R0
					LDDW	R1 			#42
					MOV		R2 			R10
					ADD		R2 			#4294967240
					CALL	R0 			#1 ; map_lookup_elem
					JEQ		R0 			#0 => 0016 -- if (map_value ~= NULL)
					LDXDW	R7 			[R10-48]
					STXDW	[R0+0] 		R7
					MOV		R7 			#0
					JEQ		R7 			#0 => 0026 -- jump over false branch
					STXDW	[R10-24] 	R0
					LDDW	R1 			#42
					MOV		R2 			R10
					ADD		R2 			#4294967240
					MOV		R4 			#0
					MOV		R3 			R10
					ADD		R3 			#4294967240
					CALL	R0 			#2 ; map_update_elem
					LDXDW	R0 			[R10-24]
					MOV		R0 			#0
					EXIT	R0 			#0
				]]
			}
		end)
	end)
	describe('control flow', function()
		it('condition with constant return', function()
			compile {
				input = function (skb)
					local v = eth.ip.tos
					if v then
						return 1
					else
						return 0
					end
				end,
				expect = [[
					LDB		R0 			skb[15]
					JEQ		R0 			#0 => 0005
					MOV		R0 			#1
					EXIT	R0 			#0
					MOV		R0 			#0 -- 0005 jump target
					EXIT	R0 			#0
				]]
			}
		end)
		it('condition with cdata constant return', function()
			local cdata = 2ULL
			compile {
				input = function (skb)
					local v = eth.ip.tos
					if v then
						return cdata + 1
					else
						return 0
					end
				end,
				expect = [[
					LDB		R0 			skb[15]
					JEQ		R0 			#0 => 0006
					LDDW	R0 			#3
					EXIT	R0 			#0
					MOV		R0 			#0 -- 0006 jump target
					EXIT	R0 			#0
				]]
			}
		end)
		it('condition with constant return (inversed)', function()
			compile {
				input = function (skb)
					local v = eth.ip.tos
					if not v then
						return 1
					else
						return 0
					end
				end,
				expect = [[
					LDB		R0 			skb[15]
					JNE		R0 			#0 => 0005
					MOV		R0 			#1
					EXIT	R0 			#0
					MOV		R0 			#0 -- 0005 jump target
					EXIT	R0 			#0
				]]
			}
		end)
		it('condition with variable mutation', function()
			compile {
				input = function (skb)
					local v = 0
					if eth.ip.tos then
						v = 1
					end
					return v
				end,
				expect = [[
					LDB		R0 			skb[15]
					MOV		R1 			#0
					STXDW	[R10-16] 	R1
					JEQ		R0 			#0 => 0007
					MOV		R7 			#1
					STXDW	[R10-16] 	R7
					LDXDW	R0 			[R10-16]
					EXIT	R0 			#0
				]]
			}
		end)
		it('condition with nil variable mutation', function()
			compile {
				input = function (skb)
					local v -- nil, will be elided
					if eth.ip.tos then
						v = 1
					else
						v = 0
					end
					return v
				end,
				expect = [[
					LDB		R0 			skb[15]
					JEQ		R0 			#0 => 0007
					MOV		R7 			#1
					STXDW	[R10-16] 	R7
					MOV		R7 			#0
					JEQ		R7 			#0 => 0009
					MOV		R7 			#0
					STXDW	[R10-16] 	R7
					LDXDW	R0 			[R10-16]
					EXIT	R0 			#0
				]]
			}
		end)
		it('nested condition with variable mutation', function()
			compile {
				input = function (skb)
					local v = 0
					local tos = eth.ip.tos
					if tos then
						if tos > 5 then
							v = 5
						else
							v = 1
						end
					end
					return v
				end,
				expect = [[
					LDB		R0 			skb[15]
					MOV		R1 			#0
					STXDW	[R10-16] 	R1 -- materialize v = 0
					JEQ		R0 			#0 => 0013 -- if not tos
					MOV		R7 			#5
					JGE		R7 			R0 => 0011 -- if 5 > tos
					MOV		R7 			#5
					STXDW	[R10-16] 	R7 -- materialize v = 5
					MOV		R7 			#0
					JEQ		R7 			#0 => 0013
					MOV		R7 			#1 -- 0011 jump target
					STXDW	[R10-16]	R7 -- materialize v = 1
					LDXDW	R0 			[R10-16]
					EXIT	R0 			#0
				]]
			}
		end)
		it('nested condition with variable shadowing', function()
			compile {
				input = function (skb)
					local v = 0
					local tos = eth.ip.tos
					if tos then
						local v = 0 -- luacheck: ignore 231
						if tos > 5 then
							v = 5 -- changing shadowing variable
						end
					else
						v = 1
					end
					return v
				end,
				expect = [[
					LDB		R0 			skb[15]
					MOV		R1 			#0
					STXDW	[R10-16] 	R1 -- materialize v = 0
					JEQ		R0 			#0 => 0011 -- if not tos
					MOV		R7 			#5
					MOV		R1 			#0
					STXDW	[R10-32] 	R1 -- materialize shadowing variable
					JGE		R7 			R0 => 0013 -- if 5 > tos
					MOV		R7 			#0 -- erased 'v = 5' dead store
					JEQ		R7 			#0 => 0013
					MOV		R7 			#1 -- 0011 jump target
					STXDW	[R10-16]	R7 -- materialize v = 1
					LDXDW	R0 			[R10-16] -- 0013 jump target
					EXIT	R0 			#0
				]]
			}
		end)
		it('condition materializes shadowing variable at the end of BB', function()
			compile {
				input = function (skb)
					local v = time()
					local v1 = 0 -- luacheck: ignore 231
					if eth.ip.tos then
						v1 = v
					end
				end,
				expect = [[
					CALL	R0 			#5 ; ktime_get_ns
					STXDW	[R10-16] 	R0
					LDB		R0 			skb[15]
					MOV		R1 			#0
					STXDW	[R10-24] 	R1 -- materialize v1 = 0
					JEQ		R0 			#0 => 0009
					LDXDW	R7 			[R10-16]
					STXDW	[R10-24] 	R7 -- v1 = v0
					MOV		R0 #0
					EXIT	R0 #0
				]]
			}
		end)

	end)
end)
