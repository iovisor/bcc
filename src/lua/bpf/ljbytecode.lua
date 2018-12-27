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
local jutil = require("jit.util")
local vmdef = require("jit.vmdef")
local bit = require('bit')
local shr, band = bit.rshift, bit.band

-- Decode LuaJIT 2.0 Byte Format
-- Reference: http://wiki.luajit.org/Bytecode-2.0
-- Thanks to LJ, we get code in portable bytecode with constants folded, basic
-- virtual registers allocated etc.
-- No SSA IR, type inference or advanced optimizations because the code wasn't traced yet.
local function decode_ins(func, pc)
	local ins, m = jutil.funcbc(func, pc)
	if not ins then return nil end
	local op, ma, mb, mc = band(ins, 0xff), band(m, 7), band(m, 15*8), band(m, 15*128)
	local a, b, c, d = band(shr(ins, 8), 0xff), nil, nil, shr(ins, 16)
	if mb ~= 0 then
		d = band(d, 0xff)
		b = shr(ins, 24)
	end
	if ma == 5 then          -- BCMuv
	    a = jutil.funcuvname(func, a)
	end
	if mc == 13*128 then     -- BCMjump
		c = pc+d-0x7fff
	elseif mc == 14*128 then -- BCMcdata
		c = jutil.funck(func, -d-1)
	elseif mc == 9*128 then  -- BCMint
		c = jutil.funck(func, d)
	elseif mc == 10*128 then -- BCMstr
		c = jutil.funck(func, -d-1)
	elseif mc == 5*128 then  -- BCMuv
	    c = jutil.funcuvname(func, d)
	end
	-- Convert version-specific opcode to string
	op = 6*op
	op = string.sub(vmdef.bcnames, op+1, op+6):match('[^%s]+')
	return pc, op, a, b, c, d
end

-- Decoder closure
local function decoder(func)
	local pc = 0
	return function ()
		pc = pc + 1
		return decode_ins(func, pc)
	end
end

-- Hexdump generated code
local function dump(func)
	return require('jit.bc').dump(func)
end

return {
	decode = decode_ins,
	decoder = decoder,
	dump = dump,
	funcinfo = function (...) return jutil.funcinfo(...) end,
}