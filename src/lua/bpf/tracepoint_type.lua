-- SPDX-License-Identifier: Apache-2.0
local M = {}

function M.from_format(fmt)
	local fields = {}
	for f in fmt:gmatch 'field:([^;]+;)' do
		-- __data_loc stores a 32-bit offset/length pair, not a pointer.
		f = f:gsub('^%s*__data_loc char%[%]', 'unsigned int')
		table.insert(fields, f)
	end
	return string.format('struct { %s }', table.concat(fields))
end

return M
