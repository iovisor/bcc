std = 'luajit'

new_read_globals = {
	'assert',
	'describe',
	'it',
}
new_globals = {
	'math',
}

-- Luacheck < 0.18 doesn't support new_read_globals
for _, v in ipairs(new_read_globals) do
	table.insert(new_globals, v)
end

-- Ignore some pedantic checks
ignore = {
	'4.1/err', -- Shadowing err
	'4.1/.',   -- Shadowing one letter variables
}
