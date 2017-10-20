std = "luajit"
ignore = { "211", "212", "411", "412", "421", "431", "542" }
files["examples"] = {
	new_globals = { "pkt", "time", "xadd", "c" }
}
files["bpf/builtins.lua"] = {
	ignore = { "122" }
}
files["spec"] = {
	std = "+busted",
	new_globals = { "pkt", "time", "xadd", "c" }
}