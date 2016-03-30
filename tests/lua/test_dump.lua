local suite = require("test_helper")
local TestDump = {}

function TestDump:test_dump_func()
  local raw = "\xb7\x00\x00\x00\x01\x00\x00\x00\x95\x00\x00\x00\x00\x00\x00\x00"
  local b = BPF:new{text=[[int entry(void) { return 1; }]]}
  assert_equals(b:dump_func("entry"), raw)
end

suite("TestDump", TestDump)
