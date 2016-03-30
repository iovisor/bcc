function setup_path()
  local str = require("debug").getinfo(2, "S").source:sub(2)
  local cwd = str:match("(.*/)")
  local bpf_path = cwd.."/../../src/lua/?.lua;"
  local test_path = cwd.."/?.lua;"
  package.path = bpf_path..test_path..package.path
end

setup_path()

USE_EXPECTED_ACTUAL_IN_ASSERT_EQUALS = false
EXPORT_ASSERT_TO_GLOBALS = true
require("luaunit")

BCC = require("bcc.init")
BPF = BCC.BPF
log.enabled = false
