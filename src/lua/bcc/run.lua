--[[
Copyright 2016 GitHub, Inc

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

return function()
  require("bcc.vendor.helpers")
  local standalone = rawget(_G, "BCC_STANDALONE")
  local progname = standalone or "bcc-probe"

  local function print_usage()
    io.stderr:write(string.format(
      "usage: %s [[--version|--verbose] --] path_to_script.lua [...]\n",
      progname))
    os.exit(1)
  end

  local function print_version()
    local jit = require("jit")
    print(string.format("%s %s -- Running on %s (%s/%s)",
      progname, rawget(_G, "BCC_VERSION") or "HEAD",
      jit.version, jit.os, jit.arch))
    os.exit(0)
  end

  while arg[1] and string.starts(arg[1], "-") do
    local k = table.remove(arg, 1)
    if k == "--" then
      break
    elseif standalone == nil and string.starts(k, "--so-path=") then
      rawset(_G, "LIBBCC_SO_PATH", string.lstrip(k, "--so-path="))
    elseif k == "--llvm-debug" then
      rawset(_G, "LIBBCC_LLVM_DEBUG", 1)
    elseif k == "-V" or k == "--verbose" then
      log.enabled = true
    elseif k == "-v" or k == "--version" then
      print_version()
    else
      print_usage()
    end
  end

  local tracefile = table.remove(arg, 1)
  if not tracefile then print_usage() end

  local BPF = require("bcc.bpf")
  BPF.script_root(tracefile)

  local USDT = require("bcc.usdt")
  local utils = {
    argparse = require("bcc.vendor.argparse"),
    posix = require("bcc.vendor.posix"),
    USDT = USDT,
  }

  local command = dofile(tracefile)
  local res, err = xpcall(command, debug.traceback, BPF, utils)

  if not res and err ~= "interrupted!" then
    io.stderr:write("[ERROR] "..err.."\n")
  end

  BPF.cleanup()
  USDT.cleanup()
  return res, err
end
