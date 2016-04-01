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

local function print_usage()
  io.stderr:write(
  "usage: bcc-probe [[--so-path=PATH|--version|--quiet] --] path_to_script.lua [...]\n")
  os.exit(1)
end

local function has_prefix(s,p)
  return string.sub(s,1,string.len(p))==p
end

local function strip_prefix(s,p)
  return string.sub(s, string.len(p) + 1)
end

return function()
  local logging = true

  while arg[1] and has_prefix(arg[1], "-") do
    local k = table.remove(arg, 1) 

    if k == "--" then
      break
    elseif has_prefix(k, "--so-path=") then
      rawset(_G, "LIBBCC_SO_PATH", strip_prefix(k, "--so-path="))
    elseif k == "-q" or k == "--quiet" then
      logging = false
    elseif k == "-v" or k == "--version" then
      local jit = require("jit")
      print(string.format("bcc-probe %s -- Running on %s (%s/%s)",
        rawget(_G, "BCC_VERSION") or "HEAD",
        jit.version, jit.os, jit.arch))
      return true
    else
      print_usage()
    end
  end

  local tracefile = table.remove(arg, 1)
  if not tracefile then print_usage() end

  local BCC = require("bcc.init")
  local BPF = BCC.BPF

  BPF.script_root(tracefile)
  log.enabled = logging

  local utils = {
    argparse = require("bcc.vendor.argparse"),
    posix = require("bcc.vendor.posix"),
    sym = BCC.sym
  }

  local command = dofile(tracefile)
  local res, err = pcall(command, BPF, utils)

  if not res then
    io.stderr:write("[ERROR] "..err.."\n")
  end

  BPF.cleanup_probes()
  return res, err
end
