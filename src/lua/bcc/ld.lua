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
local ffi = require("ffi")
local posix = require("bcc.vendor.posix")

local _find_library_cache = {}
local function _find_library(name)
  if _find_library_cache[name] ~= nil then
    return _find_library_cache[name]
  end

  local arch = ffi.arch
  local abi_type = "libc6"

  if ffi.abi("64bit") then
    if arch == "x64" then
      abi_type = abi_type .. ",x86-64"
    elseif arch == "ppc" or arch == "mips" then
      abi_type = abi_type .. ",64bit"
    end
  end

  local pattern = "%s+lib" .. name:escape() .. "%.%S+ %(" .. abi_type:escape() .. ".-%) => (%S+)"
  local f = assert(io.popen("/sbin/ldconfig -p"))
  local path = nil

  for line in f:lines() do
    path = line:match(pattern)
    if path then break end
  end
  f:close()

  if path then
    _find_library_cache[name] = path
  end

  return path
end

local _find_load_address_cache = {}
local function _find_load_address(path)
  if _find_load_address_cache[path] ~= nil then
    return _find_load_address_cache[path]
  end

  local addr = os.spawn(
    [[/usr/bin/objdump -x %s | awk '$1 == "LOAD" && $3 ~ /^[0x]*$/ { print $5 }']],
    path)

  if addr then
    addr = posix.tonumber64(addr, 16)
    _find_load_address_cache[path] = addr
  end

  return addr
end

local _find_symbol_cache = {}
local function _find_symbol(path, sym)
  assert(path and sym)

  if _find_symbol_cache[path] == nil then
    _find_symbol_cache[path] = {}
  end

  local symbols = _find_symbol_cache[path]
  if symbols[sym] ~= nil then
    return symbols[sym]
  end

  local addr = os.spawn(
    [[/usr/bin/objdump -tT %s | awk -v sym=%s '$NF == sym && $4 == ".text" { print $1; exit }']],
    path, sym)

  if addr then
    addr = posix.tonumber64(addr, 16)
    symbols[sym] = addr
  end

  return addr
end

local function _check_path_symbol(name, sym, addr)
  assert(name)

  local path = name:sub(1,1) == "/" and name or _find_library(name)
  assert(path, "could not find library "..name)

  -- TODO: realpath
  local load_addr = _find_load_address(path)
  assert(load_addr, "could not find load address for "..path)

  if addr == nil and sym ~= nil then
    addr = _find_symbol(path, sym)
  end

  assert(addr, "could not find address of symbol "..sym)
  return path, (addr - load_addr)
end

return {
  check_path_symbol=_check_path_symbol,
  find_symbol=_find_symbol,
  find_load_address=_find_load_address,
  find_library=_find_library
}
