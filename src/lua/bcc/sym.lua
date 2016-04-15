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
local posix = require("bcc.vendor.posix")
local ProcSymbols = class("ProcSymbols")

function ProcSymbols:initialize(pid)
  self.pid = pid
  self:refresh()
end

function ProcSymbols:_get_exe()
  return os.spawn("readlink -f /proc/%d/exe", self.pid)
end

function ProcSymbols:_get_start_time()
  return tonumber(os.spawn("cut -d' ' -f 22 /proc/%d/stat", self.pid))
end

function ProcSymbols:_get_code_ranges()
  local function is_binary_segment(parts)
    if #parts ~= 6 then return false end
    if parts[6]:starts("[") then return false end
    if parts[2]:find("x") == nil then return false end
    return true
  end

  local ranges = {}
  local cmd = string.format("/proc/%d/maps", self.pid)

  for line in io.lines(cmd) do
    local parts = line:split()
    if is_binary_segment(parts) then
      local binary = parts[6]
      local range = parts[1]:split("-", true)
      assert(#range == 2)

      ranges[binary] = {posix.tonumber64(range[1], 16), posix.tonumber64(range[2], 16)}
    end
  end

  return ranges
end

function ProcSymbols:refresh()
  self.code_ranges = self:_get_code_ranges()
  self.ranges_cache = {}
  self.exe = self:_get_exe()
  self.start_time = self:_get_start_time()
end

function ProcSymbols:_check_pid_wrap()
  local new_exe = self:_get_exe()
  local new_time = self:_get_start_time()
  if self.exe ~= new_exe or self.start_time ~= new_time then
    self:refresh()
  end
end

function ProcSymbols:_get_sym_ranges(binary)
  if self.ranges_cache[binary] ~= nil then
    return self.ranges_cache[binary]
  end

  local function is_function_sym(parts)
    return #parts == 6 and parts[4] == ".text" and parts[3] == "F"
  end

  local sym_ranges = {}
  local proc = assert(io.popen("objdump -t "..binary))

  for line in proc:lines() do
    local parts = line:split()
    if is_function_sym(parts) then
      local sym_start = posix.tonumber64(parts[1], 16)
      local sym_len = posix.tonumber64(parts[5], 16)
      local sym_name = parts[6]
      sym_ranges[sym_name] = {sym_start, sym_len}
    end
  end
  proc:close()

  self.ranges_cache[binary] = sym_ranges
  return sym_ranges
end

function ProcSymbols:_decode_sym(binary, offset)
  local sym_ranges = self:_get_sym_ranges(binary)

  for name, range in pairs(sym_ranges) do
    local start = range[1]
    local length = range[2]
    if offset >= start and offset <= (start + length) then
      return string.format("%s+0x%p", name, offset - start)
    end
  end
  return string.format("%p", offset)
end

function ProcSymbols:lookup(addr)
  self:_check_pid_wrap()

  for binary, range in pairs(self.code_ranges) do
    local start = range[1]
    local tend = range[2]

    if addr >= start and addr <= tend then
      local offset = binary:ends(".so") and (addr - start) or addr
      return string.format("%s [%s]", self:_decode_sym(binary, offset), binary)
    end
  end

  return string.format("%p", addr)
end

local KSymbols = class("KSymbols")

KSymbols.static.KALLSYMS = "/proc/kallsyms"

function KSymbols:initialize()
  self.ksyms = {}
  self.ksym_names = {}
  self.loaded = false
end

function KSymbols:_load()
  if self.loaded then return end
  local first_line = true

  for line in io.lines(KSymbols.KALLSYMS) do
    if not first_line then
      local cols = line:split()
      local name = cols[3]
      local addr = posix.tonumber64(cols[1], 16)
      table.insert(self.ksyms, {name, addr})
      self.ksym_names[name] = #self.ksyms
    end
    first_line = false
  end
  self.loaded = true
end

function KSymbols:_addr2index(addr)
  self:_load()
  return table.bsearch(self.ksyms, addr, function(v) return v[2] end)
end

function KSymbols:lookup(addr, with_offset)
  local idx = self:_addr2index(addr)
  if idx == nil then
    return "[unknown]"
  end

  if with_offset then
    local offset = addr - self.ksyms[idx][2]
    return "%s %p" % {self.ksyms[idx][1], offset}
  else
    return self.ksyms[idx][1]
  end
end

function KSymbols:refresh()
  -- NOOP
end

return { ProcSymbols=ProcSymbols, KSymbols=KSymbols }
