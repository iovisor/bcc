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
local libbcc = require("bcc.libbcc")

local TracerPipe = require("bcc.tracerpipe")
local Table = require("bcc.table")
local Sym = require("bcc.sym")

local Bpf = class("BPF")

Bpf.static.open_kprobes = {}
Bpf.static.open_uprobes = {}
Bpf.static.perf_buffers = {}
Bpf.static.KPROBE_LIMIT = 1000
Bpf.static.tracer_pipe = nil
Bpf.static.DEFAULT_CFLAGS = {
  '-D__HAVE_BUILTIN_BSWAP16__',
  '-D__HAVE_BUILTIN_BSWAP32__',
  '-D__HAVE_BUILTIN_BSWAP64__',
}

function Bpf.static.check_probe_quota(n)
  local cur = table.count(Bpf.static.open_kprobes) + table.count(Bpf.static.open_uprobes)
  assert(cur + n <= Bpf.static.KPROBE_LIMIT, "number of open probes would exceed quota")
end

function Bpf.static.cleanup()
  local function detach_all(probe_type, all_probes)
    for key, fd in pairs(all_probes) do
      libbcc.bpf_close_perf_event_fd(fd)
      -- skip bcc-specific kprobes
      if not key:starts("bcc:") then
        if probe_type == "kprobes" then
          libbcc.bpf_detach_kprobe(key)
        elseif probe_type == "uprobes" then
          libbcc.bpf_detach_uprobe(key)
        end
      end
      all_probes[key] = nil
    end
  end

  detach_all("kprobes", Bpf.static.open_kprobes)
  detach_all("uprobes", Bpf.static.open_uprobes)

  for key, perf_buffer in pairs(Bpf.static.perf_buffers) do
    libbcc.perf_reader_free(perf_buffer)
    Bpf.static.perf_buffers[key] = nil
  end

  if Bpf.static.tracer_pipe ~= nil then
    Bpf.static.tracer_pipe:close()
  end
end

function Bpf.static.SymbolCache(pid)
  return Sym.create_cache(pid)
end

function Bpf.static.num_open_uprobes()
  return table.count(Bpf.static.open_uprobes)
end

function Bpf.static.num_open_kprobes()
  return table.count(Bpf.static.open_kprobes)
end

Bpf.static.SCRIPT_ROOT = "./"
function Bpf.static.script_root(root)
  local dir, file = root:match'(.*/)(.*)'
  Bpf.static.SCRIPT_ROOT = dir or "./"
  return Bpf
end

local function _find_file(script_root, filename)
  if filename == nil then
    return nil
  end

  if os.exists(filename) then
    return filename
  end

  if not filename:starts("/") then
    filename = script_root .. filename
    if os.exists(filename) then
      return filename
    end
  end

  assert(nil, "failed to find file "..filename.." (root="..script_root..")")
end

function Bpf:initialize(args)
  self.funcs = {}
  self.tables = {}

  if args.usdt and args.text then
    args.text = args.usdt:_get_text() .. args.text
  end

  local cflags = table.join(Bpf.DEFAULT_CFLAGS, args.cflags)
  local cflags_ary = ffi.new("const char *[?]", #cflags, cflags)

  local llvm_debug = rawget(_G, "LIBBCC_LLVM_DEBUG") or args.debug or 0
  assert(type(llvm_debug) == "number")

  if args.text then
    log.info("\n%s\n", args.text)
    self.module = libbcc.bpf_module_create_c_from_string(args.text, llvm_debug, cflags_ary, #cflags)
  elseif args.src_file then
    local src = _find_file(Bpf.SCRIPT_ROOT, args.src_file)

    if src:ends(".b") then
      local hdr = _find_file(Bpf.SCRIPT_ROOT, args.hdr_file)
      self.module = libbcc.bpf_module_create_b(src, hdr, llvm_debug)
    else
      self.module = libbcc.bpf_module_create_c(src, llvm_debug, cflags_ary, #cflags)
    end
  end

  assert(self.module ~= nil, "failed to compile BPF module")

  if args.usdt then
    args.usdt:_attach_uprobes(self)
  end
end

function Bpf:load_funcs(prog_type)
  prog_type = prog_type or "BPF_PROG_TYPE_KPROBE"

  local result = {}
  local fn_count = tonumber(libbcc.bpf_num_functions(self.module))

  for i = 0,fn_count-1 do
    local name = ffi.string(libbcc.bpf_function_name(self.module, i))
    table.insert(result, self:load_func(name, prog_type))
  end

  return result
end

function Bpf:load_func(fn_name, prog_type)
  if self.funcs[fn_name] ~= nil then
    return self.funcs[fn_name]
  end

  assert(libbcc.bpf_function_start(self.module, fn_name) ~= nil,
    "unknown program: "..fn_name)

  local fd = libbcc.bpf_prog_load(prog_type,
    fn_name,
    libbcc.bpf_function_start(self.module, fn_name),
    libbcc.bpf_function_size(self.module, fn_name),
    libbcc.bpf_module_license(self.module),
    libbcc.bpf_module_kern_version(self.module),
    0, nil, 0)

  assert(fd >= 0, "failed to load BPF program "..fn_name)
  log.info("loaded %s (%d)", fn_name, fd)

  local fn = {bpf=self, name=fn_name, fd=fd}
  self.funcs[fn_name] = fn
  return fn
end

function Bpf:dump_func(fn_name)
  local start = libbcc.bpf_function_start(self.module, fn_name)
  assert(start ~= nil, "unknown program")

  local len = libbcc.bpf_function_size(self.module, fn_name)
  return ffi.string(start, tonumber(len))
end

function Bpf:attach_uprobe(args)
  Bpf.check_probe_quota(1)

  local path, addr = Sym.check_path_symbol(args.name, args.sym, args.addr, args.pid)
  local fn = self:load_func(args.fn_name, 'BPF_PROG_TYPE_KPROBE')
  local ptype = args.retprobe and "r" or "p"
  local ev_name = string.format("%s_%s_0x%p", ptype, path:gsub("[^%a%d]", "_"), addr)
  local retprobe = args.retprobe and 1 or 0

  local res = libbcc.bpf_attach_uprobe(fn.fd, retprobe, ev_name, path, addr,
    args.pid or -1)

  assert(res >= 0, "failed to attach BPF to uprobe")
  self:probe_store("uprobe", ev_name, res)
  return self
end

function Bpf:attach_kprobe(args)
  -- TODO: allow the caller to glob multiple functions together
  Bpf.check_probe_quota(1)

  local fn = self:load_func(args.fn_name, 'BPF_PROG_TYPE_KPROBE')
  local event = args.event or ""
  local ptype = args.retprobe and "r" or "p"
  local ev_name = string.format("%s_%s", ptype, event:gsub("[%+%.]", "_"))
  local retprobe = args.retprobe and 1 or 0

  local res = libbcc.bpf_attach_kprobe(fn.fd, retprobe, ev_name, event)

  assert(res >= 0, "failed to attach BPF to kprobe")
  self:probe_store("kprobe", ev_name, res)
  return self
end

function Bpf:pipe()
  if Bpf.tracer_pipe == nil then
    Bpf.tracer_pipe = TracerPipe:new()
  end
  return Bpf.tracer_pipe
end

function Bpf:get_table(name, key_type, leaf_type)
  if self.tables[name] == nil then
    self.tables[name] = Table(self, name, key_type, leaf_type)
  end
  return self.tables[name]
end

function Bpf:probe_store(t, id, fd)
  if t == "kprobe" then
    Bpf.open_kprobes[id] = fd
  elseif t == "uprobe" then
    Bpf.open_uprobes[id] = fd
  else
    error("unknown probe type '%s'" % t)
  end

  log.info("%s -> %s", id, fd)
end

function Bpf:perf_buffer_store(id, reader)
    Bpf.perf_buffers[id] = reader

    log.info("%s -> %s", id, reader)
end

function Bpf:probe_lookup(t, id)
  if t == "kprobe" then
    return Bpf.open_kprobes[id]
  elseif t == "uprobe" then
    return Bpf.open_uprobes[id]
  else
    return nil
  end
end

function Bpf:_perf_buffer_array()
  local perf_buffer_count = table.count(Bpf.perf_buffers)
  local readers = ffi.new("struct perf_reader*[?]", perf_buffer_count)
  local n = 0

  for _, r in pairs(Bpf.perf_buffers) do
    readers[n] = r
    n = n + 1
  end

  assert(n == perf_buffer_count)
  return readers, n
end

function Bpf:perf_buffer_poll_loop()
  local perf_buffers, perf_buffer_count = self:_perf_buffer_array()
  return pcall(function()
    while true do
      libbcc.perf_reader_poll(perf_buffer_count, perf_buffers, -1)
    end
  end)
end

function Bpf:kprobe_poll_loop()
  return self:perf_buffer_poll_loop()
end

function Bpf:perf_buffer_poll(timeout)
  local perf_buffers, perf_buffer_count = self:_perf_buffer_array()
  libbcc.perf_reader_poll(perf_buffer_count, perf_buffers, timeout or -1)
end

function Bpf:kprobe_poll(timeout)
  self:perf_buffer_poll(timeout)
end

return Bpf
