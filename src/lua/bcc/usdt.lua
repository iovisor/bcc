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
local Usdt = class("USDT")

Usdt.static.open_contexts = {}

function Usdt.static.cleanup()
  for _, context in ipairs(Usdt.static.open_contexts) do
    context:_cleanup()
  end
end

function Usdt:initialize(args)
  assert(args.pid or args.path)

  if args.pid then
    self.pid = args.pid
    self.context = libbcc.bcc_usdt_new_frompid(args.pid)
  elseif args.path then
    self.path = args.path
    self.context = libbcc.bcc_usdt_new_frompath(args.path)
  end

  assert(self.context ~= nil, "failed to create USDT context")
  table.insert(Usdt.open_contexts, self)
end

function Usdt:enable_probe(args)
  assert(args.probe and args.fn_name)
  assert(libbcc.bcc_usdt_enable_probe(
    self.context, args.probe, args.fn_name) == 0)
end

function Usdt:_cleanup()
  libbcc.bcc_usdt_close(self.context)
  self.context = nil
end

function Usdt:_get_text()
  local argc = libbcc.bcc_usdt_genargs(self.context)
  assert(argc ~= nil)
  return ffi.string(argc)
end

function Usdt:_attach_uprobes(bpf)
  local uprobes = {}
  local cb = ffi.cast("bcc_usdt_uprobe_cb",
    function(binpath, fn_name, addr, pid)
      table.insert(uprobes, {name=ffi.string(binpath),
        addr=addr, fn_name=ffi.string(fn_name), pid=pid})
    end)

  libbcc.bcc_usdt_foreach_uprobe(self.context, cb)
  cb:free()

  for _, args in ipairs(uprobes) do
    bpf:attach_uprobe(args)
  end
end

return Usdt
