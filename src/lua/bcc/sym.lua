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
local SYM = ffi.typeof("struct bcc_symbol[1]")

local function create_cache(pid)
  return {
    _CACHE = libbcc.bcc_symcache_new(pid or -1, nil),
    resolve = function(self, addr)
      local sym = SYM()
      if libbcc.bcc_symcache_resolve(self._CACHE, addr, sym) < 0 then
        return "[unknown]", 0x0
      end
      local name_res = ffi.string(sym[0].demangle_name)
      libbcc.bcc_symbol_free_demangle_name(sym);
      return name_res, sym[0].offset
    end
  }
end

local function check_path_symbol(module, symname, addr, pid)
  local sym = SYM()
  local module_path
  if libbcc.bcc_resolve_symname(module, symname, addr or 0x0, pid or 0, nil, sym) < 0 then
    if sym[0].module == nil then
      error("could not find library '%s' in the library path" % module)
    else
      module_path = ffi.string(sym[0].module)
      libbcc.bcc_procutils_free(sym[0].module)
      error("failed to resolve symbol '%s' in '%s'" % {
        symname, module_path})
    end
  end
  module_path = ffi.string(sym[0].module)
  libbcc.bcc_procutils_free(sym[0].module)
  return module_path, sym[0].offset
end

return { create_cache=create_cache, check_path_symbol=check_path_symbol }
