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
local TracerPipe = class("TracerPipe")

TracerPipe.static.TRACEFS = "/sys/kernel/debug/tracing"
TracerPipe.static.fields = "%s+(.-)%-(%d+)%s+%[(%d+)%]%s+(....)%s+([%d%.]+):.-:%s+(.+)"

function TracerPipe:close()
  if self.pipe ~= nil then
    self.pipe:close()
  end
end

function TracerPipe:open()
  if self.pipe == nil then
    self.pipe = assert(io.open(TracerPipe.TRACEFS .. "/trace_pipe"))
  end
  return self.pipe
end

function TracerPipe:readline()
  return self:open():read()
end

function TracerPipe:trace_fields()
  while true do
    local line = self:readline()
    if not line and self.nonblocking then
      return nil
    end

    if not line:starts("CPU:") then
      local task, pid, cpu, flags, ts, msg = line:match(TracerPipe.fields)
      if task ~= nil then
        return task, tonumber(pid), tonumber(cpu), flags, tonumber(ts), msg
      end
    end
  end
end

function TracerPipe:initialize(nonblocking)
  self.nonblocking = nonblocking
end

return TracerPipe
