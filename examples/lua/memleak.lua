#!/usr/bin/env bcc-lua
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

local bpf_source = [[
#include <uapi/linux/ptrace.h>

struct alloc_info_t {
        u64 size;
        u64 timestamp_ns;
        int stack_id;
};

BPF_HASH(sizes, u64);
BPF_HASH(allocs, u64, struct alloc_info_t);
BPF_STACK_TRACE(stack_traces, 10240);

int alloc_enter(struct pt_regs *ctx, size_t size)
{
        SIZE_FILTER
        if (SAMPLE_EVERY_N > 1) {
                u64 ts = bpf_ktime_get_ns();
                if (ts % SAMPLE_EVERY_N != 0)
                        return 0;
        }

        u64 pid = bpf_get_current_pid_tgid();
        u64 size64 = size;
        sizes.update(&pid, &size64);

        if (SHOULD_PRINT)
                bpf_trace_printk("alloc entered, size = %u\n", size);
        return 0;
}

int alloc_exit(struct pt_regs *ctx)
{
        u64 address = PT_REGS_RC(ctx);
        u64 pid = bpf_get_current_pid_tgid();
        u64* size64 = sizes.lookup(&pid);
        struct alloc_info_t info = {0};

        if (size64 == 0)
                return 0; // missed alloc entry

        info.size = *size64;
        sizes.delete(&pid);

        info.timestamp_ns = bpf_ktime_get_ns();
        info.stack_id = stack_traces.get_stackid(ctx, STACK_FLAGS);

        allocs.update(&address, &info);

        if (SHOULD_PRINT) {
                bpf_trace_printk("alloc exited, size = %lu, result = %lx\n",
                                 info.size, address);
        }
        return 0;
}

int free_enter(struct pt_regs *ctx, void *address)
{
        u64 addr = (u64)address;
        struct alloc_info_t *info = allocs.lookup(&addr);
        if (info == 0)
                return 0;

        allocs.delete(&addr);

        if (SHOULD_PRINT) {
                bpf_trace_printk("free entered, address = %lx, size = %lu\n",
                                 address, info->size);
        }
        return 0;
}
]]

return function(BPF, utils)
  local parser = utils.argparse("memleak", "Catch memory leaks")
  parser:flag("-t --trace")
  parser:flag("-a --show-allocs")
  parser:option("-p --pid"):convert(tonumber)

  parser:option("-i --interval", "", 5):convert(tonumber)
  parser:option("-o --older", "", 500):convert(tonumber)
  parser:option("-s --sample-rate", "", 1):convert(tonumber)

  parser:option("-z --min-size", ""):convert(tonumber)
  parser:option("-Z --max-size", ""):convert(tonumber)
  parser:option("-T --top", "", 10):convert(tonumber)

  local args = parser:parse()

  local size_filter = ""
  if args.min_size and args.max_size then
    size_filter = "if (size < %d || size > %d) return 0;" %  {args.min_size, args.max_size}
  elseif args.min_size then
    size_filter = "if (size < %d) return 0;" % args.min_size
  elseif args.max_size then
    size_filter = "if (size > %d) return 0;" % args.max_size
  end

  local stack_flags = "BPF_F_REUSE_STACKID"
  if args.pid then
    stack_flags = stack_flags .. "|BPF_F_USER_STACK"
  end

  local text = bpf_source
  text = text:gsub("SIZE_FILTER", size_filter)
  text = text:gsub("STACK_FLAGS",  stack_flags)
  text = text:gsub("SHOULD_PRINT", args.trace and "1" or "0")
  text = text:gsub("SAMPLE_EVERY_N", tostring(args.sample_rate))

  local bpf = BPF:new{text=text, debug=0}
  local syms = nil
  local min_age_ns = args.older * 1e6

  if args.pid then
    print("Attaching to malloc and free in pid %d, Ctrl+C to quit." % args.pid)
    bpf:attach_uprobe{name="c", sym="malloc", fn_name="alloc_enter", pid=args.pid}
    bpf:attach_uprobe{name="c", sym="malloc", fn_name="alloc_exit", pid=args.pid, retprobe=true}
    bpf:attach_uprobe{name="c", sym="free", fn_name="free_enter", pid=args.pid}
  else
    print("Attaching to kmalloc and kfree, Ctrl+C to quit.")
    bpf:attach_kprobe{event="__kmalloc", fn_name="alloc_enter"}
    bpf:attach_kprobe{event="__kmalloc", fn_name="alloc_exit", retprobe=true} -- TODO
    bpf:attach_kprobe{event="kfree", fn_name="free_enter"}
  end

  local syms = BPF.SymbolCache(args.pid)
  local allocs = bpf:get_table("allocs")
  local stack_traces = bpf:get_table("stack_traces")

  local function resolve(addr)
    local sym = syms:resolve(addr)
    if args.pid == nil then
      sym = sym .. " [kernel]"
    end
    return string.format("%s (%p)", sym, addr)
  end

  local function print_outstanding()
    local alloc_info = {}
    local now = utils.posix.time_ns()

    print("[%s] Top %d stacks with outstanding allocations:" %
      {os.date("%H:%M:%S"), args.top})

    for address, info in allocs:items() do
      if now - min_age_ns >= tonumber(info.timestamp_ns) then
        local stack_id = tonumber(info.stack_id)

        if stack_id >= 0 then
          if alloc_info[stack_id] then
            local s = alloc_info[stack_id]
            s.count = s.count + 1
            s.size = s.size + tonumber(info.size)
          else
            local stack = stack_traces:get(stack_id, resolve)
            alloc_info[stack_id] = { stack=stack, count=1, size=tonumber(info.size) }
          end
        end

        if args.show_allocs then
          print("\taddr = %p size = %s" % {address, tonumber(info.size)})
        end
      end
    end

    local top = table.values(alloc_info)
    table.sort(top, function(a, b) return a.size > b.size end)

    for n, alloc in ipairs(top) do
      print("\t%d bytes in %d allocations from stack\n\t\t%s" %
        {alloc.size, alloc.count, table.concat(alloc.stack, "\n\t\t")})
      if n == args.top then break end
    end
  end

  if args.trace then
    local pipe = bpf:pipe()
    while true do
      print(pipe:trace_fields())
    end
  else
    while true do
      utils.posix.sleep(args.interval)
      syms:refresh()
      print_outstanding()
    end
  end
end
