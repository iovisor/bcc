local suite = require("test_helper")
local ffi = require("ffi")
local TestUprobes = {}

ffi.cdef[[
  int getpid(void);
  void malloc_stats(void);
]]

function TestUprobes:test_simple_library()
  local text = [[
#include <uapi/linux/ptrace.h>
BPF_ARRAY(stats, u64, 1);
static void incr(int idx) {
    u64 *ptr = stats.lookup(&idx);
    if (ptr)
        ++(*ptr);
}
int count(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    if (pid == PID)
        incr(0);
    return 0;
}]]

  local pid = tonumber(ffi.C.getpid())
  local text = text:gsub("PID", tostring(pid))

  local b = BPF:new{text=text}
  b:attach_uprobe{name="c", sym="malloc_stats", fn_name="count", pid=pid}
  b:attach_uprobe{name="c", sym="malloc_stats", fn_name="count", pid=pid, retprobe=true}

  assert_equals(BPF.num_open_uprobes(), 2)

  ffi.C.malloc_stats()

  local stats = b:get_table("stats")
  assert_equals(tonumber(stats:get(0)), 2)
end

function TestUprobes:test_simple_binary()
  local text = [[
#include <uapi/linux/ptrace.h>
BPF_ARRAY(stats, u64, 1);
static void incr(int idx) {
    u64 *ptr = stats.lookup(&idx);
    if (ptr)
        ++(*ptr);
}
int count(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    incr(0);
    return 0;
}]]

  local b = BPF:new{text=text}
  b:attach_uprobe{name="/usr/bin/python", sym="main", fn_name="count"}
  b:attach_uprobe{name="/usr/bin/python", sym="main", fn_name="count", retprobe=true}

  os.spawn("/usr/bin/python -V")

  local stats = b:get_table("stats")
  assert_true(tonumber(stats:get(0)) >= 2)
end

function TestUprobes:teardown()
  BPF.cleanup()
end

suite("TestUprobes", TestUprobes)
