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

local program = [[
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct key_t {
  u32 prev_pid;
  u32 curr_pid;
};
// map_type, key_type, leaf_type, table_name, num_entry
BPF_HASH(stats, struct key_t, u64, 1024);
int count_sched(struct pt_regs *ctx, struct task_struct *prev) {
  struct key_t key = {};
  u64 zero = 0, *val;

  key.curr_pid = bpf_get_current_pid_tgid();
  key.prev_pid = prev->pid;

  val = stats.lookup_or_init(&key, &zero);
  (*val)++;
  return 0;
}
]]

return function(BPF)
  local b = BPF:new{text=program, debug=0}
  b:attach_kprobe{event="finish_task_switch", fn_name="count_sched"}

  print("Press any key...")
  io.read()

  local t = b:get_table("stats")
  for k, v in t:items() do
    print("task_switch[%d -> %d] = %d" % {k.prev_pid, k.curr_pid, tonumber(v)})
  end
end
