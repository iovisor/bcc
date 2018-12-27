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
--]]

local program = [[
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

struct val_t {
    u32 pid;
    char name[TASK_COMM_LEN];
};

struct data_t {
    u32 pid;
    u64 rwflag;
    u64 delta;
    u64 sector;
    u64 len;
    u64 ts;
    char disk_name[DISK_NAME_LEN];
    char name[TASK_COMM_LEN];
};

BPF_HASH(start, struct request *);
BPF_HASH(infobyreq, struct request *, struct val_t);
BPF_PERF_OUTPUT(events);

// cache PID and comm by-req
int trace_pid_start(struct pt_regs *ctx, struct request *req)
{
    struct val_t val = {};

    if (bpf_get_current_comm(&val.name, sizeof(val.name)) == 0) {
        val.pid = bpf_get_current_pid_tgid();
        infobyreq.update(&req, &val);
    }
    return 0;
}

// time block I/O
int trace_req_start(struct pt_regs *ctx, struct request *req)
{
    u64 ts;

    ts = bpf_ktime_get_ns();
    start.update(&req, &ts);

    return 0;
}

// output
int trace_req_completion(struct pt_regs *ctx, struct request *req)
{
    u64 *tsp, delta;
    u32 *pidp = 0;
    struct val_t *valp;
    struct data_t data ={};
    u64 ts;

    // fetch timestamp and calculate delta
    tsp = start.lookup(&req);
    if (tsp == 0) {
        // missed tracing issue
        return 0;
    }
    ts = bpf_ktime_get_ns();
    data.delta = ts - *tsp;
    data.ts = ts / 1000;

    valp = infobyreq.lookup(&req);
    if (valp == 0) {
        data.len = req->__data_len;
        strcpy(data.name,"?");
    } else {
        data.pid = valp->pid;
        data.len = req->__data_len;
        data.sector = req->__sector;
        bpf_probe_read(&data.name, sizeof(data.name), valp->name);
        bpf_probe_read(&data.disk_name, sizeof(data.disk_name),
                       req->rq_disk->disk_name);
    }

/*
 * The following deals with a kernel version change (in mainline 4.7, although
 * it may be backported to earlier kernels) with how block request write flags
 * are tested. We handle both pre- and post-change versions here. Please avoid
 * kernel version tests like this as much as possible: they inflate the code,
 * test, and maintenance burden.
 */
#ifdef REQ_WRITE
    data.rwflag = !!(req->cmd_flags & REQ_WRITE);
#elif defined(REQ_OP_SHIFT)
    data.rwflag = !!((req->cmd_flags >> REQ_OP_SHIFT) == REQ_OP_WRITE);
#else
    data.rwflag = !!((req->cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE);
#endif

    events.perf_submit(ctx,&data,sizeof(data));
    start.delete(&req);
    infobyreq.delete(&req);

    return 0;
}
]]

local ffi = require("ffi")

return function(BPF, utils)
  local bpf = BPF:new{text=program}

  bpf:attach_kprobe{event="blk_account_io_start", fn_name="trace_pid_start"}
  bpf:attach_kprobe{event="blk_start_request", fn_name="trace_req_start"}
  bpf:attach_kprobe{event="blk_mq_start_request", fn_name="trace_req_start"}
  bpf:attach_kprobe{event="blk_account_io_completion",
      fn_name="trace_req_completion"}

  print("%-14s %-14s %-6s %-7s %-2s %-9s %-7s %7s" % {"TIME(s)", "COMM", "PID",
    "DISK", "T", "SECTOR", "BYTES", "LAT(ms)"})

  local rwflg = ""
  local start_ts = 0
  local prev_ts = 0
  local delta = 0

  local function print_event(cpu, event)
    local val = -1
    local event_pid = event.pid
    local event_delta = tonumber(event.delta)
    local event_sector = tonumber(event.sector)
    local event_len = tonumber(event.len)
    local event_ts = tonumber(event.ts)
    local event_disk_name = ffi.string(event.disk_name)
    local event_name = ffi.string(event.name)

    if event.rwflag == 1 then
      rwflg = "W"
    end

    if event.rwflag == 0 then
      rwflg = "R"
    end

    if not event_name:match("%?") then
      val = event_sector
    end

    if start_ts == 0 then
      prev_ts = start_ts
    end

    if start_ts == 1 then
      delta = delta + (event_ts - prev_ts)
    end

    print("%-14.9f %-14.14s %-6s %-7s %-2s %-9s %-7s %7.2f" % {
      delta / 1000000, event_name, event_pid, event_disk_name, rwflg, val,
      event_len, event_delta / 1000000})

    prev_ts = event_ts
    start_ts = 1
  end

  local TASK_COMM_LEN = 16 -- linux/sched.h
  local DISK_NAME_LEN = 32 -- linux/genhd.h

  bpf:get_table("events"):open_perf_buffer(print_event, [[
    struct {
      uint32_t pid;
      uint64_t rwflag;
      uint64_t delta;
      uint64_t sector;
      uint64_t len;
      uint64_t ts;
      char disk_name[$];
      char name[$];
    }
  ]], {DISK_NAME_LEN, TASK_COMM_LEN}, 64)
  bpf:perf_buffer_poll_loop()
end
