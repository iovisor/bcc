#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# funcslower  Trace slow kernel or user function calls.
#             For Linux, uses BCC, eBPF.
#
# USAGE: funcslower [-h] [-p PID] [-m MIN_MS] [-u MIN_US] [-a ARGUMENTS]
#                   [-T] [-t] [-v] function [function ...]
#
# WARNING: This tool traces function calls by instrumenting the entry and
# return from each function. For commonly-invoked functions like memory allocs
# or file writes, this can be extremely expensive. Mind the overhead.
#
# NOTE: This tool cannot trace nested functions in the same invocation
# due to instrumentation specifics, only innermost calls will be visible.
#
# By default, a minimum millisecond threshold of 1 is used.
#
# Copyright 2017, Sasha Goldshtein
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 30-Mar-2017   Sasha Goldshtein    Created this.

from __future__ import print_function
from bcc import BPF, PerfType, PerfSWConfig
from bcc.containers import filter_by_containers
import argparse
import time

examples = """examples:
  ./funcslower syscall:write    # trace syscall write calls slower than 1ms
  ./funcslower vfs_write        # same  but trace vfs_write
  ./funcslower -m 10 vfs_write  # same, but slower than 10ms
  ./funcslower -u 10 c:open     # trace open calls slower than 10us
  ./funcslower -p 135 c:open    # trace pid 135 only
  ./funcslower c:malloc c:free  # trace both malloc and free slower than 1ms
  ./funcslower -a 2 c:open      # show first two arguments to open
  ./funcslower -UK -m 10 c:open # Show user and kernel stack frame of open calls slower than 10ms
  ./funcslower -f -UK :open    # Output in folded format for flame graphs
"""
parser = argparse.ArgumentParser(
    description="Trace slow kernel or user function calls.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid", type=int, metavar="PID", dest="tgid",
    help="trace this PID only")
parser.add_argument("-m", "--min-ms", type=float, dest="min_ms",
    help="minimum duration to trace (ms)")
parser.add_argument("-u", "--min-us", type=float, dest="min_us",
    help="minimum duration to trace (us)")
parser.add_argument("-a", "--arguments", type=int,
    help="print this many entry arguments, as hex")
parser.add_argument("-T", "--time", action="store_true",
    help="show HH:MM:SS timestamp")
parser.add_argument("-t", "--timestamp", action="store_true",
    help="show timestamp in seconds at us resolution")
parser.add_argument("-v", "--verbose", action="store_true",
    help="print the BPF program for debugging purposes")
parser.add_argument(metavar="function", nargs="+", dest="functions",
    help="function(s) to trace")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
parser.add_argument("--cgroupmap",
    help="trace cgroups in this BPF map only")
parser.add_argument("--mntnsmap",
    help="trace mount namespaces in this BPF map only")
parser.add_argument("-f", "--folded", action="store_true",
    help="output folded format, one line per stack (for flame graphs)")
parser.add_argument("-U", "--user-stack",
  action="store_true", help="output user stack trace")
parser.add_argument("-K", "--kernel-stack",
  action="store_true", help="output kernel stack trace")

parser.add_argument("-C", "--cpu", type=int, default=-1,
    help="cpu number to run profile on")
parser.add_argument("-B", "--profile-blocked",
    action="store_true", help="profile stack trace on task schedule")
parser.add_argument("-S", "--profile-stack",
    action="store_true", help="profile stack trace after timeout")
parser.add_argument("-F", "--profile-frequency",  type=int,
    help="profile frequency", default=49)
parser.add_argument("-P", "--profile-functions", metavar="function", nargs="+",
                    dest="profile_functions", default=[],
                    help="additional list of profile events")

args = parser.parse_args()
# fractions are allowed, but rounded to an integer nanosecond
if args.min_ms:
    duration_ns = int(args.min_ms * 1000000)
elif args.min_us:
    duration_ns = int(args.min_us * 1000)
else:
    duration_ns = 1000000   # default to 1ms

class EventType(object):
    EVENT_RET = 0
    EVENT_SCHEDULE = 1
    EVENT_SAMPLE = 2

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
#include <linux/sched.h>    // for TASK_COMM_LEN

enum event_type {
    EVENT_RET = 0,
    EVENT_SCHEDULE = 1,
    EVENT_SAMPLE = 2,
};

struct entry_t {
    u64 id;
    u64 start_ns;
#ifdef GRAB_ARGS
#ifndef __s390x__
    u64 args[6];
#else
    u64 args[5];
#endif
#endif
};

struct event_t {
    u32 id;
    enum event_type type;
    u64 tgid_pid;
    u64 start_ns;
    u64 duration_ns;
    u64 retval;
    char comm[TASK_COMM_LEN];
#ifdef GRAB_ARGS
#ifndef __s390x__
    u64 args[6];
#else
    u64 args[5];
#endif
#endif
#ifdef USER_STACKS
    int user_stack_id;
#endif
#ifdef KERNEL_STACKS
    int kernel_stack_id;
    u64 kernel_ip;
#endif
};

BPF_HASH(entryinfo, u64, struct entry_t);
BPF_PERF_OUTPUT(events);

#if defined(USER_STACKS) || defined(KERNEL_STACKS)
struct profile_t {
    u64 count;     // Number of samples
    u64 first_ns;  // Timestamp of first sample
    u64 last_ns;   // Timestamp of last sample
    u64 total_ns;  // Total amount of time samples
};

BPF_HASH(blocked, u64, u64);
BPF_HASH(profileinfo,  struct event_t, struct profile_t);
BPF_STACK_TRACE(stacks, 2048);
#endif

static int trace_entry(struct pt_regs *ctx, int id)
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 tgid = tgid_pid >> 32;
    if (TGID_FILTER)
        return 0;
    if (container_should_be_filtered())
        return 0;

    u32 pid = tgid_pid;

    struct entry_t entry = {};
    entry.start_ns = bpf_ktime_get_ns();
    entry.id = id;
#ifdef GRAB_ARGS
    entry.args[0] = PT_REGS_PARM1(ctx);
    entry.args[1] = PT_REGS_PARM2(ctx);
    entry.args[2] = PT_REGS_PARM3(ctx);
    entry.args[3] = PT_REGS_PARM4(ctx);
    entry.args[4] = PT_REGS_PARM5(ctx);
#ifndef __s390x__
    entry.args[5] = PT_REGS_PARM6(ctx);
#endif
#endif

    entryinfo.update(&tgid_pid, &entry);

    return 0;
}

static void fill_event(struct event_t *e, enum event_type type, u64 id, u64 tgid_pid, struct pt_regs *regs, u64 start_ns, u64 delta_ns)
{
    e->id = id;
    e->type = type;
    e->tgid_pid = tgid_pid;
    e->start_ns = start_ns;
    e->duration_ns = delta_ns;
    e->retval = PT_REGS_RC(regs);

#ifdef USER_STACKS
    e->user_stack_id = stacks.get_stackid(regs, BPF_F_USER_STACK);
#endif

#ifdef KERNEL_STACKS
    e->kernel_stack_id = stacks.get_stackid(regs, 0);

    if (e->kernel_stack_id >= 0) {
        u64 ip = PT_REGS_IP(regs);
        u64 page_offset;

        // if ip isn't sane, leave key ips as zero for later checking
#if defined(CONFIG_X86_64) && defined(__PAGE_OFFSET_BASE)
        // x64, 4.16, ..., 4.11, etc., but some earlier kernel didn't have it
        page_offset = __PAGE_OFFSET_BASE;
#elif defined(CONFIG_X86_64) && defined(__PAGE_OFFSET_BASE_L4)
        // x64, 4.17, and later
#if defined(CONFIG_DYNAMIC_MEMORY_LAYOUT) && defined(CONFIG_X86_5LEVEL)
        page_offset = __PAGE_OFFSET_BASE_L5;
#else
        page_offset = __PAGE_OFFSET_BASE_L4;
#endif
#else
        // earlier x86_64 kernels, e.g., 4.6, comes here
        // arm64, s390, powerpc, x86_32
        page_offset = PAGE_OFFSET;
#endif

        if (ip > page_offset && type == EVENT_RET) {
            e->kernel_ip = ip;
        }
    }
#endif

}

int trace_return(struct pt_regs *ctx)
{
    struct entry_t *entryp;
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 tgid = tgid_pid >> 32;

    entryp = entryinfo.lookup(&tgid_pid);
    if (entryp == 0) {
        return 0;
    }

    u64 delta_ns = bpf_ktime_get_ns() - entryp->start_ns;
    entryinfo.delete(&tgid_pid);

    if (delta_ns < DURATION_NS)
        return 0;

    struct event_t data = {};
    fill_event(&data, EVENT_RET, entryp->id, tgid_pid, ctx, entryp->start_ns, delta_ns);
#ifdef GRAB_ARGS
    bpf_probe_read_kernel(&data.args[0], sizeof(data.args), entryp->args);
#endif
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

static int do_profile_event(struct pt_regs *ctx, enum event_type type) {
    struct entry_t *entryp;
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 tgid = tgid_pid >> 32;

    if (TGID_FILTER)
        return 0;

   if (container_should_be_filtered())
        return 0;

    entryp = entryinfo.lookup(&tgid_pid);
    if (entryp == 0) {
        return 0;
    }
    u64 now = bpf_ktime_get_ns();
    u64 delta_ns = now - entryp->start_ns;
    if (delta_ns < DURATION_NS)
        return 0;

    //This is slow function, record it's stack
    struct event_t event = {};
    struct profile_t pe = {.count = 1, .first_ns = delta_ns, .last_ns = delta_ns};
    fill_event(&event, type, entryp->id, tgid_pid, ctx, entryp->start_ns, 0);

    /* For schedule events we do know the moment when this task was blocked */
    if (type == EVENT_SCHEDULE) {
        u64 *blocked_ns = blocked.lookup(&tgid_pid);
        if (blocked_ns && *blocked_ns > entryp->start_ns) {
            pe.first_ns = *blocked_ns - entryp->start_ns;
            pe.total_ns =  now - *blocked_ns; 
        }
    }
    struct profile_t *old = profileinfo.lookup(&event);
    if (old) {
        pe.count = old->count +1;
        pe.first_ns = old->first_ns;
        pe.total_ns += old->total_ns;
    }
    profileinfo.update(&event, &pe);
    return 0;
}

int offcpu(struct pt_regs *ctx) {
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 tgid = tgid_pid >> 32;
    
    if (TGID_FILTER)
        return 0;

   if (container_should_be_filtered())
        return 0;

    u64 ts = bpf_ktime_get_ns();
    blocked.update(&tgid_pid, &ts);
    return 0;
}

int oncpu(struct pt_regs *ctx) {
    return do_profile_event(ctx, EVENT_SCHEDULE);
}

int do_perf_event(struct bpf_perf_event_data *ctx)
{
    return do_profile_event(&ctx->regs, EVENT_SAMPLE);
}

int do_kprobe_profile_event(struct pt_regs *ctx) {
    return do_profile_event(ctx, EVENT_SAMPLE);
}
"""

bpf_text = bpf_text.replace('DURATION_NS', str(duration_ns))
bpf_text = filter_by_containers(args) + bpf_text

if args.arguments:
    bpf_text = "#define GRAB_ARGS\n" + bpf_text
if args.user_stack:
    bpf_text = "#define USER_STACKS\n" + bpf_text
if args.kernel_stack:
    bpf_text = "#define KERNEL_STACKS\n" + bpf_text
if args.tgid:
    bpf_text = bpf_text.replace('TGID_FILTER', 'tgid != %d' % args.tgid)
else:
    bpf_text = bpf_text.replace('TGID_FILTER', '0')

for i in range(len(args.functions)):
    bpf_text += """
int trace_%d(struct pt_regs *ctx) {
    return trace_entry(ctx, %d);
}
""" % (i, i)

if args.verbose or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

b = BPF(text=bpf_text)

# Attach  probes
for i, function in enumerate(args.functions):
    library=""

    if ":" in function:
        library, func = function.split(":")
        if library == "syscall":
            library = ""
            function = b.get_syscall_fnname(func)
    if library:
        b.attach_uprobe(name=library, sym=func, fn_name="trace_%d" % i)
        b.attach_uretprobe(name=library, sym=func, fn_name="trace_return")
    else:
        b.attach_kprobe(event=function, fn_name="trace_%d" % i)
        b.attach_kretprobe(event=function, fn_name="trace_return")

profile_enabled = False
if args.profile_stack:
    profile_enabled = True
    b.attach_perf_event(ev_type=PerfType.SOFTWARE,
                        ev_config=PerfSWConfig.CPU_CLOCK, fn_name="do_perf_event",
                        sample_freq=args.profile_frequency, cpu=args.cpu)
if args.profile_blocked:
    profile_enabled = True
    b.attach_kprobe(event="schedule", fn_name="offcpu")
    b.attach_kprobe(event="finish_task_switch", fn_name="oncpu")

if args:
    profile_enabled = True
    for fn in args.profile_functions:
        print("attach: {}".format(fn))
        b.attach_kprobe(event=fn, fn_name="do_kprobe_profile_event")

time_designator = "us" if args.min_us else "ms"
time_value = args.min_us or args.min_ms or 1
time_multiplier = 1000 if args.min_us else 1000000
time_col = args.time or args.timestamp

# Do not print header when folded
if not args.folded:
    print("Tracing function calls slower than %g %s... Ctrl+C to quit." %
          (time_value, time_designator))
    print((("%-10s " % "TIME" if time_col else "") + "%-14s %-6s %7s %16s %s") %
        ("COMM", "PID", "LAT(%s)" % time_designator, "RVAL",
        "FUNC" + (" ARGS" if args.arguments else "")))

earliest_ts = 0

def time_str(event):
    if args.time:
        return "%-10s " % time.strftime("%H:%M:%S")
    if args.timestamp:
        global earliest_ts
        if earliest_ts == 0:
            earliest_ts = event.start_ns
        return "%-10.6f " % ((event.start_ns - earliest_ts) / 1000000000.0)
    return ""

def args_str(event):
    if not args.arguments:
        return ""
    return str.join(" ", ["0x%x" % arg for arg in event.args[:args.arguments]])

def print_stack(event):
    user_stack = []
    stack_traces = b.get_table("stacks")

    if args.user_stack and event.user_stack_id > 0:
        user_stack = stack_traces.walk(event.user_stack_id)

    kernel_stack = []
    if args.kernel_stack and event.kernel_stack_id > 0:
        kernel_tmp = stack_traces.walk(event.kernel_stack_id)

        # fix kernel stack
        for addr in kernel_tmp:
            kernel_stack.append(addr)

    do_delimiter = user_stack and kernel_stack

    if args.folded:
        # print folded stack output
        user_stack = list(user_stack)
        kernel_stack = list(kernel_stack)
        line = [event.comm.decode('utf-8', 'replace')] + \
            [b.sym(addr, event.tgid_pid) for addr in reversed(user_stack)] + \
            (do_delimiter and ["-"] or []) + \
            [b.ksym(addr) for addr in reversed(kernel_stack)]
        print("%s %d" % (";".join(line), 1))
    else:
        # print default multi-line stack output.
        for addr in kernel_stack:
            print("    %s" % b.ksym(addr))
        for addr in user_stack:
            print("    %s" % b.sym(addr, event.tgid_pid))

def print_one_event(event, pe, endl):
    first_ns = float(pe.first_ns) / time_multiplier
    last_ns = float(pe.last_ns) / time_multiplier
    total_ns = float(pe.total_ns) / time_multiplier
    type_str = "U"

    if event.type == EventType.EVENT_RET:
        type_str = 'R'
    if int(event.type) == EventType.EVENT_SCHEDULE:
        type_str = 'B'
    elif event.type == EventType.EVENT_SAMPLE:
        type_str = 'S'

    print("%s %8d %7.2f %7.2f %7.2f" %(type_str, pe.count, first_ns, last_ns - first_ns, total_ns), end=endl)
    print_stack(event)


def print_profile_events(event, endl):
    # output stacks
    missing_stacks = 0
    has_collision = False


    profileinfo = b.get_table("profileinfo")
    to_handle = []
    for k, v in sorted(profileinfo.items(), key=lambda profileinfo: profileinfo[1].first_ns):
        if k.id != event.id or k.start_ns  != event.start_ns:
            continue
        to_handle.append(k)
        print_one_event(k, v, endl)
    for k in to_handle:
        del(profileinfo[k])


def print_event(cpu, data, size):
    event = b["events"].event(data)
    ts = float(event.duration_ns) / time_multiplier
    end='\n'
    if args.folded:
        end=' '

    print((time_str(event) + "%-14.14s %-6s %7.2f %16x %s %s") %
          (event.comm.decode('utf-8', 'replace'), event.tgid_pid >> 32,
           ts, event.retval, args.functions[event.id], args_str(event)))
    if (args.user_stack or args.kernel_stack) and not profile_enabled:
        print_stack(event)
    if profile_enabled:
        print_profile_events(event, end)

b["events"].open_perf_buffer(print_event, page_cnt=64)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
