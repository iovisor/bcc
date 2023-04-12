#!/usr/bin/env python
#
# klockstat traces lock events and display locks statistics.
#
# USAGE: klockstat
#

from __future__ import print_function
from bcc import BPF, USDT
import argparse
import subprocess
import ctypes as ct
from time import sleep, strftime
from datetime import datetime, timedelta
import errno
from sys import stderr

examples = """
    klockstat                           # trace system wide
    klockstat -d 5                      # trace for 5 seconds only
    klockstat -i 5                      # display stats every 5 seconds
    klockstat -p 123                    # trace locks for PID 123
    klockstat -t 321                    # trace locks for TID 321
    klockstat -c pipe_                  # display stats only for lock callers with 'pipe_' substring
    klockstat -S acq_count              # sort lock acquired results on acquired count
    klockstat -S hld_total              # sort lock held results on total held time
    klockstat -S acq_count,hld_total    # combination of above
    klockstat -n 3                      # display 3 locks
    klockstat -s 3                      # display 3 levels of stack
"""

# arg validation
def positive_int(val):
    try:
        ival = int(val)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer")

    if ival < 0:
        raise argparse.ArgumentTypeError("must be positive")
    return ival

def positive_nonzero_int(val):
    ival = positive_int(val)
    if ival == 0:
        raise argparse.ArgumentTypeError("must be nonzero")
    return ival

def stack_id_err(stack_id):
    # -EFAULT in get_stackid normally means the stack-trace is not available,
    # Such as getting kernel stack trace in userspace code
    return (stack_id < 0) and (stack_id != -errno.EFAULT)

parser = argparse.ArgumentParser(
    description="",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)

time_group = parser.add_mutually_exclusive_group()
time_group.add_argument("-d", "--duration", type=int,
    help="total duration of trace in seconds")
time_group.add_argument("-i", "--interval", type=int,
    help="print summary at this interval (seconds)")
parser.add_argument("-n", "--locks", type=int, default=99999999,
    help="print given number of locks")
parser.add_argument("-s", "--stacks", type=int, default=1,
    help="print given number of stack entries")
parser.add_argument("-c", "--caller",
    help="print locks taken by given caller")
parser.add_argument("-S", "--sort",
    help="sort data on <aq_field,hd_field>, fields: acq_[max|total|count] hld_[max|total|count]")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("-t", "--tid",
    help="trace this TID only")
parser.add_argument("--stack-storage-size", default=16384,
    type=positive_nonzero_int,
    help="the number of unique stack traces that can be stored and "
         "displayed (default 16384)")

args = parser.parse_args()

program = """
#include <uapi/linux/ptrace.h>

struct depth_id {
  u64 id;
  u64 depth;
};

BPF_ARRAY(enabled,   u64, 1);
BPF_HASH(track,      u64, u64);
BPF_HASH(time_aq,    u64, u64);
BPF_HASH(lock_depth, u64, u64);
BPF_HASH(time_held,  struct depth_id, u64);
BPF_HASH(stack,      struct depth_id, int);

BPF_HASH(aq_report_count, int, u64);
BPF_HASH(aq_report_max,   int, u64);
BPF_HASH(aq_report_total, int, u64);

BPF_HASH(hl_report_count, int, u64);
BPF_HASH(hl_report_max,   int, u64);
BPF_HASH(hl_report_total, int, u64);

BPF_STACK_TRACE(stack_traces, STACK_STORAGE_SIZE);

static bool is_enabled(void)
{
    int key = 0;
    u64 *ret;

    ret = enabled.lookup(&key);
    return ret && *ret == 1;
}

static bool allow_pid(u64 id)
{
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // Cast and get the lower part

    FILTER

    return 1;
}

static int do_mutex_lock_enter(void *ctx, int skip)
{
    if (!is_enabled())
        return 0;

    u64 id = bpf_get_current_pid_tgid();

    if (!allow_pid(id))
        return 0;

    u64 one = 1, zero = 0;

    track.update(&id, &one);

    u64 *depth = lock_depth.lookup(&id);

    if (!depth) {
        lock_depth.update(&id, &zero);

        depth = lock_depth.lookup(&id);
        /* something is wrong.. */
        if (!depth)
            return 0;
    }

    int stackid = stack_traces.get_stackid(ctx, skip);
    struct depth_id did = {
      .id    = id,
      .depth = *depth,
    };
    stack.update(&did, &stackid);

    u64 ts = bpf_ktime_get_ns();
    time_aq.update(&id, &ts);

    *depth += 1;
    return 0;
}

static void update_aq_report_count(int *stackid)
{
    u64 *count, one = 1;

    count = aq_report_count.lookup(stackid);
    if (!count) {
        aq_report_count.update(stackid, &one);
    } else {
        *count += 1;
    }
}

static void update_hl_report_count(int *stackid)
{
    u64 *count, one = 1;

    count = hl_report_count.lookup(stackid);
    if (!count) {
        hl_report_count.update(stackid, &one);
    } else {
        *count += 1;
    }
}

static void update_aq_report_max(int *stackid, u64 time)
{
    u64 *max;

    max = aq_report_max.lookup(stackid);
    if (!max || *max < time)
        aq_report_max.update(stackid, &time);
}

static void update_hl_report_max(int *stackid, u64 time)
{
    u64 *max;

    max = hl_report_max.lookup(stackid);
    if (!max || *max < time)
        hl_report_max.update(stackid, &time);
}

static void update_aq_report_total(int *stackid, u64 delta)
{
    u64 *count, *time;

    count = aq_report_count.lookup(stackid);
    if (!count)
        return;

    time = aq_report_total.lookup(stackid);
    if (!time) {
        aq_report_total.update(stackid, &delta);
    } else {
        *time = *time + delta;
    }
}

static void update_hl_report_total(int *stackid, u64 delta)
{
    u64 *count, *time;

    count = hl_report_count.lookup(stackid);
    if (!count)
        return;

    time = hl_report_total.lookup(stackid);
    if (!time) {
        hl_report_total.update(stackid, &delta);
    } else {
        *time = *time + delta;
    }
}

static int do_mutex_lock_return(void)
{
    if (!is_enabled())
        return 0;

    u64 id = bpf_get_current_pid_tgid();

    if (!allow_pid(id))
        return 0;

    u64 *one = track.lookup(&id);

    if (!one)
        return 0;

    track.delete(&id);

    u64 *depth = lock_depth.lookup(&id);
    if (!depth)
        return 0;

    struct depth_id did = {
      .id    = id,
      .depth = *depth - 1,
    };

    u64 *aq = time_aq.lookup(&id);
    if (!aq)
        return 0;

    int *stackid = stack.lookup(&did);
    if (!stackid)
        return 0;

    int stackid_ = *stackid;
    u64 cur = bpf_ktime_get_ns();

    if (cur > *aq) {
        int val = cur - *aq;
        update_aq_report_count(&stackid_);
        update_aq_report_max(&stackid_, val);
        update_aq_report_total(&stackid_, val);
    }

    time_held.update(&did, &cur);
    return 0;
}

static int do_mutex_unlock_enter(void)
{
    if (!is_enabled())
        return 0;

    u64 id = bpf_get_current_pid_tgid();

    if (!allow_pid(id))
        return 0;

    u64 *depth = lock_depth.lookup(&id);

    if (!depth || *depth == 0)
        return 0;

    *depth -= 1;

    struct depth_id did = {
      .id    = id,
      .depth = *depth,
    };

    u64 *held = time_held.lookup(&did);
    if (!held)
        return 0;

    int *stackid = stack.lookup(&did);
    if (!stackid)
        return 0;


    int stackid_ = *stackid;
    u64 cur = bpf_ktime_get_ns();

    if (cur > *held) {
        u64 val = cur - *held;
        update_hl_report_count(&stackid_);
        update_hl_report_max(&stackid_, val);
        update_hl_report_total(&stackid_, val);
    }

    stack.delete(&did);
    time_held.delete(&did);
    return 0;
}
"""

program_kprobe = """
int mutex_unlock_enter(struct pt_regs *ctx)
{
    return do_mutex_unlock_enter();
}

int mutex_lock_return(struct pt_regs *ctx)
{
    return do_mutex_lock_return();
}

int mutex_lock_enter(struct pt_regs *ctx)
{
    return do_mutex_lock_enter(ctx, 0);
}
"""

program_kfunc = """
KFUNC_PROBE(mutex_unlock, void *lock)
{
    return do_mutex_unlock_enter();
}

KRETFUNC_PROBE(mutex_lock, void *lock, int ret)
{
    return do_mutex_lock_return();
}

KFUNC_PROBE(mutex_lock, void *lock)
{
    return do_mutex_lock_enter(ctx, 3);
}

"""

program_kfunc_nested = """
KFUNC_PROBE(mutex_unlock, void *lock)
{
    return do_mutex_unlock_enter();
}

KRETFUNC_PROBE(mutex_lock_nested, void *lock, int ret)
{
    return do_mutex_lock_return();
}

KFUNC_PROBE(mutex_lock_nested, void *lock)
{
    return do_mutex_lock_enter(ctx, 3);
}

"""

is_support_kfunc = BPF.support_kfunc()
if is_support_kfunc:
    if BPF.get_kprobe_functions(b"mutex_lock_nested"):
        program += program_kfunc_nested
    else:
        program += program_kfunc
else:
    program += program_kprobe

def sort_list(maxs, totals, counts):
    if (not args.sort):
        return maxs;

    for field in args.sort.split(','):
        if (field == "acq_max" or field == "hld_max"):
            return maxs
        if (field == "acq_total" or field == "hld_total"):
            return totals
        if (field == "acq_count" or field == "hld_count"):
            return counts

    print("Wrong sort argument: %s", args.sort)
    exit(-1)

def display(sort, maxs, totals, counts):
    global missing_stacks
    global has_enomem

    for k, v in sorted(sort.items(), key=lambda sort: sort[1].value, reverse=True)[:args.locks]:
        missing_stacks += int(stack_id_err(k.value))
        has_enomem      = has_enomem or (k.value == -errno.ENOMEM)

        caller = "[Missed Kernel Stack]"
        stack  = []

        if (k.value >= 0):
            stack  = list(stack_traces.walk(k.value))
            caller = b.ksym(stack[1], show_offset=True)

            if (args.caller and caller.find(args.caller.encode())):
                continue

        avg = totals[k].value / counts[k].value

        print("%40s %10lu %6lu %10lu %10lu" % (caller, avg, counts[k].value, maxs[k].value, totals[k].value))

        for addr in stack[2:args.stacks]:
            print("%40s" %  b.ksym(addr, show_offset=True))


if args.tid:  # TID trumps PID
    program = program.replace('FILTER',
        'if (tid != %s) { return 0; }' % args.tid)
elif args.pid:
    program = program.replace('FILTER',
        'if (pid != %s) { return 0; }' % args.pid)
else:
    program = program.replace('FILTER', '')

program = program.replace('STACK_STORAGE_SIZE', str(args.stack_storage_size))

b = BPF(text=program)

if not is_support_kfunc:
    b.attach_kprobe(event="mutex_unlock", fn_name="mutex_unlock_enter")
    # Depending on whether DEBUG_LOCK_ALLOC is set, the proper kprobe may be either mutex_lock or mutex_lock_nested
    if BPF.get_kprobe_functions(b"mutex_lock_nested"):
        b.attach_kretprobe(event="mutex_lock_nested", fn_name="mutex_lock_return")
        b.attach_kprobe(event="mutex_lock_nested", fn_name="mutex_lock_enter")
    else:
        b.attach_kretprobe(event="mutex_lock", fn_name="mutex_lock_return")
        b.attach_kprobe(event="mutex_lock", fn_name="mutex_lock_enter")

enabled = b.get_table("enabled");

stack_traces = b.get_table("stack_traces")
aq_counts = b.get_table("aq_report_count")
aq_maxs   = b.get_table("aq_report_max")
aq_totals = b.get_table("aq_report_total")

hl_counts = b.get_table("hl_report_count")
hl_maxs   = b.get_table("hl_report_max")
hl_totals = b.get_table("hl_report_total")

aq_sort = sort_list(aq_maxs, aq_totals, aq_counts)
hl_sort = sort_list(hl_maxs, hl_totals, hl_counts)

print("Tracing lock events... Hit Ctrl-C to end.")

# duration and interval are mutualy exclusive
exiting = 0 if args.interval else 1
exiting = 1 if args.duration else 0

seconds = 99999999
if args.interval:
    seconds = args.interval
if args.duration:
    seconds = args.duration

missing_stacks = 0
has_enomem     = False

while (1):
    enabled[ct.c_int(0)] = ct.c_int(1)

    try:
        sleep(seconds)
    except KeyboardInterrupt:
        exiting = 1

    enabled[ct.c_int(0)] = ct.c_int(0)

    print("\n%40s %10s %6s %10s %10s" % ("Caller", "Avg Spin", "Count", "Max spin", "Total spin"))
    display(aq_sort, aq_maxs, aq_totals, aq_counts)


    print("\n%40s %10s %6s %10s %10s" % ("Caller", "Avg Hold", "Count", "Max hold", "Total hold"))
    display(hl_sort, hl_maxs, hl_totals, hl_counts)

    if exiting:
        break;

    stack_traces.clear()
    aq_counts.clear()
    aq_maxs.clear()
    aq_totals.clear()
    hl_counts.clear()
    hl_maxs.clear()
    hl_totals.clear()

if missing_stacks > 0:
    enomem_str = " Consider increasing --stack-storage-size."
    print("WARNING: %d stack traces lost and could not be displayed.%s" %
        (missing_stacks, (enomem_str if has_enomem else "")),
        file=stderr)
