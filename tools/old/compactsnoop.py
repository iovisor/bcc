#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# compactsnoop  Trace compact zone and print details including issuing PID.
#       For Linux, uses BCC, eBPF.
#
# This uses in-kernel eBPF maps to cache process details (PID and comm) by
# compact zone begin, as well as a starting timestamp for calculating
# latency.
#
# Copyright (c) 2019 Wenbo Zhang
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 11-NOV-2019   Wenbo Zhang   Created this.

from __future__ import print_function
from bcc import BPF
import argparse
import platform
from datetime import datetime, timedelta

# arguments
examples = """examples:
    ./compactsnoop          # trace all compact stall
    ./compactsnoop -T       # include timestamps
    ./compactsnoop -d 10    # trace for 10 seconds only
    ./compactsnoop -K       # output kernel stack trace
    ./compactsnoop -e       # show extended fields
"""

parser = argparse.ArgumentParser(
    description="Trace compact zone",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples,
)
parser.add_argument("-T", "--timestamp", action="store_true",
                    help="include timestamp on output")
parser.add_argument("-p", "--pid", help="trace this PID only")
parser.add_argument("-d", "--duration",
                    help="total duration of trace in seconds")
parser.add_argument("-K", "--kernel-stack", action="store_true",
                    help="output kernel stack trace")
parser.add_argument("-e", "--extended_fields", action="store_true",
                    help="show system memory state")
parser.add_argument("--ebpf", action="store_true", help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0
if args.duration:
    args.duration = timedelta(seconds=int(args.duration))

NO_EXTENDED = """
#ifdef EXTNEDED_FIELDS
#undef EXTNEDED_FIELDS
#endif
"""

EXTENDED = """
#define EXTNEDED_FIELDS    1
"""

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/mmzone.h>
struct node;
#include <linux/compaction.h>

struct compact_control {
    struct list_head freepages;     /* List of free pages to migrate to */
    struct list_head migratepages;  /* List of pages being migrated */
    unsigned long nr_freepages;     /* Number of isolated free pages */
    unsigned long nr_migratepages;  /* Number of pages to migrate */
    unsigned long free_pfn;         /* isolate_freepages search base */
    unsigned long migrate_pfn;      /* isolate_migratepages search base */
    bool sync;                      /* Synchronous migration */
};

struct val_t {
    int nid;
    int idx;
    int order;
    int sync;
#ifdef EXTNEDED_FIELDS
    int fragindex;
    int low;
    int min;
    int high;
    int free;
#endif
    u64 ts;    // compaction begin time
};

struct data_t {
    u32 pid;
    u32 tid;
    int nid;
    int idx;
    int order;
    u64 delta;
    u64 ts;    // compaction end time
    int sync;
#ifdef EXTNEDED_FIELDS
    int fragindex;
    int low;
    int min;
    int high;
    int free;
#endif
    int status;
    int stack_id;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(start, u64, struct val_t);
BPF_PERF_OUTPUT(events);
BPF_STACK_TRACE(stack_traces, 2048);

#ifdef CONFIG_NUMA
static inline int zone_to_nid_(struct zone *zone)
{
    int node;
    bpf_probe_read(&node, sizeof(node), &zone->node);
    return node;
}
#else
static inline int zone_to_nid_(struct zone *zone)
{
    return 0;
}
#endif

// #define zone_idx(zone) ((zone) - (zone)->zone_pgdat->node_zones)
static inline int zone_idx_(struct zone *zone)
{
    struct pglist_data *zone_pgdat = NULL;
    bpf_probe_read(&zone_pgdat, sizeof(zone_pgdat), &zone->zone_pgdat);
    return zone - zone_pgdat->node_zones;
}

#ifdef EXTNEDED_FIELDS
static inline void get_all_wmark_pages(struct zone *zone, struct val_t *valp)
{
    u64 watermark[NR_WMARK] = {};
    u64 watermark_boost = 0;

    bpf_probe_read(&watermark, sizeof(watermark), &zone->watermark);
    valp->min = watermark[WMARK_MIN];
    valp->low = watermark[WMARK_LOW];
    valp->high = watermark[WMARK_HIGH];
    bpf_probe_read(&valp->free, sizeof(valp->free),
                   &zone->vm_stat[NR_FREE_PAGES]);
}
#endif

int trace_compact_zone_entry(struct pt_regs *ctx, struct zone *zone,
                             struct compact_control *cc)
{
#ifdef EXTNEDED_FIELDS
    struct val_t val = { .fragindex=-1000 };
#else
    struct val_t val = { };
#endif
    u64 id = bpf_get_current_pid_tgid();
    PID_FILTER
    val.sync = cc->sync;
    start.update(&id, &val);
    return 0;
}

int trace_compaction_suitable_entry(struct pt_regs *ctx, struct zone *zone,
                                    int order)
{
    u64 id = bpf_get_current_pid_tgid();
    struct val_t *valp = start.lookup(&id);
    if (valp == NULL) {
        // missed entry
        return 0;
    }
    valp->nid = zone_to_nid_(zone);
    valp->idx = zone_idx_(zone);
    valp->order = order;

#ifdef EXTNEDED_FIELDS
     get_all_wmark_pages(zone, valp);
#endif

    return 0;
}

int trace_fragmentation_index_return(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    u64 id = bpf_get_current_pid_tgid();
    struct val_t *valp = start.lookup(&id);
    if (valp == NULL) {
        // missed entry
        return 0;
    }
#ifdef EXTNEDED_FIELDS
    valp->fragindex = ret;
#endif
    return 0;
}

int trace_compaction_suitable_return(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    u64 id = bpf_get_current_pid_tgid();
    struct val_t *valp = start.lookup(&id);
    if (valp == NULL) {
        // missed entry
        return 0;
    }
    if (ret != COMPACT_CONTINUE)
        start.delete(&id);
    else
        valp->ts = bpf_ktime_get_ns();
    return 0;
}

int trace_compact_zone_return(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    struct data_t data = {};
    u64 ts = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    struct val_t *valp = start.lookup(&id);
    if (valp == NULL) {
        // missed entry or unsuitable
        return 0;
    }

    data.delta = ts - valp->ts;
    data.ts = ts / 1000;
    data.pid = id >> 32;
    data.tid = id;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.nid = valp->nid;
    data.idx = valp->idx;
    data.order = valp->order;
    data.sync = valp->sync;

#ifdef EXTNEDED_FIELDS
    data.fragindex = valp->fragindex;
    data.min = valp->min;
    data.low = valp->low;
    data.high = valp->high;
    data.free = valp->free;
#endif

    data.status = ret;
    data.stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);

    events.perf_submit(ctx, &data, sizeof(data));

    start.delete(&id);
    return 0;
}
"""

if platform.machine() != 'x86_64':
    print("""
          Currently only support x86_64 servers, if you want to use it on
          other platforms, please refer include/linux/mmzone.h to modify
          zone_idex_to_str to get the right zone type
    """)
    exit()

if args.extended_fields:
    bpf_text = EXTENDED + bpf_text
else:
    bpf_text = NO_EXTENDED + bpf_text

if args.pid:
    bpf_text = bpf_text.replace(
        "PID_FILTER", "if (id >> 32 != %s) { return 0; }" % args.pid)
else:
    bpf_text = bpf_text.replace("PID_FILTER", "")
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# load BPF program
b = BPF(text=bpf_text)
b.attach_kprobe(event="compact_zone", fn_name="trace_compact_zone_entry")
b.attach_kretprobe(event="compact_zone", fn_name="trace_compact_zone_return")
b.attach_kprobe(
    event="compaction_suitable", fn_name="trace_compaction_suitable_entry"
)
b.attach_kretprobe(
    event="fragmentation_index", fn_name="trace_fragmentation_index_return"
)
b.attach_kretprobe(
    event="compaction_suitable", fn_name="trace_compaction_suitable_return"
)

stack_traces = b.get_table("stack_traces")
initial_ts = 0

def zone_idx_to_str(idx):
    # from include/linux/mmzone.h
    # NOTICE: consider only x86_64 servers
    zonetype = {
        0: "ZONE_DMA",
        1: "ZONE_DMA32",
        2: "ZONE_NORMAL",
    }

    if idx in zonetype:
        return zonetype[idx]
    else:
        return str(idx)

def compact_result_to_str(status):
    # from include/linux/compaction.h
    compact_status = {
        # COMPACT_SKIPPED: compaction didn't start as it was not possible
        # or direct reclaim was more suitable
        0: "skipped",
        # COMPACT_CONTINUE: compaction should continue to another pageblock
        1: "continue",
        # COMPACT_PARTIAL: direct compaction partially compacted a zone and
        # there are suitable pages
        2: "partial",
        # COMPACT_COMPLETE: The full zone was compacted
        3: "complete",
    }

    if status in compact_status:
        return compact_status[status]
    else:
        return str(status)

# header
if args.timestamp:
    print("%-14s" % ("TIME(s)"), end=" ")
print(
    "%-14s %-6s %-4s %-12s %-5s %-7s"
    % ("COMM", "PID", "NODE", "ZONE", "ORDER", "MODE"),
    end=" ",
)
if args.extended_fields:
    print("%-8s %-8s %-8s %-8s %-8s" %
            ("FRAGIDX", "MIN", "LOW", "HIGH", "FREE"), end=" ")
print("%9s %16s" % ("LAT(ms)", "STATUS"))

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)

    global initial_ts

    if not initial_ts:
        initial_ts = event.ts

    if args.timestamp:
        delta = event.ts - initial_ts
        print("%-14.9f" % (float(delta) / 1000000), end=" ")

    print("%-14.14s %-6s %-4s %-12s %-5s %-7s" % (
            event.comm.decode("utf-8", "replace"),
            event.pid,
            event.nid,
            zone_idx_to_str(event.idx),
            event.order,
            "SYNC" if event.sync else "ASYNC"), end=" ")
    if args.extended_fields:
        print("%-8.3f %-8s %-8s %-8s %-8s" % (
                float(event.fragindex) / 1000,
                event.min,
                event.low,
                event.high,
                event.free), end=" ")
    print("%9.3f %16s" % (
        float(event.delta) / 1000000, compact_result_to_str(event.status)))
    if args.kernel_stack:
        for addr in stack_traces.walk(event.stack_id):
            sym = b.ksym(addr, show_offset=True)
            print("\t%s" % sym)
            print("")

# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
start_time = datetime.now()
while not args.duration or datetime.now() - start_time < args.duration:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
