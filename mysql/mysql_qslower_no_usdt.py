#!/usr/bin/env python

from bcc import BPF, USDT
from functools import partial
from time import sleep, strftime
import argparse
import re
import ctypes as ct
import os
import traceback
import sys
import subprocess

examples = """examples:
    mysql_query_slower <mysqld_path> [-m <threshold ms>]
"""
parser = argparse.ArgumentParser(
    description="",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("path", type=str,
    help="path to mysqld")
parser.add_argument("-m", "--threshold", type=int, default=1,
    help="trace queries slower than this threshold (ms)")    
args = parser.parse_args()

threshold_ns = args.threshold * 1000000
threshold_if_begin = ("if (delta >= " + str(threshold_ns) + ") {") if threshold_ns > 0 else ""
threshold_if_end = ("}") if threshold_ns > 0 else ""

bpf_text = """
#include <uapi/linux/ptrace.h>

struct temp_t {
    u64 timestamp;
    char query[256];
};

struct data_t {
    u64 pid;
    u64 timestamp;
    u64 duration;
    char query[256];
};

BPF_HASH(temp, u64, struct temp_t);
BPF_PERF_OUTPUT(events);

int dispatch_start(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 command  = (u64) PT_REGS_PARM1(ctx);

    if (command == 3) {
        struct temp_t tmp = {};
        tmp.timestamp = bpf_ktime_get_ns();
        bpf_probe_read(&tmp.query, sizeof(tmp.query), (void*) PT_REGS_PARM3(ctx));

        temp.update(&pid, &tmp);
    }
    return 0;
};

int dispatch_end(struct pt_regs *ctx) {
    struct temp_t *tempp;
    u64 pid = bpf_get_current_pid_tgid();
    tempp = temp.lookup(&pid);
    if (!tempp)
        return 0;
    u64 delta = bpf_ktime_get_ns() - tempp->timestamp;
    """ + threshold_if_begin + """
        struct data_t data = {};
        data.pid = pid;
        data.timestamp = tempp->timestamp;
        data.duration = delta;
        bpf_probe_read(&data.query, sizeof(data.query), tempp->query);
        events.perf_submit(ctx, &data, sizeof(data));
    """ + threshold_if_end + """
    temp.delete(&pid);

    return 0;
};

"""

symbols = subprocess.check_output(["nm", "-aD", args.path])
dispatch_fname = [name for name in symbols.split('\n') if name.find("dispatch_command") >= 0]

if len(dispatch_fname) == 0:
    print("Cant find function 'dispatch_command' in %s" % (args.path))
    exit(1)

m = re.search("\\w+dispatch_command\\w+", dispatch_fname[0])
if m:
    func_name = m.group(0)
else:
    print("Cant extract real 'dispatch_command' function name from %s" % (dispatch_fname[0]))
    exit(1)

b = BPF(text=bpf_text)
b.attach_uprobe(name=args.path, sym=func_name, fn_name="dispatch_start")
b.attach_uretprobe(name=args.path, sym=func_name, fn_name="dispatch_end")

class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_ulonglong),
        ("timestamp", ct.c_ulonglong),
        ("delta", ct.c_ulonglong),
        ("query", ct.c_char * 256)
    ]

start = BPF.monotonic_time()

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    print("%-14.6f %-6d %8.3f %s" % (
        float(event.timestamp - start) / 1000000000,
        event.pid, float(event.delta) / 1000000, event.query))

print("%-14s %-6s %8s %s" % ("TIME(s)", "PID", "MS", "QUERY"))

b["events"].open_perf_buffer(print_event, page_cnt=64)
while True:
    b.kprobe_poll()        