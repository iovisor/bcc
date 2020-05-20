#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# tcpconnect    Trace TCP connect()s.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpconnect [-h] [-c] [-t] [-p PID] [-P PORT [PORT ...]]
#
# All connection attempts are traced, even if they ultimately fail.
#
# This uses dynamic tracing of kernel functions, and will need to be updated
# to match kernel changes.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 25-Sep-2015   Brendan Gregg   Created this.
# 14-Feb-2016      "      "     Switch to bpf_perf_output.
# 09-Jan-2019   Takuma Kume     Support filtering by UID
# 30-Jul-2019   Xiaozhou Liu    Count connects.

from __future__ import print_function
from bcc import BPF
from bcc.containers import filter_by_containers
from bcc.utils import printb
import argparse
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack
from time import sleep

# arguments
examples = """examples:
    ./tcpconnect           # trace all TCP connect()s
    ./tcpconnect -t        # include timestamps
    ./tcpconnect -p 181    # only trace PID 181
    ./tcpconnect -P 80     # only trace port 80
    ./tcpconnect -P 80,81  # only trace port 80 and 81
    ./tcpconnect -U        # include UID
    ./tcpconnect -u 1000   # only trace UID 1000
    ./tcpconnect -c        # count connects per src ip and dest ip/port
    ./tcpconnect --cgroupmap mappath  # only trace cgroups in this BPF map
    ./tcpconnect --mntnsmap mappath   # only trace mount namespaces in the map
"""
parser = argparse.ArgumentParser(
    description="Trace TCP connects",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-t", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("-P", "--port",
    help="comma-separated list of destination ports to trace.")
parser.add_argument("-U", "--print-uid", action="store_true",
    help="include UID on output")
parser.add_argument("-u", "--uid",
    help="trace this UID only")
parser.add_argument("-c", "--count", action="store_true",
    help="count connects per src ip and dest ip/port")
parser.add_argument("--cgroupmap",
    help="trace cgroups in this BPF map only")
parser.add_argument("--mntnsmap",
    help="trace mount namespaces in this BPF map only")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_HASH(currsock, u32, struct sock *);

// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u64 ip;
    u16 dport;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 ip;
    u16 dport;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv6_events);

// separate flow keys per address family
struct ipv4_flow_key_t {
    u32 saddr;
    u32 daddr;
    u16 dport;
};
BPF_HASH(ipv4_count, struct ipv4_flow_key_t);

struct ipv6_flow_key_t {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 dport;
};
BPF_HASH(ipv6_count, struct ipv6_flow_key_t);

int trace_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
    if (container_should_be_filtered()) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    FILTER_PID

    u32 uid = bpf_get_current_uid_gid();
    FILTER_UID

    // stash the sock ptr for lookup on return
    currsock.update(&tid, &sk);

    return 0;
};

static int trace_connect_return(struct pt_regs *ctx, short ipver)
{
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;

    struct sock **skpp;
    skpp = currsock.lookup(&tid);
    if (skpp == 0) {
        return 0;   // missed entry
    }

    if (ret != 0) {
        // failed to send SYNC packet, may not have populated
        // socket __sk_common.{skc_rcv_saddr, ...}
        currsock.delete(&tid);
        return 0;
    }

    // pull in details
    struct sock *skp = *skpp;
    u16 dport = skp->__sk_common.skc_dport;

    FILTER_PORT

    if (ipver == 4) {
        IPV4_CODE
    } else /* 6 */ {
        IPV6_CODE
    }

    currsock.delete(&tid);

    return 0;
}

int trace_connect_v4_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 4);
}

int trace_connect_v6_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 6);
}
"""

struct_init = { 'ipv4':
        { 'count' :
               """
               struct ipv4_flow_key_t flow_key = {};
               flow_key.saddr = skp->__sk_common.skc_rcv_saddr;
               flow_key.daddr = skp->__sk_common.skc_daddr;
               flow_key.dport = ntohs(dport);
               ipv4_count.increment(flow_key);""",
          'trace' :
               """
               struct ipv4_data_t data4 = {.pid = pid, .ip = ipver};
               data4.uid = bpf_get_current_uid_gid();
               data4.ts_us = bpf_ktime_get_ns() / 1000;
               data4.saddr = skp->__sk_common.skc_rcv_saddr;
               data4.daddr = skp->__sk_common.skc_daddr;
               data4.dport = ntohs(dport);
               bpf_get_current_comm(&data4.task, sizeof(data4.task));
               ipv4_events.perf_submit(ctx, &data4, sizeof(data4));"""
               },
        'ipv6':
        { 'count' :
               """
               struct ipv6_flow_key_t flow_key = {};
               bpf_probe_read_kernel(&flow_key.saddr, sizeof(flow_key.saddr),
                   skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
               bpf_probe_read_kernel(&flow_key.daddr, sizeof(flow_key.daddr),
                   skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
               flow_key.dport = ntohs(dport);
               ipv6_count.increment(flow_key);""",
          'trace' :
               """
               struct ipv6_data_t data6 = {.pid = pid, .ip = ipver};
               data6.uid = bpf_get_current_uid_gid();
               data6.ts_us = bpf_ktime_get_ns() / 1000;
               bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr),
                   skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
               bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr),
                   skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
               data6.dport = ntohs(dport);
               bpf_get_current_comm(&data6.task, sizeof(data6.task));
               ipv6_events.perf_submit(ctx, &data6, sizeof(data6));"""
               }
        }

# code substitutions
if args.count:
    bpf_text = bpf_text.replace("IPV4_CODE", struct_init['ipv4']['count'])
    bpf_text = bpf_text.replace("IPV6_CODE", struct_init['ipv6']['count'])
else:
    bpf_text = bpf_text.replace("IPV4_CODE", struct_init['ipv4']['trace'])
    bpf_text = bpf_text.replace("IPV6_CODE", struct_init['ipv6']['trace'])

if args.pid:
    bpf_text = bpf_text.replace('FILTER_PID',
        'if (pid != %s) { return 0; }' % args.pid)
if args.port:
    dports = [int(dport) for dport in args.port.split(',')]
    dports_if = ' && '.join(['dport != %d' % ntohs(dport) for dport in dports])
    bpf_text = bpf_text.replace('FILTER_PORT',
        'if (%s) { currsock.delete(&pid); return 0; }' % dports_if)
if args.uid:
    bpf_text = bpf_text.replace('FILTER_UID',
        'if (uid != %s) { return 0; }' % args.uid)
bpf_text = filter_by_containers(args) + bpf_text

bpf_text = bpf_text.replace('FILTER_PID', '')
bpf_text = bpf_text.replace('FILTER_PORT', '')
bpf_text = bpf_text.replace('FILTER_UID', '')

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# process event
def print_ipv4_event(cpu, data, size):
    event = b["ipv4_events"].event(data)
    global start_ts
    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us
        printb(b"%-9.3f" % ((float(event.ts_us) - start_ts) / 1000000), nl="")
    if args.print_uid:
        printb(b"%-6d" % event.uid, nl="")
    printb(b"%-6d %-12.12s %-2d %-16s %-16s %-4d" % (event.pid,
        event.task, event.ip,
        inet_ntop(AF_INET, pack("I", event.saddr)).encode(),
        inet_ntop(AF_INET, pack("I", event.daddr)).encode(), event.dport))

def print_ipv6_event(cpu, data, size):
    event = b["ipv6_events"].event(data)
    global start_ts
    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us
        printb(b"%-9.3f" % ((float(event.ts_us) - start_ts) / 1000000), nl="")
    if args.print_uid:
        printb(b"%-6d" % event.uid, nl="")
    printb(b"%-6d %-12.12s %-2d %-16s %-16s %-4d" % (event.pid,
        event.task, event.ip,
        inet_ntop(AF_INET6, event.saddr).encode(), inet_ntop(AF_INET6, event.daddr).encode(),
        event.dport))

def depict_cnt(counts_tab, l3prot='ipv4'):
    for k, v in sorted(counts_tab.items(), key=lambda counts: counts[1].value, reverse=True):
        depict_key = ""
        if l3prot == 'ipv4':
            depict_key = "%-25s %-25s %-20s" %  ((inet_ntop(AF_INET, pack('I', k.saddr))),
                                              inet_ntop(AF_INET, pack('I', k.daddr)), k.dport)
        else:
            depict_key = "%-25s %-25s %-20s" % ((inet_ntop(AF_INET6, k.saddr)),
                                              inet_ntop(AF_INET6, k.daddr), k.dport)

        print ("%s %-10d" % (depict_key, v.value))

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_connect_entry")
b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")
b.attach_kretprobe(event="tcp_v6_connect", fn_name="trace_connect_v6_return")

print("Tracing connect ... Hit Ctrl-C to end")
if args.count:
    try:
        while 1:
            sleep(99999999)
    except KeyboardInterrupt:
        pass

    # header
    print("\n%-25s %-25s %-20s %-10s" % (
        "LADDR", "RADDR", "RPORT", "CONNECTS"))
    depict_cnt(b["ipv4_count"])
    depict_cnt(b["ipv6_count"], l3prot='ipv6')
# read events
else:
    # header
    if args.timestamp:
        print("%-9s" % ("TIME(s)"), end="")
    if args.print_uid:
        print("%-6s" % ("UID"), end="")
    print("%-6s %-12s %-2s %-16s %-16s %-4s" % ("PID", "COMM", "IP", "SADDR",
        "DADDR", "DPORT"))

    start_ts = 0

    # read events
    b["ipv4_events"].open_perf_buffer(print_ipv4_event)
    b["ipv6_events"].open_perf_buffer(print_ipv6_event)
    while 1:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()
