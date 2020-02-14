#!/usr/bin/python
#
# tcpbind       Trace IPv4 and IPv6 binds()s.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# based on tcpconnect utility from Brendan Gregg's suite.
#
# USAGE: tcpbind [-h] [-t] [-E] [-p PID] [-P PORT [PORT ...]] [-w]
#             [--count] [--cgroupmap mappath]
#
# tcpbind reports socket options set before the bind call
# that would impact this system call behavior:
# SOL_IP     IP_FREEBIND              F....
# SOL_IP     IP_TRANSPARENT           .T...
# SOL_IP     IP_BIND_ADDRESS_NO_PORT  ..N..
# SOL_SOCKET SO_REUSEADDR             ...R.
# SOL_SOCKET SO_REUSEPORT             ....r
#
# SO_BINDTODEVICE interface is reported as "BOUND_IF" index
#
# This uses dynamic tracing of kernel functions, and will need to be updated
# to match kernel changes.
#

from __future__ import print_function, absolute_import, unicode_literals
from bcc import BPF, DEBUG_SOURCE
from bcc.utils import printb
import argparse
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from time import sleep

# arguments
examples = """examples:
    ./tcpbind           # trace all TCP bind()s
    ./tcpbind -t        # include timestamps
    ./tcplife -w        # wider columns (fit IPv6)
    ./tcpbind -p 181    # only trace PID 181
    ./tcpbind -P 80     # only trace port 80
    ./tcpbind -P 80,81  # only trace port 80 and 81
    ./tcpbind -U        # include UID
    ./tcpbind -u 1000   # only trace UID 1000
    ./tcpbind -E        # report bind errors
    ./tcpbind --count   # count bind per src ip
    ./tcpbind --cgroupmap mappath  # only trace cgroups in this BPF map

it is reporting socket options set before the bins call
impacting system call behavior:
 SOL_IP     IP_FREEBIND              F....
 SOL_IP     IP_TRANSPARENT           .T...
 SOL_IP     IP_BIND_ADDRESS_NO_PORT  ..N..
 SOL_SOCKET SO_REUSEADDR             ...R.
 SOL_SOCKET SO_REUSEPORT             ....r

 SO_BINDTODEVICE interface is reported as "IF" index
"""
parser = argparse.ArgumentParser(
    description="Trace TCP binds",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-t", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-w", "--wide", action="store_true",
    help="wide column output (fits IPv6 addresses)")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("-P", "--port",
    help="comma-separated list of ports to trace.")
parser.add_argument("-E", "--errors", action="store_true",
    help="include errors in the output.")
parser.add_argument("-U", "--print-uid", action="store_true",
    help="include UID on output")
parser.add_argument("-u", "--uid",
    help="trace this UID only")
parser.add_argument("--count", action="store_true",
    help="count binds per src ip and port")
parser.add_argument("--cgroupmap",
    help="trace cgroups in this BPF map only")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
parser.add_argument("--debug-source", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wtautological-compare"
#include <net/sock.h>
#pragma clang diagnostic pop
#include <net/inet_sock.h>
#include <net/net_namespace.h>
#include <bcc/proto.h>

BPF_HASH(currsock, u32, struct socket *);

// separate data structs for ipv4 and ipv6
struct ipv4_bind_data_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u64 ip;
    u32 saddr;
    u32 bound_dev_if;
    int return_code;
    u16 sport;
    u8 socket_options;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_bind_events);

struct ipv6_bind_data_t {
    // int128 would be aligned on 16 bytes boundary, better to go first
    unsigned __int128 saddr;
    u64 ts_us;
    u32 pid;
    u32 uid;
    u64 ip;
    u32 bound_dev_if;
    int return_code;
    u16 sport;
    u8 socket_options;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv6_bind_events);

// separate flow keys per address family
struct ipv4_flow_key_t {
    u32 saddr;
    u16 sport;
};
BPF_HASH(ipv4_count, struct ipv4_flow_key_t);

struct ipv6_flow_key_t {
    unsigned __int128 saddr;
    u16 sport;
};
BPF_HASH(ipv6_count, struct ipv6_flow_key_t);

CGROUP_MAP

// bind options for event reporting
union bind_options {
    u8 data;
    struct {
        u8 freebind:1;
        u8 transparent:1;
        u8 bind_address_no_port:1;
        u8 reuseaddress:1;
        u8 reuseport:1;
    } fields;
};

// TODO: add reporting for the original bind arguments
int tcpbind_entry(struct pt_regs *ctx, struct socket *socket)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    FILTER_PID

    u32 uid = bpf_get_current_uid_gid();

    FILTER_UID

    FILTER_CGROUP

    // stash the sock ptr for lookup on return
    currsock.update(&tid, &socket);

    return 0;
};


static int tcpbind_return(struct pt_regs *ctx, short ipver)
{
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;

    struct socket **skpp;
    skpp = currsock.lookup(&tid);
    if (skpp == 0) {
        return 0;   // missed entry
    }

    int ignore_errors = 1;
    FILTER_ERRORS
    if (ret != 0 && ignore_errors) {
        // failed to bind
        currsock.delete(&tid);
        return 0;
    }

    // pull in details
    struct socket *skp_ = *skpp;
    struct sock *skp = skp_->sk;

    struct inet_sock *sockp = (struct inet_sock *)skp;
    // struct inet_sock *sockp = inet_sk(skp);
    u16 sport;
    bpf_probe_read(&sport, sizeof(sport), &sockp->inet_sport);
    sport = ntohs(sport);

    FILTER_PORT

    // u8 opts = 0;
    union bind_options opts = {0};
    u8 bitfield;
    // fetching freebind, transparent, and bind_address_no_port bitfields
    // via the next struct member, rcv_tos
    bitfield = (u8) *(&sockp->rcv_tos - 2) & 0xFF;
    // IP_FREEBIND (sockp->freebind)
    opts.fields.freebind = bitfield >> 2 & 0x01;
    // IP_TRANSPARENT (sockp->transparent)
    opts.fields.transparent = bitfield >> 5 & 0x01;
    // IP_BIND_ADDRESS_NO_PORT (sockp->bind_address_no_port)
    opts.fields.bind_address_no_port = *(&sockp->rcv_tos - 1) & 0x01;

    // SO_REUSEADDR and SO_REUSEPORT are bitfields that
    // cannot be accessed directly, fetched via the next struct member,
    // __sk_common.skc_bound_dev_if
    bitfield = *((u8*)&skp->__sk_common.skc_bound_dev_if - 1);
    // SO_REUSEADDR (skp->reuse)
    // it is 4 bit, but we are interested in the lowest one
    opts.fields.reuseaddress = bitfield & 0x0F;
    // SO_REUSEPORT (skp->reuseport)
    opts.fields.reuseport = bitfield >> 4 & 0x01;

    if (ipver == 4) {
        IPV4_CODE
    } else /* 6 */ {
        IPV6_CODE
    }

    currsock.delete(&tid);

    return 0;
}

int tcpbind_v4_return(struct pt_regs *ctx)
{
    return tcpbind_return(ctx, 4);
}

int tcpbind_v6_return(struct pt_regs *ctx)
{
    return tcpbind_return(ctx, 6);
}
"""

struct_init = {
    'ipv4': {
        'count': """
               struct ipv4_flow_key_t flow_key = {};
               flow_key.saddr = skp->__sk_common.skc_rcv_saddr;
               flow_key.sport = sport;
               ipv4_count.increment(flow_key);""",
        'trace': """
               struct ipv4_bind_data_t data4 = {.pid = pid, .ip = ipver};
               data4.uid = bpf_get_current_uid_gid();
               data4.ts_us = bpf_ktime_get_ns() / 1000;
               bpf_probe_read(
                 &data4.saddr, sizeof(data4.saddr), &sockp->inet_saddr);
               data4.return_code = ret;
               data4.sport = sport;
               data4.bound_dev_if = skp->__sk_common.skc_bound_dev_if;
               data4.socket_options = opts.data;
               bpf_get_current_comm(&data4.task, sizeof(data4.task));
               ipv4_bind_events.perf_submit(ctx, &data4, sizeof(data4));"""
    },
    'ipv6': {
        'count': """
               struct ipv6_flow_key_t flow_key = {};
               bpf_probe_read(&flow_key.saddr, sizeof(flow_key.saddr),
                   skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
               flow_key.sport = sport;
               ipv6_count.increment(flow_key);""",
        'trace': """
               struct ipv6_bind_data_t data6 = {.pid = pid, .ip = ipver};
               data6.uid = bpf_get_current_uid_gid();
               data6.ts_us = bpf_ktime_get_ns() / 1000;
               bpf_probe_read(&data6.saddr, sizeof(data6.saddr),
                   skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
               data6.return_code = ret;
               data6.sport = sport;
               data6.bound_dev_if = skp->__sk_common.skc_bound_dev_if;
               data6.socket_options = opts.data;
               bpf_get_current_comm(&data6.task, sizeof(data6.task));
               ipv6_bind_events.perf_submit(ctx, &data6, sizeof(data6));"""
    },
    'filter_cgroup': """
    u64 cgroupid = bpf_get_current_cgroup_id();
    if (cgroupset.lookup(&cgroupid) == NULL) {
      return 0;
    }""",
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
    sports = [int(sport) for sport in args.port.split(',')]
    sports_if = ' && '.join(['sport != %d' % sport for sport in sports])
    bpf_text = bpf_text.replace('FILTER_PORT',
        'if (%s) { currsock.delete(&pid); return 0; }' % sports_if)
if args.uid:
    bpf_text = bpf_text.replace('FILTER_UID',
        'if (uid != %s) { return 0; }' % args.uid)
if args.errors:
    bpf_text = bpf_text.replace('FILTER_ERRORS', 'ignore_errors = 0;')
if args.cgroupmap:
    bpf_text = bpf_text.replace('FILTER_CGROUP', struct_init['filter_cgroup'])
    bpf_text = bpf_text.replace(
        'CGROUP_MAP',
        (
            'BPF_TABLE_PINNED("hash", u64, u64, cgroupset, 1024, "%s");' %
            args.cgroupmap
        )
    )

bpf_text = bpf_text.replace('FILTER_PID', '')
bpf_text = bpf_text.replace('FILTER_PORT', '')
bpf_text = bpf_text.replace('FILTER_UID', '')
bpf_text = bpf_text.replace('FILTER_ERRORS', '')
bpf_text = bpf_text.replace('FILTER_CGROUP', '')
bpf_text = bpf_text.replace('CGROUP_MAP', '')

# selecting output format - 80 characters or wide, fitting IPv6 addresses
header_fmt = "%5s %-12.12s %-2s %-15s %-5s %5s %2s"
output_fmt = b"%5d %-12.12s %-2d %-15.15s %5d %-5s %2d"
if args.wide:
    header_fmt = "%10s %-12.12s %-2s %-39s %-5s %5s %2s"
    output_fmt = b"%10d %-12.12s %-2d %-39s %5d %-5s %2d"

if args.ebpf:
    print(bpf_text)
    exit()

if args.debug_source:
    b = BPF(text=bpf_text, debug=DEBUG_SOURCE)
    exit()


# bind options:
# SOL_IP     IP_FREEBIND              F....
# SOL_IP     IP_TRANSPARENT           .T...
# SOL_IP     IP_BIND_ADDRESS_NO_PORT  ..N..
# SOL_SOCKET SO_REUSEADDR             ...R.
# SOL_SOCKET SO_REUSEPORT             ....r
def opts2str(bitfield):
    str_options = ""
    bit = 1
    for opt in "FTNRr":
        str_options += opt if bitfield & bit else "."
        bit *= 2
    return str_options.encode()


# process events
def print_ipv4_bind_event(cpu, data, size):
    event = b["ipv4_bind_events"].event(data)
    global start_ts
    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us
        printb(b"%-9.6f " % ((float(event.ts_us) - start_ts) / 1000000), nl="")
    if args.print_uid:
        printb(b"%6d " % event.uid, nl="")
    if args.errors:
        printb(b"%3d " % event.return_code, nl="")
    printb(output_fmt % (event.pid, event.task, event.ip,
        inet_ntop(AF_INET, pack("I", event.saddr)).encode(),
        event.sport, opts2str(event.socket_options), event.bound_dev_if))


def print_ipv6_bind_event(cpu, data, size):
    event = b["ipv6_bind_events"].event(data)
    global start_ts
    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us
        printb(b"%-9.6f " % ((float(event.ts_us) - start_ts) / 1000000), nl="")
    if args.print_uid:
        printb(b"%6d " % event.uid, nl="")
    if args.errors:
        printb(b"%3d " % event.return_code, nl="")
    printb(output_fmt % (event.pid, event.task, event.ip,
        inet_ntop(AF_INET6, event.saddr).encode(),
        event.sport, opts2str(event.socket_options), event.bound_dev_if))


def depict_cnt(counts_tab, l3prot='ipv4'):
    for k, v in sorted(
        counts_tab.items(), key=lambda counts: counts[1].value, reverse=True
    ):
        depict_key = ""
        if l3prot == 'ipv4':
            depict_key = "%-32s %20s" % (
                (inet_ntop(AF_INET, pack('I', k.saddr))), k.sport
            )
        else:
            depict_key = "%-32s %20s" % (
                (inet_ntop(AF_INET6, k.saddr)), k.sport
            )
        print("%s     %-10d" % (depict_key, v.value))


# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="inet_bind", fn_name="tcpbind_entry")
b.attach_kprobe(event="inet6_bind", fn_name="tcpbind_entry")
b.attach_kretprobe(event="inet_bind", fn_name="tcpbind_v4_return")
b.attach_kretprobe(event="inet6_bind", fn_name="tcpbind_v6_return")

print("Tracing binds ... Hit Ctrl-C to end")
if args.count:
    try:
        while 1:
            sleep(99999999)
    except KeyboardInterrupt:
        pass

    # header
    print("\n%-32s %20s     %-10s" % (
        "LADDR", "LPORT", "BINDS"))
    depict_cnt(b["ipv4_count"])
    depict_cnt(b["ipv6_count"], l3prot='ipv6')
# read events
else:
    # header
    if args.timestamp:
        print("%-9s " % ("TIME(s)"), end="")
    if args.print_uid:
        print("%6s " % ("UID"), end="")
    if args.errors:
        print("%2s " % ("RC"), end="")
    print(header_fmt % ("PID", "COMM", "IP", "ADDR", "PORT", "OPTS", "IF"))

    start_ts = 0

    # read events
    b["ipv4_bind_events"].open_perf_buffer(print_ipv4_bind_event)
    b["ipv6_bind_events"].open_perf_buffer(print_ipv6_bind_event)
    while 1:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()
