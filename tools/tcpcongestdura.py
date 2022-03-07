#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# tcpcongestdura  Measure tcp congestion control status duration.
#           For Linux, uses BCC, eBPF.
#
# USAGE: tcpcongestdura [-h] [-T] [-L] [-R] [-N] [-d] [interval] [outputs]
#
#
#
# Copyright (c) ping gan.
#
# 27-Jan-2022   jacky_gam_2001@163.com   Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
from struct import pack
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
import argparse

examples = """examples:
    ./tcpcongestdura                 #show tcp congestion status duration
    ./tcpcongestdura 1 10            #show 1 second summaries, 10 times
    ./tcpcongestdura -L 3000-3006 1  #1s summaries, local port 3000-3006
    ./tcpcongestdura -R 5000-5005 1  #1s summaries, remote port 5000-5005
    ./tcpcongestdura -NT 1           #1s summaries, nanoseconds, and timestamps
    ./tcpcongestdura -d              #show the duration as histograms
"""

parser = argparse.ArgumentParser(
    description="Summarize tcp socket congestion control status duration",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-L", "--localport",
            help="trace local ports only")
parser.add_argument("-R", "--remoteport",
            help="trace the dest ports only")
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-d", "--dist", action="store_true",
    help="show distributions as histograms")
parser.add_argument("-N", "--nanoseconds", action="store_true",
    help="output in nanoseconds")
parser.add_argument("interval", nargs="?", default=99999999,
    help="output interval, in seconds")
parser.add_argument("outputs", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
countdown = int(args.outputs)
debug = 0

start_rport = end_rport = -1
if args.remoteport:
    rports = args.remoteport.split("-")
    if (len(rports) != 2) and (len(rports) != 1):
        print("unrecognized remote port range")
        exit(1)
    if len(rports) == 2:
        start_rport = int(rports[0])
        end_rport = int(rports[1])
    else:
        start_rport = int(rports[0])
        end_rport = int(rports[0])
if start_rport > end_rport:
    tmp = start_rport
    start_rport = end_rport
    end_rport = tmp

start_lport = end_lport = -1
if args.localport:
    lports = args.localport.split("-")
    if (len(lports) != 2) and (len(lports) != 1):
        print("unrecognized local port range")
        exit(1)
    if len(lports) == 2:
        start_lport = int(lports[0])
        end_lport = int(lports[1])
    else:
        start_lport = int(lports[0])
        end_lport = int(lports[0])
if start_lport > end_lport:
    tmp = start_lport
    start_lport = end_lport
    end_lport = tmp

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>

typedef struct ipv4_flow_key {
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
}ipv4_flow_key_t;

typedef struct ipv6_flow_key {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 lport;
    u16 dport;
}ipv6_flow_key_t;

typedef struct process_key {
    char comm[TASK_COMM_LEN];
    u32  pid;
    u32  tid;
    u32  status;
}process_key_t;

typedef struct ipv4_flow_val {
    ipv4_flow_key_t ipv4_key;
    u16  cong_state;
}ipv4_flow_val_t;

typedef struct ipv6_flow_val {
    ipv6_flow_key_t ipv6_key;
    u16  cong_state;
}ipv6_flow_val_t;


BPF_HASH(start_ipv4, process_key_t, ipv4_flow_val_t);
BPF_HASH(start_ipv6, process_key_t, ipv6_flow_val_t);

typedef struct data_val {
    DEF_TEXT
    u64  last_ts;
    u16  last_cong_stat;
}data_val_t;

BPF_HASH(ipv4_stat, ipv4_flow_key_t, data_val_t);
BPF_HASH(ipv6_stat, ipv6_flow_key_t, data_val_t);

HIST_TABLE

static int entry_func(struct pt_regs *ctx, struct sock *sk, u32 status)
{
    u32 tid = bpf_get_current_pid_tgid();
    u32 pid = (bpf_get_current_pid_tgid() >> 32);
    process_key_t key = {};
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    key.pid = pid;
    key.tid = tid;
    key.status = status;
    u16 dport = 0, lport = 0;
    u64 family = sk->__sk_common.skc_family;
    struct inet_connection_sock *icsk = inet_csk(sk);
    struct cong {
        u8  cong_stat:5,
            ca_inited:1,
            ca_setsockopt:1,
            ca_dstlocked:1;
    }cong_status;

    bpf_probe_read_kernel(&cong_status, sizeof(cong_status),
        (void *)((long)&icsk->icsk_retransmits) - 1);
    if (family == AF_INET) {
        ipv4_flow_val_t ipv4_val = {0};
        ipv4_val.ipv4_key.saddr = sk->__sk_common.skc_rcv_saddr;
        ipv4_val.ipv4_key.daddr = sk->__sk_common.skc_daddr;
        ipv4_val.ipv4_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        dport = ntohs(dport);
        lport = ipv4_val.ipv4_key.lport;
        FILTER_LPORT
        FILTER_DPORT
        ipv4_val.ipv4_key.dport = dport;
        ipv4_val.cong_state = cong_status.cong_stat + 1;
        start_ipv4.update(&key, &ipv4_val);
    } else if (family == AF_INET6) {
        ipv6_flow_val_t ipv6_val = {0};
        bpf_probe_read_kernel(&ipv6_val.ipv6_key.saddr,
            sizeof(ipv6_val.ipv6_key.saddr),
            &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&ipv6_val.ipv6_key.daddr,
            sizeof(ipv6_val.ipv6_key.daddr),
            &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        ipv6_val.ipv6_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        dport = ntohs(dport);
        lport = ipv6_val.ipv6_key.lport;
        FILTER_LPORT
        FILTER_DPORT
        ipv6_val.ipv6_key.dport = ntohs(dport);
        ipv6_val.cong_state = cong_status.cong_stat + 1;
        start_ipv6.update(&key, &ipv6_val);
    }
    return 0;
}

static int ret_func(struct sock *sk, u32 status)
{
    u64 *tsp, ts, ts1;
    u16 last_cong_state;
    u16 dport = 0, lport = 0;
    u32 tid = bpf_get_current_pid_tgid();
    u32 pid = (bpf_get_current_pid_tgid() >> 32);
    process_key_t key;
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    key.pid = pid;
    key.tid = tid;
    key.status = status;

    struct inet_connection_sock *icsk = inet_csk(sk);
    struct cong {
        u8  cong_stat:5,
            ca_inited:1,
            ca_setsockopt:1,
            ca_dstlocked:1;
    }cong_status;
    bpf_probe_read_kernel(&cong_status, sizeof(cong_status),
        (void *)((long)&icsk->icsk_retransmits) - 1);
    data_val_t *datap, data = {0};
    STATE_KEY
    if (*tsp == AF_INET) {
        ipv4_flow_val_t *val4 = start_ipv4.lookup(&key);
        if (val4 == 0) {
            return 0; //missed
        }
        ipv4_flow_key_t keyv4 = {0};
        bpf_probe_read_kernel(&keyv4, sizeof(ipv4_flow_key_t),
            &(val4->ipv4_key));
        dport = keyv4.dport;
        lport = keyv4.lport;
        FILTER_LPORT
        FILTER_DPORT
        datap = ipv4_stat.lookup(&keyv4);
        if (datap == 0) {
            data.last_ts = bpf_ktime_get_ns();
            data.last_cong_stat = val4->cong_state;
            ipv4_stat.update(&keyv4, &data);
        } else {
            last_cong_state = val4->cong_state;
            if ((cong_status.cong_stat + 1) != last_cong_state) {
                ts1 = bpf_ktime_get_ns();
                ts = ts1 - datap->last_ts;
                datap->last_ts = ts1;
                datap->last_cong_stat = cong_status.cong_stat + 1;
                TIME_UNIT
                STORE
            }
        }
        start_ipv4.delete(&key);
    } else if (*tsp == AF_INET6) {
        ipv6_flow_val_t *val6 = start_ipv6.lookup(&key);
        if (val6 == 0) {
            return 0; //missed
        }
        ipv6_flow_key_t keyv6 = {0};
        bpf_probe_read_kernel(&keyv6, sizeof(ipv6_flow_key_t),
            &(val6->ipv6_key));
        dport = keyv6.dport;
        lport = keyv6.lport;
        FILTER_LPORT
        FILTER_DPORT
        datap = ipv6_stat.lookup(&keyv6);
        if (datap == 0) {
            data.last_ts = bpf_ktime_get_ns();
            data.last_cong_stat = val6->cong_state;
            ipv6_stat.update(&keyv6, &data);
        } else {
            last_cong_state = val6->cong_state;
            if ((cong_status.cong_stat + 1) != last_cong_state) {
                ts1 = bpf_ktime_get_ns();
                ts = ts1 - datap->last_ts;
                datap->last_ts = ts1;
                datap->last_cong_stat = (cong_status.cong_stat + 1);
                TIME_UNIT
                STORE
            }
        }
        start_ipv6.delete(&key);
    }
    return 0;
}

int trace_entry_tcp_enter_disorder(struct pt_regs *ctx, struct sock *sk)
{
    u32 status = 1;
    return entry_func(ctx, sk, status);
}

int trace_ret_tcp_enter_disorder(struct pt_regs *ctx, struct sock *sk)
{
    u32 status = 1;
    return ret_func(sk, status);
}

int trace_entry_tcp_enter_cwr(struct pt_regs *ctx, struct sock *sk)
{
    u32 status = 2;
    return entry_func(ctx, sk, status);
}

int trace_ret_tcp_enter_cwr(struct pt_regs *ctx, struct sock *sk)
{
    u32 status = 2;
    return ret_func(sk, status);
}

int trace_entry_tcp_enter_recovery(struct pt_regs *ctx, struct sock *sk)
{
    u32 status = 3;
    return entry_func(ctx, sk, status);
}

int trace_ret_tcp_enter_recovery(struct pt_regs *ctx, struct sock *sk)
{
    u32 status = 3;
    return ret_func(sk, status);
}

int trace_entry_tcp_enter_loss(struct pt_regs *ctx, struct sock *sk)
{
    u32 status = 4;
    return entry_func(ctx, sk, status);
}

int trace_ret_tcp_enter_loss(struct pt_regs *ctx, struct sock *sk)
{
    u32 status = 4;
    return ret_func(sk, status);
}

int trace_entry_tcp_enter_open(struct pt_regs *ctx, struct sock *sk)
{
    u32 status = 5;
    return entry_func(ctx, sk, status);
}

int trace_ret_tcp_enter_open(struct pt_regs *ctx, struct sock *sk)
{
    u32 status = 5;
    return ret_func(sk, status);
}

"""

# code replace
if args.localport:
    bpf_text = bpf_text.replace('FILTER_LPORT',
        'if (lport < %d || lport > %d) { return 0; }'
        % (start_lport, end_lport))
else:
    bpf_text = bpf_text.replace('FILTER_LPORT', '')

if args.remoteport:
    bpf_text = bpf_text.replace('FILTER_DPORT',
        'if (dport < %d || dport > %d) { return 0; }'
        % (start_rport, end_rport))
else:
    bpf_text = bpf_text.replace('FILTER_DPORT', '')

table_def_text = """
    u64  open_dura;
    u64  loss_dura;
    u64  disorder_dura;
    u64  recover_dura;
    u64  cwr_dura;
    u64  total_changes;
"""

store_text = """
                datap->total_changes += 1;
                if (last_cong_state == (TCP_CA_Open + 1)) {
                    datap->open_dura += ts;
                } else if (last_cong_state == (TCP_CA_Disorder + 1)) {
                    datap->disorder_dura += ts;
                } else if (last_cong_state == (TCP_CA_CWR + 1)) {
                    datap->cwr_dura += ts;
                } else if (last_cong_state == (TCP_CA_Recovery + 1)) {
                    datap->recover_dura += ts;
                } else if (last_cong_state == (TCP_CA_Loss + 1)) {
                    datap->loss_dura += ts;
                }
"""

store_dist_text = """
                if (last_cong_state == (TCP_CA_Open + 1)) {
                    key_s.state = TCP_CA_Open;
                } else if (last_cong_state == (TCP_CA_Disorder + 1)) {
                    key_s.state = TCP_CA_Disorder;
                } else if (last_cong_state == (TCP_CA_CWR + 1)) {
                    key_s.state = TCP_CA_CWR;
                } else if (last_cong_state == (TCP_CA_Recovery + 1)) {
                    key_s.state = TCP_CA_Recovery;
                } else if (last_cong_state == (TCP_CA_Loss + 1)) {
                    key_s.state = TCP_CA_Loss;
                }
                key_s.slot = bpf_log2l(ts);
                dist.atomic_increment(key_s);
"""

hist_table_text = """
typedef struct congest_state_key {
    u32  state;
    u64  slot;
}congest_state_key_t;

BPF_HISTOGRAM(dist, congest_state_key_t);
"""

if args.dist:
    bpf_text = bpf_text.replace('DEF_TEXT', '')
    bpf_text = bpf_text.replace('STORE', store_dist_text)
    bpf_text = bpf_text.replace('STATE_KEY',
        'congest_state_key_t key_s = {0};')
    bpf_text = bpf_text.replace('HIST_TABLE', hist_table_text)
else:
    bpf_text = bpf_text.replace('DEF_TEXT', table_def_text)
    bpf_text = bpf_text.replace('STORE', store_text)
    bpf_text = bpf_text.replace('STATE_KEY', '')
    bpf_text = bpf_text.replace('HIST_TABLE', '')

if args.nanoseconds:
    bpf_text = bpf_text.replace('TIME_UNIT', '')
else:
    bpf_text = bpf_text.replace('TIME_UNIT', 'ts /= 1000;')

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# load BPF program
b = BPF(text=bpf_text)

b.attach_kprobe(event="tcp_try_keep_open",
    fn_name="trace_entry_tcp_enter_disorder")
b.attach_kretprobe(event="tcp_try_keep_open",
    fn_name="trace_ret_tcp_enter_disorder")
b.attach_kprobe(event="tcp_enter_cwr", fn_name="trace_entry_tcp_enter_cwr")
b.attach_kretprobe(event="tcp_enter_cwr",
    fn_name="trace_ret_tcp_enter_cwr")
b.attach_kprobe(event="tcp_process_tlp_ack",
    fn_name="trace_entry_tcp_enter_cwr")
b.attach_kretprobe(event="tcp_process_tlp_ack",
    fn_name="trace_ret_tcp_enter_cwr")
b.attach_kprobe(event="tcp_enter_recovery",
    fn_name="trace_entry_tcp_enter_recovery")
b.attach_kretprobe(event="tcp_enter_recovery",
    fn_name="trace_ret_tcp_enter_recovery")
b.attach_kprobe(event="tcp_enter_loss", fn_name="trace_entry_tcp_enter_loss")
b.attach_kretprobe(event="tcp_enter_loss",
    fn_name="trace_ret_tcp_enter_loss")
b.attach_kprobe(event="tcp_simple_retransmit",
    fn_name="trace_entry_tcp_enter_loss")
b.attach_kretprobe(event="tcp_simple_retransmit",
    fn_name="trace_ret_tcp_enter_loss")
b.attach_kprobe(event="tcp_try_undo_recovery",
    fn_name="trace_entry_tcp_enter_open")
b.attach_kretprobe(event="tcp_try_undo_recovery",
    fn_name="trace_ret_tcp_enter_open")
b.attach_kprobe(event="tcp_try_undo_loss",
    fn_name="trace_entry_tcp_enter_open")
b.attach_kretprobe(event="tcp_try_undo_loss",
    fn_name="trace_ret_tcp_enter_open")
b.attach_kprobe(event="tcp_fastretrans_alert",
    fn_name="trace_entry_tcp_enter_open")
b.attach_kretprobe(event="tcp_fastretrans_alert",
    fn_name="trace_ret_tcp_enter_open")
b.attach_kprobe(event="tcp_disconnect", fn_name="trace_entry_tcp_enter_open")
b.attach_kretprobe(event="tcp_disconnect",
    fn_name="trace_ret_tcp_enter_open")

print("Tracing tcp socket congestion control status duration... Hit Ctrl-C to end.")


def cong_state_to_name(state):
    # this need to match with kernel state
    state_name = ["open", "disorder", "cwr", "recovery", "loss"]
    return state_name[state]

# output
exiting = 0 if args.interval else 1
ipv6_stat = b.get_table("ipv6_stat")
ipv4_stat = b.get_table("ipv4_stat")
if args.dist:
    dist = b.get_table("dist")
label = "us"
if args.nanoseconds:
    label = "ns"
while (1):
    try:
        sleep(int(args.interval))
    except KeyboardInterrupt:
        exiting = 1

    print()
    if args.timestamp:
        print("%-8s\n" % strftime("%H:%M:%S"), end="")
    if args.dist:
        if label == "ns":
            label = "nsecs"
        else:
            label = "msecs"
        dist.print_log2_hist(label, "tcp_congest_state",
            section_print_fn=cong_state_to_name)
        dist.clear()
    else:
        if ipv4_stat:
            print("%-21s% -21s %-7s %-7s %-7s %-6s %-6s %-5s" % ("LAddrPort",
                "RAddrPort", "Open_" + label, "Dsod_" + label,
                "Rcov_" + label, "Cwr_" + label, "Los_" + label, "Chgs"))
        laddr = ""
        raddr = ""
        for k, v in sorted(ipv4_stat.items(), key=lambda ipv4_stat: ipv4_stat[0].lport):
            laddr = inet_ntop(AF_INET, pack("I", k.saddr))
            raddr = inet_ntop(AF_INET, pack("I", k.daddr))
            open_dura = v.open_dura
            disorder_dura = v.disorder_dura
            recover_dura = v.recover_dura
            cwr_dura = v.cwr_dura
            loss_dura = v.loss_dura
            if v.total_changes != 0:
                print("%-21s %-21s %-7d %-7d %-7d %-6d %-6d %-5d" % (laddr +
                    "/" + str(k.lport), raddr + "/" + str(k.dport), open_dura,
                    disorder_dura, recover_dura, cwr_dura, loss_dura,
                    v.total_changes))
        if ipv6_stat:
            print("%-32s %-32s %-7s %-7s %-7s %-6s %-6s %-5s" % ("LAddrPort6",
                "RAddrPort6", "Open_" + label, "Dsod_" + label, "Rcov_" + label,
                "Cwr_" + label, "Los_" + label, "Chgs"))
        for k, v in sorted(ipv6_stat.items(), key=lambda ipv6_stat: ipv6_stat[0].lport):
            laddr = inet_ntop(AF_INET6, bytes(k.saddr))
            raddr = inet_ntop(AF_INET6, bytes(k.daddr))
            open_dura = v.open_dura
            disorder_dura = v.disorder_dura
            recover_dura = v.recover_dura
            cwr_dura = v.cwr_dura
            loss_dura = v.loss_dura
            if v.total_changes != 0:
                print("%-32s %-32s %-7d %-7d %-7d %-6d %-6d %-5d" % (laddr +
                    "/" + str(k.lport), raddr + "/" + str(k.dport), open_dura,
                    disorder_dura, recover_dura, cwr_dura, loss_dura,
                    v.total_changes))
    ipv4_stat.clear()
    ipv6_stat.clear()
    countdown -= 1
    if exiting or countdown == 0:
        exit()
