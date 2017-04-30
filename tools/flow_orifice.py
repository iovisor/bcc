#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# Copyright (C) 2017  Matthias Tafelmeier
#
# flow_orifice.py is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# flow_orifice.py is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

from bcc import BPF
import argparse
import time
from socket import inet_ntop, AF_INET, AF_INET6
import ctypes as ct
from struct import pack

#todo
examples = """examples:
    ./flow_orifice         # 
"""

parser = argparse.ArgumentParser(
    description="Trace flows traversing down the network stack",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-i", "--interval", default=3, type=int,
    help="interval of run in seconds")
args = parser.parse_args()

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>

struct ipv4_data_t {
    int cpu;
    u16 qu_idx;
    u64 saddr;
    u64 daddr;
    u64 lport;
    u64 dport;
    char prot[32];
};

struct ipv6_data_t {
    int cpu;
    u16 qu_idx;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 lport;
    u64 dport;
    char prot[32];
};

BPF_PERF_OUTPUT(ipv4_flows);
BPF_PERF_OUTPUT(ipv6_flows);

int trace_hard_start_xmit(struct pt_regs *ctx, struct sk_buff *skb)
{
    u64 zero = 0;
    struct sk_buff *_skb = NULL;
    bpf_probe_read(&_skb, sizeof(_skb), &skb);
    struct sock *skp = NULL;
    bpf_probe_read(&skp, sizeof(skp), &_skb->sk);
    u16 _qu_idx = skb->queue_mapping;
    int curr_cpu = bpf_get_smp_processor_id();

    // get flow details
    u16 family = 0, lport = 0, dport = 0;
    struct proto *prot_ref = NULL;
    bpf_probe_read(&family, sizeof(family), &skp->__sk_common.skc_family);
    bpf_probe_read(&lport, sizeof(lport), &skp->__sk_common.skc_num);
    bpf_probe_read(&dport, sizeof(dport), &skp->__sk_common.skc_dport);
    bpf_probe_read(&dport, sizeof(dport), &skp->__sk_common.skc_dport);
    bpf_probe_read(&prot_ref, sizeof(prot_ref), &skp->__sk_common.skc_prot);

    if (family == AF_INET) {
        struct ipv4_data_t data4 = { .cpu = curr_cpu, .qu_idx = _qu_idx };
        data4.lport = lport;
        data4.dport = ntohs(dport);
        bpf_probe_read(&data4.prot, sizeof(data4.prot),
            &prot_ref->name);
        bpf_probe_read(&data4.saddr, sizeof(u32),
            &skp->__sk_common.skc_rcv_saddr);
        bpf_probe_read(&data4.daddr, sizeof(u32),
            &skp->__sk_common.skc_daddr);
        ipv4_flows.perf_submit(ctx, &data4, sizeof(data4));
    } else if (family == AF_INET6) {
        struct ipv6_data_t data6 = { .cpu = curr_cpu, .qu_idx = _qu_idx };
        data6.lport = lport;
        data6.dport = ntohs(dport);
        bpf_probe_read(&data6.prot, sizeof(data6.prot),
            &prot_ref->name);
        bpf_probe_read(&data6.saddr, sizeof(data6.saddr),
            &skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(&data6.daddr, sizeof(data6.daddr),
            &skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        ipv6_flows.perf_submit(ctx, &data6, sizeof(data6));
    }
    // drop other

    return 0;
}
"""

# entry data
class Data_ipv4(ct.Structure):
    _fields_ = [
        ("cpu", ct.c_int),
        ("qu_idx", ct.c_ushort),
        ("saddr", ct.c_ulonglong),
        ("daddr", ct.c_ulonglong),
        ("lport", ct.c_ulonglong),
        ("dport", ct.c_ulonglong),
        ("prot", ct.c_char * 32)
    ]

class Data_ipv6(ct.Structure):
    _fields_ = [
        ("cpu", ct.c_int),
        ("qu_idx", ct.c_ushort),
        ("saddr", (ct.c_ulonglong * 2)),
        ("daddr", (ct.c_ulonglong * 2)),
        ("lport", ct.c_ulonglong),
        ("dport", ct.c_ulonglong),
        ("prot", ct.c_char * 32)
    ]

def set_surrogate_aux(f_event):
    if f_event.qu_idx not in flows_hive.keys():
        flows_hive[f_event.qu_idx] = {}

    if f_event.cpu not in flows_hive[f_event.qu_idx].keys():
        flows_hive[f_event.qu_idx][f_event.cpu] = {}


def gather_ipv4_flow(cpu, data, size):
    f_event = ct.cast(data, ct.POINTER(Data_ipv4)).contents
    set_surrogate_aux(f_event)

    proto = f_event.prot
    s_tuple = "%s:%s" % (inet_ntop(AF_INET, pack('I', f_event.saddr)), f_event.lport)
    d_tuple = "%s:%s" % (inet_ntop(AF_INET, pack('I', f_event.daddr)), f_event.dport)
    flow_str = "%-20s %-20s %-20s " % (proto, s_tuple, d_tuple)
    flows_hive[f_event.qu_idx][f_event.cpu][flow_str] = None

def gather_ipv6_flow(cpu, data, size):
    f_event = ct.cast(data, ct.POINTER(Data_ipv6)).contents
    set_surrogate_aux(f_event)

    proto = f_event.prot
    s_tuple = "%s:%s" % (inet_ntop(AF_INET6, f_event.saddr), f_event.lport)
    d_tuple = "%s:%s" % (inet_ntop(AF_INET6, f_event.daddr), f_event.dport)
    flow_str = "%-20s %-20s %-20s " % (proto, s_tuple, d_tuple)
    flows_hive[f_event.qu_idx][f_event.cpu][flow_str] = None

#data gathering representation
flows_hive = {}

b = BPF(text=bpf_text)
b.attach_kprobe(event="dev_hard_start_xmit", fn_name="trace_hard_start_xmit")

b['ipv4_flows'].open_perf_buffer(gather_ipv4_flow)
b['ipv6_flows'].open_perf_buffer(gather_ipv6_flow)

t_end = time.time() + args.interval
while time.time() < t_end:
    b.kprobe_poll()

#header
print("QDISC%-5sCPU%-5sFLOW" % (" ", " "))
for qu_idx, per_cpu_flows in flows_hive.items():
    print ("".ljust(80, "*"))
    print("%s" % (qu_idx))
    for cpu, flows in per_cpu_flows.items():
        print ("".ljust(80, "-"))
        indent = 13
        print("%s\n".rjust(indent) % (cpu))
        for f in flows.keys():
            indent = 23
            print ("%-40s".rjust(indent) % f)
