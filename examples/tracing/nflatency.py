#!/usr/bin/python3
#
# nflatency     Trace netfilter hook latency.
#
# This attaches a kprobe and kretprobe to nf_hook_slow.
# 2020-04-03 Casey Callendrello / <cdc@redhat.com>

import argparse
import sys
import time

from bcc import BPF

BPF_SRC = """
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <net/ip.h>
#include <uapi/linux/bpf.h>

static struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb)
{
    // unstable API. verify logic in tcp_hdr() -> skb_transport_header().
    return (struct tcphdr *)(skb->head + skb->transport_header);
}

static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb)
{
    // unstable API. verify logic in ip_hdr() -> skb_network_header().
    return (struct iphdr *)(skb->head + skb->network_header);
}

static inline struct ipv6hdr *skb_to_ip6hdr(const struct sk_buff *skb)
{
    // unstable API. verify logic in ip_hdr() -> skb_network_header().
    return (struct ipv6hdr *)(skb->head + skb->network_header);
}

// for correlating between kprobe and kretprobe
struct start_data {
    u8 hook;
    u8 pf; // netfilter protocol
    u8 tcp_state;
    u64 ts;
};
BPF_PERCPU_ARRAY(sts, struct start_data, 1);

// the histogram keys
typedef struct nf_lat_key {
    u8 proto; // see netfilter.h
    u8 hook;
    u8 tcp_state;
} nf_lat_key_t;

typedef struct hist_key {
    nf_lat_key_t key;
    u64 slot;
} hist_key_t;
BPF_HISTOGRAM(dist, hist_key_t);


int kprobe__nf_hook_slow(struct pt_regs *ctx, struct sk_buff *skb, struct nf_hook_state *state) {
    struct start_data data = {};
    data.ts = bpf_ktime_get_ns();
    data.hook = state->hook;
    data.pf = state->pf;

    COND

    u8 ip_proto;
    if (skb->protocol == htons(ETH_P_IP)) {
        struct iphdr *ip = skb_to_iphdr(skb);
        ip_proto = ip->protocol;

    } else if (skb->protocol == htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip = skb_to_ip6hdr(skb);
        ip_proto = ip->nexthdr;
    }

    data.tcp_state = 0;
    if (ip_proto == 0x06) { //tcp
        struct tcphdr *tcp = skb_to_tcphdr(skb);
        u8 tcpflags = ((u_int8_t *)tcp)[13];

        // FIN or RST
        if (((tcpflags & 1) + (tcpflags & 4)) > 0) {
            data.tcp_state = 3;
        }
        // SYN / SACK
        else if ((tcpflags & 0x02) > 0) {
            data.tcp_state = 1;
            if ((tcpflags & 16) > 0) { // ACK
                data.tcp_state = 2;
            }
        }
    }

    u32 idx = 0;
    sts.update(&idx, &data);
    return 0;
}

int kretprobe__nf_hook_slow(struct pt_regs *ctx) {
    u32 idx = 0;
    struct start_data *s;
    s = sts.lookup(&idx);
    if (!s || s->ts == 0) {
        return 0;
    }

    s->ts = bpf_ktime_get_ns() - s->ts;

    hist_key_t key = {};
    key.key.hook = s->hook;
    key.key.proto = s->pf;
    key.key.tcp_state = s->tcp_state;
    key.slot = bpf_log2l(s->ts / FACTOR );
    dist.increment(key);

    s->ts = 0;
    sts.update(&idx, s);

    return 0;
}
"""

# constants from netfilter.h
NF_HOOKS = {
    0: "PRE_ROUTING",
    1: "LOCAL_IN",
    2: "FORWARD",
    3: "LOCAL_OUT",
    4: "POST_ROUTING",
}

NF_PROTOS = {
    0: "UNSPEC",
    1: "INET",
    2: "IPV4",
    3: "ARP",
    5: "NETDEV",
    7: "BRIDGE",
    10: "IPV6",
    12: "DECNET",
}

TCP_FLAGS = {
    0: "other",
    1: "SYN",
    2: "SACK",
    3: "FIN",
}

EXAMPLES = """examples:
    nflatency                   # print netfilter latency histograms, 1 second refresh
    nflatency -p IPV4 -p IPV6   # print only for ipv4 and ipv6
    nflatency -k PRE_ROUTING    # only record the PRE_ROUTING hook
    nflatency -i 5 -d 10        # run for 10 seconds, printing every 5
"""


parser = argparse.ArgumentParser(
    description="Track latency added by netfilter hooks. Where possible, interesting TCP flags are included",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=EXAMPLES)
parser.add_argument("-p", "--proto",
                    action='append',
                    help="record this protocol only (multiple parameters allowed)",
                    choices=NF_PROTOS.values())
parser.add_argument("-k", "--hook",
                    action='append',
                    help="record this netfilter hook only (multiple parameters allowed)",
                    choices=NF_HOOKS.values())
parser.add_argument("-i", "--interval", type=int,
                    help="summary interval, in seconds. Default is 10, unless --duration is supplied")
parser.add_argument("-d", "--duration", type=int,
                    help="total duration of trace, in seconds")
parser.add_argument("--nano", action="store_true",
                    help="bucket by nanoseconds instead of milliseconds")

def main():
    args = parser.parse_args()

    src = build_src(args)
    b = BPF(text=src)
    dist = b.get_table("dist")

    seconds = 0
    interval = 0
    if not args.interval:
        interval = 1
        if args.duration:
            interval = args.duration
    else:
        interval = args.interval

    sys.stderr.write("Tracing netfilter hooks... Hit Ctrl-C to end.\n")
    while 1:
        try:
            dist.print_log2_hist(
                section_header="Bucket",
                bucket_fn=lambda k: (k.proto, k.hook, k.tcp_state),
                section_print_fn=bucket_desc)
            if args.duration and seconds >= args.duration:
                sys.exit(0)
            seconds += interval
            time.sleep(interval)
        except KeyboardInterrupt:
            sys.exit(1)


def build_src(args):
    cond_src = ""
    if args.proto:
        predicate = " || ".join(map(lambda x: "data.pf == NFPROTO_%s" % x, args.proto))
        cond_src = "if (!(%s)) { return 0; }\n" % predicate
    if args.hook:
        predicate = " || ".join(map(lambda x: "data.hook == NF_INET_%s" % x, args.hook))
        cond_src = "%s    if (!(%s)) { return 0;}\n" % (cond_src, predicate)

    factor = "1000"
    if args.nano:
        factor = "1"

    return BPF_SRC.replace('COND', cond_src).replace('FACTOR', factor)


def bucket_desc(bucket):
    return "%s %s (tcp %s)" % (
        NF_PROTOS[bucket[0]],
        NF_HOOKS[bucket[1]],
        TCP_FLAGS[bucket[2]])


if __name__ == "__main__":
    main()
