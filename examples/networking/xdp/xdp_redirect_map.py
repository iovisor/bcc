#!/usr/bin/env python
#
# xdp_redirect_map.py Redirect the incoming packet to another interface
#                     with the helper: bpf_redirect_map()
#
# Copyright (c) 2018 Gary Lin
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
import pyroute2
import time
import sys
import ctypes as ct

flags = 0
def usage():
    print("Usage: {0} <in ifdev> <out ifdev>".format(sys.argv[0]))
    print("e.g.: {0} eth0 eth1\n".format(sys.argv[0]))
    exit(1)

if len(sys.argv) != 3:
    usage()

in_if = sys.argv[1]
out_if = sys.argv[2]

ip = pyroute2.IPRoute()
out_idx = ip.link_lookup(ifname=out_if)[0]

# load BPF program
b = BPF(text = """
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>

BPF_DEVMAP(tx_port, 1);
BPF_PERCPU_ARRAY(rxcnt, long, 1);

static inline void swap_src_dst_mac(void *data)
{
    unsigned short *p = data;
    unsigned short dst[3];

    dst[0] = p[0];
    dst[1] = p[1];
    dst[2] = p[2];
    p[0] = p[3];
    p[1] = p[4];
    p[2] = p[5];
    p[3] = dst[0];
    p[4] = dst[1];
    p[5] = dst[2];
}

int xdp_redirect_map(struct xdp_md *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    struct ethhdr *eth = data;
    uint32_t key = 0;
    long *value;
    uint64_t nh_off;

    nh_off = sizeof(*eth);
    if (data + nh_off  > data_end)
        return XDP_DROP;

    value = rxcnt.lookup(&key);
    if (value)
        *value += 1;

    swap_src_dst_mac(data);

    return tx_port.redirect_map(0, 0);
}

int xdp_dummy(struct xdp_md *ctx) {
    return XDP_PASS;
}
""", cflags=["-w"])

tx_port = b.get_table("tx_port")
tx_port[0] = ct.c_int(out_idx)

in_fn = b.load_func("xdp_redirect_map", BPF.XDP)
out_fn = b.load_func("xdp_dummy", BPF.XDP)

b.attach_xdp(in_if, in_fn, flags)
b.attach_xdp(out_if, out_fn, flags)

rxcnt = b.get_table("rxcnt")
prev = 0
print("Printing redirected packets, hit CTRL+C to stop")
while 1:
    try:
        val = rxcnt.sum(0).value
        if val:
            delta = val - prev
            prev = val
            print("{} pkt/s".format(delta))
        time.sleep(1)
    except KeyboardInterrupt:
        print("Removing filter from device")
        break;

b.remove_xdp(in_if, flags)
b.remove_xdp(out_if, flags)
