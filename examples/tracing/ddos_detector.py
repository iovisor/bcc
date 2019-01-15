#!/usr/bin/env python
#
# ddos_detector.py	DDOS dectection system.
#
# Written as a basic networking example of using ePBF
# to detect a potential DDOS attack against a system.
#
# Copyright (c) 2019 Jugurtha BELKALEM.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 14-Jan-2019 Jugurtha BELKALEM Created this.

from bcc import BPF
import ctypes as ct
prog = """
#include <linux/skbuff.h>
#include <uapi/linux/ip.h>

/* If We receive more than 100 succesive packets with a difference of */ 
/* timestamp between each one of them is less than 1000000ns */
/* Trigger ALERT */
#define MAX_NB_PACKETS 100
#define LEGAL_DIFF_TIMESTAMP_PACKETS 1000000

BPF_HASH(rcv_packets);

// define C structure
struct detectionTimestamp {
    u64 ts;
};

// use perf buffer (avoid using /sys/kernel/debug/tracing/trace_pipe)
BPF_PERF_OUTPUT(events);

int detect_ddos(struct pt_regs *ctx, struct sk_buff *skb){
    struct detectionTimestamp detectionTs = {};
    // Counts number of received packets
    u64 rcv_packets_nb = 0, rcv_packets_nb_inter=1, *rcv_packets_nb_ptr;
    // Measures elapsed time between 2 successive received packets
    u64 rcv_packets_ts_index = 1, rcv_packets_ts_inter=0, *rcv_packets_ts_ptr;
    rcv_packets_nb_ptr = rcv_packets.lookup(&rcv_packets_nb);
    rcv_packets_ts_ptr = rcv_packets.lookup(&rcv_packets_ts_index);
    if(rcv_packets_nb_ptr != 0 && rcv_packets_ts_ptr != 0){
        rcv_packets_nb_inter = *rcv_packets_nb_ptr;
        rcv_packets_ts_inter = bpf_ktime_get_ns() - *rcv_packets_ts_ptr;
        if(rcv_packets_ts_inter < LEGAL_DIFF_TIMESTAMP_PACKETS){
            rcv_packets_nb_inter++;
        } else {
            rcv_packets_nb_inter = 0;
        }
        if(rcv_packets_nb_inter > MAX_NB_PACKETS){
            // Get timestamp of DDOS detection
            detectionTs.ts = bpf_ktime_get_ns();
            events.perf_submit(ctx, &detectionTs, sizeof(detectionTs));
        }
            rcv_packets.delete(&rcv_packets_nb);
            rcv_packets.delete(&rcv_packets_ts_index);
        }
    rcv_packets_ts_inter = bpf_ktime_get_ns();
    rcv_packets.update(&rcv_packets_nb, &rcv_packets_nb_inter);
    rcv_packets.update(&rcv_packets_ts_index, &rcv_packets_ts_inter);
    return 0; // always return 0
}
"""

# Loads eBPF program
b = BPF(text=prog)

# Attach kprobe to kernel function and sets detect_ddos as kprobe handler
b.attach_kprobe(event="ip_rcv", fn_name="detect_ddos")

class DetectionTimestamp(ct.Structure):
    _fields_ = [("ts", ct.c_ulonglong)]

# Show message when ePBF stats
print("DDOS detector started ... Hit Ctrl-C to end!")

print("%-18s %-6s" % ("TIME(s)", "MESSAGE"))

def trigger_alert_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(DetectionTimestamp)).contents
    print("%-18s %-6s" % (event.ts, "Attack detected"))

# loop with callback to trigger_alert_event
b["events"].open_perf_buffer(trigger_alert_event)
while 1:
    b.perf_buffer_poll()
