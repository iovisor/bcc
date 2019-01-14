#!/usr/bin/env python
#
# ddos_detector.py	DDOS dectection system.
#		
#
# Written as a basic networking example of using ePBF to detect a potential DDOS attack against a system.
#
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

/* If We receive more than 100 succesive packets with a difference of timestamp between each one of them is less than 1000000ns - Trigger ALERT */
#define MAX_NB_PACKETS 100
#define LEGAL_DIFF_TIMESTAMP_PACKETS 1000000

BPF_HASH(received_packets);

// define C structure
struct detectionTimestamp {
    u64 ts;
};

// use perf buffer (avoid using /sys/kernel/debug/tracing/trace_pipe)
BPF_PERF_OUTPUT(events);

int detect_ddos(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev){

    struct detectionTimestamp detectionTs = {};
    u64 received_packets_nb = 0, received_packets_nb_inter=1, *received_packets_nb_ptr;	

    u64 received_packets_timestamp_index = 1, received_packets_timestamp_inter=0, *received_packets_timestamp_ptr;


    received_packets_nb_ptr = received_packets.lookup(&received_packets_nb);



    received_packets_timestamp_ptr = received_packets.lookup(&received_packets_timestamp_index);


    if(received_packets_nb_ptr != 0 && received_packets_timestamp_ptr != 0){
        received_packets_nb_inter = *received_packets_nb_ptr;


        received_packets_timestamp_inter = bpf_ktime_get_ns() - *received_packets_timestamp_ptr;

        if(received_packets_timestamp_inter < LEGAL_DIFF_TIMESTAMP_PACKETS){
            received_packets_nb_inter++;
        } else {
            received_packets_nb_inter = 0;
        }

        if(received_packets_nb_inter > MAX_NB_PACKETS){
            bpf_trace_printk("DDOS attack - number of packets : %d\\n", received_packets_nb_inter);
            detectionTs.ts = bpf_ktime_get_ns();
            events.perf_submit(ctx, &detectionTs, sizeof(detectionTs));
        }
            received_packets.delete(&received_packets_nb);
            received_packets.delete(&received_packets_timestamp_index);
        }
    received_packets_timestamp_inter = bpf_ktime_get_ns();
    received_packets.update(&received_packets_nb, &received_packets_nb_inter);
    received_packets.update(&received_packets_timestamp_index, &received_packets_timestamp_inter);

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
