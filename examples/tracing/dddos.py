#!/usr/bin/python
#
# dddos.py	DDOS dectection system.
#
# Written as a basic tracing example of using ePBF
# to detect a potential DDOS attack against a system.
#
# Copyright (c) 2019 Jugurtha BELKALEM.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 14-Jan-2019 Jugurtha BELKALEM Created this.

from bcc import BPF
import ctypes as ct
import datetime
prog = """
#include <linux/skbuff.h>
#include <uapi/linux/ip.h>

#define MAX_NB_PACKETS 1000
#define LEGAL_DIFF_TIMESTAMP_PACKETS 1000000

BPF_HASH(rcv_packets);

struct detectionPackets {
    u64 nb_ddos_packets;
};

BPF_PERF_OUTPUT(events);

int detect_ddos(struct pt_regs *ctx, void *skb){
    struct detectionPackets detectionPacket = {};

    // Used to count number of received packets
    u64 rcv_packets_nb_index = 0, rcv_packets_nb_inter=1, *rcv_packets_nb_ptr;

    // Used to measure elapsed time between 2 successive received packets
    u64 rcv_packets_ts_index = 1, rcv_packets_ts_inter=0, *rcv_packets_ts_ptr;

    /* The algorithm analyses packets received by ip_rcv function
    * and measures the difference in reception time between each packet.
    * DDOS flooders send millions of packets such that difference of
    * timestamp between 2 successive packets is so small
    * (which is not like regular applications behaviour).
    * This script looks for this difference in time and if it sees
    * more than MAX_NB_PACKETS successive packets with a difference
    * of timestamp between each one of them less than
    * LEGAL_DIFF_TIMESTAMP_PACKETS ns,
    * ------------------ It Triggers an ALERT -----------------
    * Those settings must be adapted depending on regular network traffic
    * -------------------------------------------------------------------
    * Important: this is a rudimentary intrusion detection system, one can
    * test a real case attack using hping3. However; if regular network
    * traffic increases above predefined detection settings, a false
    * positive alert will be triggered (an example would be the
    * case of large file downloads).
    */
    rcv_packets_nb_ptr = rcv_packets.lookup(&rcv_packets_nb_index);
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
            detectionPacket.nb_ddos_packets = rcv_packets_nb_inter;
            events.perf_submit(ctx, &detectionPacket, sizeof(detectionPacket));
        }
    }
    rcv_packets_ts_inter = bpf_ktime_get_ns();
    rcv_packets.update(&rcv_packets_nb_index, &rcv_packets_nb_inter);
    rcv_packets.update(&rcv_packets_ts_index, &rcv_packets_ts_inter);
    return 0;
}
"""

# Loads eBPF program
b = BPF(text=prog)

# Attach kprobe to kernel function and sets detect_ddos as kprobe handler
b.attach_kprobe(event="ip_rcv", fn_name="detect_ddos")

class DetectionTimestamp(ct.Structure):
    _fields_ = [("nb_ddos_packets", ct.c_ulonglong)]

# Show message when ePBF starts
print("DDOS detector started ... Hit Ctrl-C to end!")

print("%-26s %-10s" % ("TIME(s)", "MESSAGE"))

def trigger_alert_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(DetectionTimestamp)).contents
    print("%-26s %s %ld" % (datetime.datetime.now(),
    "DDOS Attack => nb of packets up to now : ", event.nb_ddos_packets))

# loop with callback to trigger_alert_event
b["events"].open_perf_buffer(trigger_alert_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
