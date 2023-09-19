#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
#
# Block alignment observability tool.
#
# Copyright (c) 2023 Samsung Electronics Co., Ltd. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 06-Nov-2023   Daniel Gomez   Created this.
from __future__ import (
    absolute_import, division, unicode_literals, print_function
)
from bcc import BPF
import argparse
import time

examples = """examples:
  blkalgn                             # Observe all blk commands
  blkalgn --disk nvme9n1              # Observe all commands on 9th NVMe node
  blkalgn --ops Read                  # Observe read commands on all NVMe
  blkalgn --ops Write                 # Observe write commands on all NVMe
  blkalgn --ops Write --disk nvme9n1  # Observe write commands on 9th NVMe node
  blkalgn --debug                     # Print eBPF program before observe
  blkalgn --trace                     # Print NVMe captured events
  blkalgn --interval 0.1              # Poll data ring buffer every 100 ms
"""

parser = argparse.ArgumentParser(
    description="Block commands observer tool",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples,
)
parser.add_argument(
    "-d",
    "--disk",
    type=str,
    help="capture commands for this block device node only"
)
parser.add_argument(
    "-o",
    "--ops",
    type=str,
    help="capture this command operation only"
)
parser.add_argument("--debug", action="store_true", help="debug")
parser.add_argument(
    "--trace",
    action="store_true",
    help="trace block captured commands"
)
parser.add_argument(
    "--interval",
    type=float,
    help="polling interval"
)

args = parser.parse_args()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char disk[DISK_NAME_LEN];
    u32 op;
    u32 len;
    u32 lba;
    u32 algn;
};

BPF_HISTOGRAM(block_len, u32, 64);
BPF_HISTOGRAM(algn, u32, 64);
BPF_ARRAY(counts, u64, 1);
BPF_RINGBUF_OUTPUT(events, 8);

/* local strcmp function, max length 16 to protect instruction loops */
#define CMPMAX	16

static int local_strcmp(const char *cs, const char *ct)
{
    int len = 0;
    unsigned char c1, c2;

    while (len++ < CMPMAX) {
        c1 = *cs++;
        c2 = *ct++;
        if (c1 != c2)
            return c1 < c2 ? -1 : 1;
        if (!c1)
            break;
    }
    return 0;
}
"""

bpf_text_disk_filter = ""
if args.disk:
    bpf_text_disk_filter = """
        if (local_strcmp(req->q->disk->disk_name, "{disk}"))
            return;
    """.format(
        disk=args.disk
    )

bpf_text_ops_filter = ""
# Operation dictionary. Full list of operations at Linux kernel
# 'include/linux/blk_types.h' header file.
blk_ops = {
    0: "Read",
    1: "Write",
    2: "Flush",
    3: "Discard",
    5: "SecureErase",
    9: "WriteZeroes",
    10: "ZoneOpen",
    11: "ZoneClose",
    12: "ZoneFinish",
    13: "ZoneAppend",
    15: "ZoneReset",
    17: "ZoneResetAll",
    34: "DrvIn",
    35: "DrvOut",
    36: "Last",
    "Read": 0,
    "Write": 1,
    "Flush": 2,
    "Discard": 3,
    "SecureErase": 5,
    "WriteZeroes": 9,
    "ZoneOpen": 10,
    "ZoneClose": 11,
    "ZoneFinish": 12,
    "ZoneAppend": 13,
    "ZoneReset": 15,
    "ZoneResetAll": 17,
    "DrvIn": 34,
    "DrvOut": 35,
    "Last": 36,
}
if args.ops:
    try:
        operation = blk_ops[args.ops]
    except KeyError:
        print("Operation does not exist. Please, introduce any valid operation")
        for k in blk_ops.keys():
            if type(k) is str:
                print(f"{k}")
        exit()

    bpf_text_ops_filter = """
        if ((req->cmd_flags & 0xff) != {ops})
            return;
    """.format(
        ops=operation
    )

bpf_text += """
void start_request(struct pt_regs *ctx, struct request *req)
{{
        struct data_t data = {{}};
        u32 max_algn_size = 4096, algn_size = 4096;
        u32 lba_len = algn_size / 4096;
        bool is_algn = false;
        u8 i;
        u32 lba_shift;

        {disk_filter}
        {ops_filter}

        data.pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        bpf_probe_read_kernel(&data.disk, sizeof(data.disk),
                              req->q->disk->disk_name);
        data.op = req->cmd_flags & 0xff;
        data.len = req->__data_len;
        lba_shift = bpf_log2(req->q->limits.logical_block_size);
        data.lba = req->__sector >> (lba_shift - SECTOR_SHIFT);

        for (i=0; i<8; i++) {{
            is_algn = !(data.len % algn_size) && !(data.lba % lba_len);
            if (is_algn) {{
                max_algn_size = algn_size;
            }}
            algn_size = algn_size << 1;
            lba_len = algn_size / 4096;
        }}
        data.algn = max_algn_size;

        events.ringbuf_output(&data, sizeof(data), 0);
        block_len.increment(bpf_log2l(req->__data_len));
        algn.increment(bpf_log2l(max_algn_size));
}}
""".format(
    disk_filter=bpf_text_disk_filter, ops_filter=bpf_text_ops_filter
)


if args.debug:
    print(args)
    print(bpf_text)

bpf = BPF(text=bpf_text)
if args.trace:
    print("Tracing block commands... Hit Ctrl-C to end.")
    print(
        "%-10s %-8s %-8s %-10s %-10s %-16s %-8s"
        % ("DISK", "OPS", "LEN", "LBA", "PID", "COMM", "ALGN")
    )

if BPF.get_kprobe_functions(b"blk_mq_start_request"):
    bpf.attach_kprobe(event="blk_mq_start_request", fn_name="start_request")


def capture_event(ctx, data, size):
    event = bpf["events"].event(data)
    if args.trace:
        print_event(event)


def print_event(event):
    try:
        op = blk_ops[event.op]
    except KeyError:
        op = event.op
    print(
        "%-10s %-8s %-8s %-10s %-10s %-16s %-8s"
        % (
            event.disk.decode("utf-8", "replace"),
            op,
            event.len,
            event.lba,
            event.pid,
            event.comm.decode("utf-8", "replace"),
            event.algn,
        ),
    )


bpf["events"].open_ring_buffer(capture_event)
block_len = bpf["block_len"]
algn = bpf["algn"]
while 1:
    try:
        bpf.ring_buffer_poll(30)
        if args.interval:
            time.sleep(abs(args.interval))
    except KeyboardInterrupt:
        bpf.ring_buffer_consume()
        print()
        block_len.print_log2_hist(
            "Block size", "operation", section_print_fn=bytes.decode
        )
        block_len.clear()
        print()
        algn.print_log2_hist("Algn size", "operation",
                             section_print_fn=bytes.decode)
        algn.clear()
        break
exit()
