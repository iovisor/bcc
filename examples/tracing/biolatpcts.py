#!/usr/bin/python
#
# biolatpcts.py  IO latency percentile calculation example
#
# Copyright (C) 2020 Tejun Heo <tj@kernel.org>
# Copyright (C) 2020 Facebook

from __future__ import print_function
from bcc import BPF
from time import sleep

bpf_source = """
#include <linux/blk_types.h>
#include <linux/blkdev.h>
#include <linux/time64.h>

BPF_PERCPU_ARRAY(lat_100ms, u64, 100);
BPF_PERCPU_ARRAY(lat_1ms, u64, 100);
BPF_PERCPU_ARRAY(lat_10us, u64, 100);

void kprobe_blk_account_io_done(struct pt_regs *ctx, struct request *rq, u64 now)
{
        unsigned int cmd_flags;
        u64 dur;
        size_t base, slot;

        if (!rq->io_start_time_ns)
                return;

        dur = now - rq->io_start_time_ns;

        slot = min_t(size_t, div_u64(dur, 100 * NSEC_PER_MSEC), 99);
        lat_100ms.increment(slot);
        if (slot)
                return;

        slot = min_t(size_t, div_u64(dur, NSEC_PER_MSEC), 99);
        lat_1ms.increment(slot);
        if (slot)
                return;

        slot = min_t(size_t, div_u64(dur, 10 * NSEC_PER_USEC), 99);
        lat_10us.increment(slot);
}
"""

bpf = BPF(text=bpf_source)
bpf.attach_kprobe(event='blk_account_io_done', fn_name='kprobe_blk_account_io_done')

cur_lat_100ms = bpf['lat_100ms']
cur_lat_1ms = bpf['lat_1ms']
cur_lat_10us = bpf['lat_10us']

last_lat_100ms = [0] * 100
last_lat_1ms = [0] * 100
last_lat_10us = [0] * 100

lat_100ms = [0] * 100
lat_1ms = [0] * 100
lat_10us = [0] * 100

def find_pct(req, total, slots, idx, counted):
    while idx > 0:
        idx -= 1
        if slots[idx] > 0:
            counted += slots[idx]
            if (counted / total) * 100 >= 100 - req:
                break
    return (idx, counted)

def calc_lat_pct(req_pcts, total, lat_100ms, lat_1ms, lat_10us):
    pcts = [0] * len(req_pcts)

    if total == 0:
        return pcts

    data = [(100 * 1000, lat_100ms), (1000, lat_1ms), (10, lat_10us)]
    data_sel = 0
    idx = 100
    counted = 0

    for pct_idx in reversed(range(len(req_pcts))):
        req = float(req_pcts[pct_idx])
        while True:
            last_counted = counted
            (gran, slots) = data[data_sel]
            (idx, counted) = find_pct(req, total, slots, idx, counted)
            if idx > 0 or data_sel == len(data) - 1:
                break
            counted = last_counted
            data_sel += 1
            idx = 100

        pcts[pct_idx] = gran * idx + gran / 2

    return pcts

print('Block I/O latency percentile example. See tools/biolatpcts.py for the full utility.')

while True:
    sleep(3)

    lat_total = 0;

    for i in range(100):
        v = cur_lat_100ms.sum(i).value
        lat_100ms[i] = max(v - last_lat_100ms[i], 0)
        last_lat_100ms[i] = v

        v = cur_lat_1ms.sum(i).value
        lat_1ms[i] = max(v - last_lat_1ms[i], 0)
        last_lat_1ms[i] = v

        v = cur_lat_10us.sum(i).value
        lat_10us[i] = max(v - last_lat_10us[i], 0)
        last_lat_10us[i] = v

        lat_total += lat_100ms[i]

    target_pcts = [50, 75, 90, 99]
    pcts = calc_lat_pct(target_pcts, lat_total, lat_100ms, lat_1ms, lat_10us);
    for i in range(len(target_pcts)):
        print('p{}={}us '.format(target_pcts[i], int(pcts[i])), end='')
    print()
