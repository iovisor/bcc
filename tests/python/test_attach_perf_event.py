#!/usr/bin/env python
# Copyright 2021, Athira Rajeev, IBM Corp.
# Licensed under the Apache License, Version 2.0 (the "License")

import bcc
import os
import time
import unittest
from bcc import BPF, PerfType, PerfHWConfig, PerfEventSampleFormat
from bcc import Perf
from time import sleep
from utils import kernel_version_ge, mayFail

class TestPerfAttachRaw(unittest.TestCase):
    @mayFail("This fails on github actions environment, hw perf events are not supported")
    @unittest.skipUnless(kernel_version_ge(4,9), "requires kernel >= 4.9")
    def test_attach_raw_event(self):
        bpf_text="""
#include <linux/perf_event.h>
struct key_t {
    int cpu;
    int pid;
    char name[100];
};

static inline __attribute__((always_inline)) void get_key(struct key_t* key) {
    key->cpu = bpf_get_smp_processor_id();
    key->pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&(key->name), sizeof(key->name));
}

int on_sample_hit(struct bpf_perf_event_data *ctx) {
    struct key_t key = {};
    get_key(&key);
    u64 addr = 0;
    struct bpf_perf_event_data_kern *kctx;
    struct perf_sample_data *data;

    kctx = (struct bpf_perf_event_data_kern *)ctx;
    bpf_probe_read(&data, sizeof(struct perf_sample_data*), &(kctx->data));
    if (data)
        bpf_probe_read(&addr, sizeof(u64), &(data->addr));

    bpf_trace_printk("Hit a sample with pid: %ld, comm: %s, addr: 0x%llx\\n", key.pid, key.name, addr);
    return 0;
}

"""

        b = BPF(text=bpf_text)
        try:
            event_attr = Perf.perf_event_attr()
            event_attr.type = Perf.PERF_TYPE_HARDWARE
            event_attr.config = PerfHWConfig.CACHE_MISSES
            event_attr.sample_period = 1000000
            event_attr.sample_type = PerfEventSampleFormat.ADDR
            event_attr.exclude_kernel = 1
            b.attach_perf_event_raw(attr=event_attr, fn_name="on_sample_hit", pid=-1, cpu=-1)
        except Exception:
            print("Failed to attach to a raw event. Please check the event attr used")
            exit()

        print("Running for 2 seconds or hit Ctrl-C to end. Check trace file for samples information written by bpf_trace_printk.")
        sleep(2)

if __name__ == "__main__":
    unittest.main()
