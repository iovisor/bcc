#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
from ctypes import c_int, c_ulonglong
import random
import time
from unittest import main, TestCase

class TestHistogram(TestCase):
    def test_simple(self):
        b = BPF(text="""
#include <uapi/linux/ptrace.h>
struct bpf_map;
BPF_HISTOGRAM(hist1);
BPF_HASH(stub);
int kprobe__htab_map_delete_elem(struct pt_regs *ctx, struct bpf_map *map, u64 *k) {
    hist1.increment(bpf_log2l(*k));
    return 0;
}
""")
        for i in range(0, 32):
            for j in range(0, random.randint(1, 10)):
                try: del b["stub"][c_ulonglong(1 << i)]
                except: pass
        b["hist1"].print_log2_hist()

        for i in range(32, 64):
            for j in range(0, random.randint(1, 10)):
                try: del b["stub"][c_ulonglong(1 << i)]
                except: pass
        b["hist1"].print_log2_hist()

    def test_struct(self):
        b = BPF(text="""
#include <uapi/linux/ptrace.h>
struct bpf_map;
typedef struct { void *map; u64 slot; } Key;
BPF_HISTOGRAM(hist1, Key, 1024);
BPF_HASH(stub1);
BPF_HASH(stub2);
int kprobe__htab_map_delete_elem(struct pt_regs *ctx, struct bpf_map *map, u64 *k) {
    hist1.increment((Key){map, bpf_log2l(*k)});
    return 0;
}
""")
        for i in range(0, 64):
            for j in range(0, random.randint(1, 10)):
                try: del b["stub1"][c_ulonglong(1 << i)]
                except: pass
                try: del b["stub2"][c_ulonglong(1 << i)]
                except: pass
        b["hist1"].print_log2_hist()

    def test_chars(self):
        b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
typedef struct { char name[TASK_COMM_LEN]; u64 slot; } Key;
BPF_HISTOGRAM(hist1, Key, 1024);
int kprobe__finish_task_switch(struct pt_regs *ctx, struct task_struct *prev) {
    Key k = {.slot = bpf_log2l(prev->real_start_time)};
    if (!bpf_get_current_comm(&k.name, sizeof(k.name)))
        hist1.increment(k);
    return 0;
}
""")
        for i in range(0, 100): time.sleep(0.01)
        b["hist1"].print_log2_hist()


if __name__ == "__main__":
    main()
