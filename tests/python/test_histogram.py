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
        b.cleanup()

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
        b.cleanup()

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
        b.cleanup()

    def test_multiple_key(self):
        b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <uapi/linux/fs.h>
struct hist_s_key {
    u64 key_1;
    u64 key_2;
};
struct hist_key {
    struct hist_s_key s_key;
    u64 slot;
};
BPF_HISTOGRAM(mk_hist, struct hist_key, 1024);
int kprobe__vfs_read(struct pt_regs *ctx, struct file *file,
        char __user *buf, size_t count) {
    struct hist_key key = {.slot = bpf_log2l(count)};
    key.s_key.key_1 = (unsigned long)buf & 0x70;
    key.s_key.key_2 = (unsigned long)buf & 0x7;
    mk_hist.increment(key);
    return 0;
}
""")
        def bucket_sort(buckets):
            buckets.sort()
            return buckets

        for i in range(0, 100): time.sleep(0.01)
        b["mk_hist"].print_log2_hist("size", "k_1 & k_2",
                section_print_fn=lambda bucket: "%3d %d" % (bucket[0], bucket[1]),
                bucket_fn=lambda bucket: (bucket.key_1, bucket.key_2),
                strip_leading_zero=True,
                bucket_sort_fn=bucket_sort)
        b.cleanup()

if __name__ == "__main__":
    main()
