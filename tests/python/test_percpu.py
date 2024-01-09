#!/usr/bin/env python3
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

import os
import unittest
from bcc import BPF
import multiprocessing

MONITORED_SYSCALL=b"execve"

class TestPercpu(unittest.TestCase):

    def setUp(self):
        try:
            b = BPF(text=b'BPF_PERCPU_ARRAY(stub, u32, 1);')
        except:
            raise unittest.SkipTest("PerCpu unsupported on this kernel")

    def test_helper(self):
        test_prog1 = b"""
        BPF_PERCPU_ARRAY(stub_default);
        BPF_PERCPU_ARRAY(stub_type, u64);
        BPF_PERCPU_ARRAY(stub_full, u64, 1024);
        """
        BPF(text=test_prog1)

    def test_u64(self):
        test_prog1 = b"""
        BPF_PERCPU_HASH(stats, u32, u64, 1);
        int hello_world(void *ctx) {
            u32 key=0;
            u64 value = 0, *val;
            val = stats.lookup_or_try_init(&key, &value);
            if (val) {
                *val += 1;
            }
            return 0;
        }
        """
        bpf_code = BPF(text=test_prog1)
        stats_map = bpf_code.get_table(b"stats")
        event_name = bpf_code.get_syscall_fnname(MONITORED_SYSCALL)
        bpf_code.attach_kprobe(event=event_name, fn_name=b"hello_world")
        ini = stats_map.Leaf()
        for i in range(0, multiprocessing.cpu_count()):
            ini[i] = 0
        stats_map[ stats_map.Key(0) ] = ini
        f = os.popen("hostname")
        f.close()
        self.assertEqual(len(stats_map),1)
        val = stats_map[ stats_map.Key(0) ]
        sum = stats_map.sum(stats_map.Key(0))
        avg = stats_map.average(stats_map.Key(0))
        max = stats_map.max(stats_map.Key(0))
        self.assertGreater(sum.value, int(0))
        self.assertGreater(max.value, int(0))
        bpf_code.detach_kprobe(event_name)

    def test_u32(self):
        test_prog1 = b"""
        BPF_PERCPU_ARRAY(stats, u32, 1);
        int hello_world(void *ctx) {
            u32 key=0;
            u32 value = 0, *val;
            val = stats.lookup_or_try_init(&key, &value);
            if (val) {
                *val += 1;
            }
            return 0;
        }
        """
        bpf_code = BPF(text=test_prog1)
        stats_map = bpf_code.get_table(b"stats")
        event_name = bpf_code.get_syscall_fnname(MONITORED_SYSCALL)
        bpf_code.attach_kprobe(event=event_name, fn_name=b"hello_world")
        ini = stats_map.Leaf()
        for i in range(0, multiprocessing.cpu_count()):
            ini[i] = 0
        stats_map[ stats_map.Key(0) ] = ini
        f = os.popen("hostname")
        f.close()
        self.assertEqual(len(stats_map),1)
        val = stats_map[ stats_map.Key(0) ]
        sum = stats_map.sum(stats_map.Key(0))
        avg = stats_map.average(stats_map.Key(0))
        max = stats_map.max(stats_map.Key(0))
        self.assertGreater(sum.value, int(0))
        self.assertGreater(max.value, int(0))
        bpf_code.detach_kprobe(event_name)

    def test_struct_custom_func(self):
        test_prog2 = b"""
        typedef struct counter {
        u32 c1;
        u32 c2;
        } counter;
        BPF_PERCPU_HASH(stats, u32, counter, 1);
        int hello_world(void *ctx) {
            u32 key=0;
            counter value = {0,0}, *val;
            val = stats.lookup_or_try_init(&key, &value);
            if (val) {
                val->c1 += 1;
                val->c2 += 1;
            }
            return 0;
        }
        """
        bpf_code = BPF(text=test_prog2)
        stats_map = bpf_code.get_table(b"stats",
                reducer=lambda x,y: stats_map.sLeaf(x.c1+y.c1))
        event_name = bpf_code.get_syscall_fnname(MONITORED_SYSCALL)
        bpf_code.attach_kprobe(event=event_name, fn_name=b"hello_world")
        ini = stats_map.Leaf()
        for i in ini:
            i = stats_map.sLeaf(0,0)
        stats_map[ stats_map.Key(0) ] = ini
        f = os.popen("hostname")
        f.close()
        self.assertEqual(len(stats_map),1)
        k = stats_map[ stats_map.Key(0) ]
        self.assertGreater(k.c1, int(0))
        bpf_code.detach_kprobe(event_name)


if __name__ == "__main__":
    unittest.main()
