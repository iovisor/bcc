#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
from time import sleep
import unittest as ut

class TestPercpu(ut.TestCase):

    def test_u64(self):
        test_prog1 = """
        BPF_TABLE("pc_hash", u32, u64, stats, 1);
        int hello_world(void *ctx) {
            u32 key=0;
            u64 value = 0, *val;
            val = stats.lookup_or_init(&key, &value);
            *val += 1;
            return 0;
        }
        """
        self.addCleanup(self.cleanup)
        bpf_code = BPF(text=test_prog1)
        stats_map = bpf_code.get_table("stats")
        bpf_code.attach_kprobe(event="sys_clone", fn_name="hello_world")
        sleep(1)
        self.assertEqual(len(stats_map),1)
        for x in range(0, 10):
            ini = stats_map.Leaf(0,0,0,0,0,0,0,0)
            stats_map[ stats_map.Key(0) ] = ini
            sleep(1)
            k = stats_map[ stats_map.Key(0) ]
            x = stats_map.sum(stats_map.Key(0))
            y = stats_map.average(stats_map.Key(0))
            z = stats_map.max(stats_map.Key(0))
            print (x.value)
            self.assertGreater(x.value, 1L)
            self.assertGreater(z.value, 1L)

    def test_u32(self):
        test_prog1 = """
        BPF_TABLE("pc_array", u32, u32, stats, 1);
        int hello_world(void *ctx) {
            u32 key=0;
            u32 value = 0, *val;
            val = stats.lookup_or_init(&key, &value);
            *val += 1;
            return 0;
        }
        """
        self.addCleanup(self.cleanup)
        bpf_code = BPF(text=test_prog1)
        stats_map = bpf_code.get_table("stats")
        bpf_code.attach_kprobe(event="sys_clone", fn_name="hello_world")
        sleep(1)
        self.assertEqual(len(stats_map),1)
        for x in range(0, 10):
            ini = stats_map.Leaf(0,0,0,0,0,0,0,0)
            stats_map[ stats_map.Key(0) ] = ini
            sleep(1)
            k = stats_map[ stats_map.Key(0) ]
            x = stats_map.sum(stats_map.Key(0))
            y = stats_map.average(stats_map.Key(0))
            z = stats_map.max(stats_map.Key(0))
            self.assertGreater(x.value, 1L)
            self.assertGreater(z.value, 1L)

    def test_struct_custom_func(self):
        test_prog2 = """
        typedef struct counter {
        u32 c1;
        u32 c2;
        } counter;
        BPF_TABLE("pc_hash", u32, counter, stats, 1);
        int hello_world(void *ctx) {
            u32 key=0;
            counter value = {0,0}, *val;
            val = stats.lookup_or_init(&key, &value);
            val->c1 += 1;
            val->c2 += 1;
            return 0;
        }
        """
        self.addCleanup(self.cleanup)
        bpf_code = BPF(text=test_prog2)
        stats_map = bpf_code.get_table("stats",
                reducer=lambda x,y: stats_map.sLeaf(x.c1+y.c1))
        bpf_code.attach_kprobe(event="sys_clone", fn_name="hello_world")
        sleep(1)
        self.assertEqual(len(stats_map),1)
        for x in range(0, 10):
            ini = stats_map.Leaf()
            for i in ini:
                i = stats_map.sLeaf(0,0)
            stats_map[ stats_map.Key(0) ] = ini
            sleep(1)
            k = stats_map[ stats_map.Key(0) ]
            self.assertGreater(k.c1, 1L)

    def cleanup(self):
        BPF.detach_kprobe("sys_clone")


if __name__ == "__main__":
    ut.main()