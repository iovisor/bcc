#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

import ctypes as ct
import os
import unittest
from bcc import BPF
import multiprocessing

class TestLru(unittest.TestCase):
    def test_lru_hash(self):
        b = BPF(text="""BPF_TABLE("lru_hash", int, u64, lru, 1024);""")
        t = b["lru"]
        for i in range(1, 1032):
            t[ct.c_int(i)] = ct.c_ulonglong(i)
        for i, v in t.items():
            self.assertEqual(v.value, i.value)
        # BPF_MAP_TYPE_LRU_HASH eviction happens in batch and we expect less
        # items than specified size.
        self.assertLess(len(t), 1024);

    def test_lru_percpu_hash(self):
        test_prog1 = """
        BPF_TABLE("lru_percpu_hash", u32, u32, stats, 1);
        int hello_world(void *ctx) {
            u32 key=0;
            u32 value = 0, *val;
            val = stats.lookup_or_init(&key, &value);
            *val += 1;
            return 0;
        }
        """
        b = BPF(text=test_prog1)
        stats_map = b.get_table("stats")
        event_name = b.get_syscall_fnname("clone")
        b.attach_kprobe(event=event_name, fn_name="hello_world")
        ini = stats_map.Leaf()
        for i in range(0, multiprocessing.cpu_count()):
            ini[i] = 0
        # First initialize with key 1
        stats_map[ stats_map.Key(1) ] = ini
        # Then initialize with key 0
        stats_map[ stats_map.Key(0) ] = ini
        # Key 1 should have been evicted
        with self.assertRaises(KeyError):
            val = stats_map[ stats_map.Key(1) ]
        f = os.popen("hostname")
        f.close()
        self.assertEqual(len(stats_map),1)
        val = stats_map[ stats_map.Key(0) ]
        sum = stats_map.sum(stats_map.Key(0))
        avg = stats_map.average(stats_map.Key(0))
        max = stats_map.max(stats_map.Key(0))
        self.assertGreater(sum.value, 0L)
        self.assertGreater(max.value, 0L)
        b.detach_kprobe(event_name)

if __name__ == "__main__":
    unittest.main()
