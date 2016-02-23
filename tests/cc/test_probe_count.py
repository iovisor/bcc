#!/usr/bin/env python
# Copyright (c) Suchakra Sharma <suchakrapani.sharma@polymtl.ca>
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
import os
import sys
from unittest import main, TestCase

class TestKprobeCnt(TestCase):
    def setUp(self):
        self.b = BPF(text="""
        int wololo(void *ctx) {
          return 0;
        }
        """)
        self.b.attach_kprobe(event_re="^vfs_.*", fn_name="wololo")

    def test_attach1(self):
        actual_cnt = 0
        with open("/sys/kernel/debug/tracing/available_filter_functions") as f:
            for line in f:
                if str(line).startswith("vfs_"):
                    actual_cnt += 1
        open_cnt = self.b.num_open_kprobes()
        self.assertEqual(actual_cnt, open_cnt)


class TestProbeQuota(TestCase):
    def setUp(self):
        self.b = BPF(text="""int count(void *ctx) { return 0; }""")

    def test_probe_quota(self):
        with self.assertRaises(Exception):
            self.b.attach_kprobe(event_re=".*", fn_name="count")


if __name__ == "__main__":
    main()
