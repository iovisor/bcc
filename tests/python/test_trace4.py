#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
import os
import sys
from unittest import main, TestCase

class TestKprobeRgx(TestCase):
    def setUp(self):
        self.b = BPF(text=b"""
        typedef struct { int idx; } Key;
        typedef struct { u64 val; } Val;
        BPF_HASH(stats, Key, Val, 3);
        int hello(void *ctx) {
          stats.lookup_or_init(&(Key){1}, &(Val){0})->val++;
          return 0;
        }
        int goodbye(void *ctx) {
          stats.lookup_or_init(&(Key){2}, &(Val){0})->val++;
          return 0;
        }
        """)
        self.b.attach_kprobe(event_re=b"^" + self.b.get_syscall_prefix() + b"bp.*",
                             fn_name=b"hello")
        self.b.attach_kretprobe(event_re=b"^" + self.b.get_syscall_prefix() + b"bp.*",
                                fn_name=b"goodbye")

    def test_send1(self):
        k1 = self.b[b"stats"].Key(1)
        k2 = self.b[b"stats"].Key(2)
        self.assertTrue(self.b[b"stats"][k1].val >= 2)
        self.assertTrue(self.b[b"stats"][k2].val == 1)

class TestKprobeReplace(TestCase):
    def setUp(self):
        self.b = BPF(text=b"int empty(void *ctx) { return 0; }")

    def test_periods(self):
        self.b.attach_kprobe(event_re=b"^tcp_enter_cwr.*", fn_name=b"empty")

if __name__ == "__main__":
    main()
