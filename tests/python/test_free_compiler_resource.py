#!/usr/bin/env python
# Copyright (c) 2017 Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# test program for the 'free_compiler_resource' method

from bcc import BPF
from unittest import main, TestCase
import os
import time

class TestFreeCompilerResource(TestCase):
    def _rss_anon(self):
        with open('/proc/%d/status' % os.getpid(), 'r') as f:
            for line in f:
                if 'RssAnon' in line:
                    return line
    def test_simple(self):
        b = BPF(text="""
            BPF_HASH(stats, int, int, 1024);
            int handle_packet(void *ctx)
            {
                return 0;
            }""")
        fn = b.load_func("handle_packet", BPF.SCHED_CLS)
        try:
            scale = {'kB': 1024.0, 'mB': 1024.0*1024.0,
                     'KB': 1024.0, 'MB': 1024.0*1024.0}
            v = self._rss_anon().split(None, 3)
            print("Before freeing and returning memory:", v)
            m1 = float(v[1]) * scale[v[2]]
            b.free_compiler_resource(True)
            v = self._rss_anon().split(None, 3)
            print("After freeing and returning memory:", v)
            m2 = float(v[1]) * scale[v[2]]
            self.assertGreater(m1, m2)
        except:
            return

if __name__ == "__main__":
    main()
