#!/usr/bin/env python
#
# USAGE: test_usdt.py
#
# Copyright 2018 Facebook, Inc
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF
from unittest import main, skipUnless, TestCase
import distutils.version
import os, resource

class TestRlimitMemlock(TestCase):
    def testRlimitMemlock(self):
        text = """
BPF_HASH(unused, u64, u64, 65536);
int test() { return 0; }
"""
        # save the original memlock limits
        memlock_limit = resource.getrlimit(resource.RLIMIT_MEMLOCK)

        # set a small RLIMIT_MEMLOCK limit
        resource.setrlimit(resource.RLIMIT_MEMLOCK, (4096, 4096))

        # below will fail
        failed = 0
        try:
            b = BPF(text=text, allow_rlimit=False)
        except:
            failed = 1
        self.assertEqual(failed, 1)

        # below should succeed
        b = BPF(text=text, allow_rlimit=True)

        # reset to the original memlock limits
        resource.setrlimit(resource.RLIMIT_MEMLOCK, memlock_limit)

if __name__ == "__main__":
    main()
