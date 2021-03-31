#!/usr/bin/env python
#
# USAGE: test_map_batch_ops.py
#
# Copyright (c) Emilien Gobillot
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF
import distutils.version
from unittest import main, skipUnless, TestCase
import ctypes as ct
import os


def kernel_version_ge(major, minor):
    # True if running kernel is >= X.Y
    version = distutils.version.LooseVersion(os.uname()[2]).version
    if version[0] > major:
        return True
    if version[0] < major:
        return False
    if minor and version[1] < minor:
        return False
    return True


@skipUnless(kernel_version_ge(5, 6), "requires kernel >= 5.6")
class TestMapBatch(TestCase):
    def test_lookup_and_delete_batch(self):
        b = BPF(text="""BPF_HASH(map, int, int, 1024);""")
        hmap = b["map"]
        for i in range(0, 1024):
            hmap[ct.c_int(i)] = ct.c_int(i)

        # check the lookup
        i = 0
        for k, v in sorted(hmap.items_lookup_and_delete_batch()):
            self.assertEqual(k, i)
            self.assertEqual(v, i)
            i += 1
        # and check the delete has workd, i.e map is empty
        count = sum(1 for _ in hmap.items_lookup_and_delete_batch())
        self.assertEqual(count, 0)


if __name__ == "__main__":
    main()
