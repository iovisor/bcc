#!/usr/bin/env python
#
# USAGE: test_map_batch_ops.py
#
# Copyright (c) Emilien Gobillot
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from unittest import main, skipUnless, TestCase
from bcc import BPF

import os
import distutils.version
import ctypes as ct


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
    MAPSIZE = 1024

    def fill_hashmap(self):
        b = BPF(text=b"""BPF_HASH(map, int, int, %d);""" % self.MAPSIZE)
        hmap = b[b"map"]
        for i in range(0, self.MAPSIZE):
            hmap[ct.c_int(i)] = ct.c_int(i)
        return hmap

    def check_hashmap_values(self, it):
        i = 0
        for k, v in sorted(it):
            self.assertEqual(k, i)
            self.assertEqual(v, i)
            i += 1
        return i

    def test_lookup_and_delete_batch(self):
        # fill the hashmap
        hmap = self.fill_hashmap()

        # check values and count them
        count = self.check_hashmap_values(hmap.items_lookup_and_delete_batch())
        self.assertEqual(count, self.MAPSIZE)

        # and check the delete has worked, i.e map is now empty
        count = sum(1 for _ in hmap.items_lookup_batch())
        self.assertEqual(count, 0)

    def test_lookup_batch(self):
        # fill the hashmap
        hmap = self.fill_hashmap()

        # check values and count them
        count = self.check_hashmap_values(hmap.items_lookup_batch())
        self.assertEqual(count, self.MAPSIZE)

    def test_delete_batch_all_keysp(self):
        # Delete all key/value in the map
        # fill the hashmap
        hmap = self.fill_hashmap()
        hmap.items_delete_batch()

        # check the delete has worked, i.e map is now empty
        count = sum(1 for _ in hmap.items())
        self.assertEqual(count, 0)

    def test_delete_batch_subset(self):
        # Delete only a subset of key/value in the map
        # fill the hashmap
        hmap = self.fill_hashmap()
        # Get 4 keys in this map.
        subset_size = 32
        keys = (hmap.Key * subset_size)()
        i = 0
        for k, _ in hmap.items_lookup_batch():
            if i < subset_size:
                keys[i] = k
                i += 1
            else:
                break

        hmap.items_delete_batch(keys)
        # check the delete has worked, i.e map is now empty
        count = sum(1 for _ in hmap.items())
        self.assertEqual(count, self.MAPSIZE - subset_size)

    def test_update_batch(self):
        hmap = self.fill_hashmap()

        # preparing keys and new values arrays
        keys = (hmap.Key * self.MAPSIZE)()
        new_values = (hmap.Leaf * self.MAPSIZE)()
        for i in range(self.MAPSIZE):
            keys[i] = ct.c_int(i)
            new_values[i] = ct.c_int(-1)
        hmap.items_update_batch(keys, new_values)

        # check the update has worked, i.e sum of values is -NUM_KEYS
        count = sum(v.value for v in hmap.values())
        self.assertEqual(count, -1*self.MAPSIZE)


if __name__ == "__main__":
    main()
