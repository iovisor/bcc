#!/usr/bin/env python3
#
# USAGE: test_map_batch_ops.py
#
# Copyright (c) Emilien Gobillot
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from unittest import main, skipUnless, TestCase
from utils import kernel_version_ge
from bcc import BPF

import os
import ctypes as ct


@skipUnless(kernel_version_ge(5, 6), "requires kernel >= 5.6")
class TestMapBatch(TestCase):
    MAPSIZE = 1024
    SUBSET_SIZE = 32

    def fill_hashmap(self):
        b = BPF(text=b"""BPF_HASH(map, int, int, %d);""" % self.MAPSIZE)
        hmap = b[b"map"]
        for i in range(0, self.MAPSIZE):
            hmap[ct.c_int(i)] = ct.c_int(i)
        return hmap

    def prepare_keys_subset(self, hmap, count=None):
        if not count:
            count = self.SUBSET_SIZE
        keys = (hmap.Key * count)()
        i = 0
        for k, _ in sorted(hmap.items_lookup_batch(), key=lambda k:k[0].value):
            if i < count:
                keys[i] = k.value
                i += 1
            else:
                break

        return keys

    def prepare_values_subset(self, hmap, count=None):
        if not count:
            count = self.SUBSET_SIZE
        values = (hmap.Leaf * count)()
        i = 0
        for _, v in sorted(hmap.items_lookup_batch(), key=lambda k:k[0].value):
            if i < count:
                values[i] = v.value * v.value
                i += 1
            else:
                break
        return values

    def check_hashmap_values(self, it):
        i = 0
        for k, v in sorted(it, key=lambda kv:kv[0].value):
            self.assertEqual(k.value, i)
            self.assertEqual(v.value, i)
            i += 1
        return i

    def test_lookup_and_delete_batch_all_keys(self):
        # fill the hashmap
        hmap = self.fill_hashmap()

        # check values and count them
        count = self.check_hashmap_values(hmap.items_lookup_and_delete_batch())
        self.assertEqual(count, self.MAPSIZE)

        # and check the delete has worked, i.e map is now empty
        count = sum(1 for _ in hmap.items())
        self.assertEqual(count, 0)

    def test_lookup_batch_all_keys(self):
        # fill the hashmap
        hmap = self.fill_hashmap()

        # check values and count them
        count = self.check_hashmap_values(hmap.items_lookup_batch())
        self.assertEqual(count, self.MAPSIZE)

    def test_delete_batch_all_keys(self):
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
        keys = self.prepare_keys_subset(hmap)

        hmap.items_delete_batch(keys)
        # check the delete has worked, i.e map is now empty
        count = sum(1 for _ in hmap.items())
        self.assertEqual(count, self.MAPSIZE - self.SUBSET_SIZE)

    def test_update_batch_all_keys(self):
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

    def test_update_batch_subset(self):
        # fill the hashmap
        hmap = self.fill_hashmap()
        keys = self.prepare_keys_subset(hmap, count=self.SUBSET_SIZE)
        new_values = self.prepare_values_subset(hmap, count=self.SUBSET_SIZE)

        hmap.items_update_batch(keys, new_values)

        # check all the values in the map
        # the first self.SUBSET_SIZE keys follow this rule value = keys * keys
        # the remaning keys follow this rule : value = keys
        i = 0
        for k, v in sorted(hmap.items_lookup_batch(),
                           key=lambda kv:kv[0].value):
            if i < self.SUBSET_SIZE:
                # values are the square of the keys
                self.assertEqual(v.value, k.value * k.value)
                i += 1
            else:
                # values = keys
                self.assertEqual(v.value, k.value)

        self.assertEqual(i, self.SUBSET_SIZE)


if __name__ == "__main__":
    main()
