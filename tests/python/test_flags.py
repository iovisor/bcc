#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

import unittest
from bcc import BPF

class TestLru(unittest.TestCase):
    def test_lru_map_flags(self):
        test_prog1 = """
        BPF_F_TABLE("lru_hash", int, u64, lru, 1024, BPF_F_NO_COMMON_LRU);
        """
        b = BPF(text=test_prog1)
        t = b["lru"]
        self.assertEqual(t.flags, 2);

    def test_hash_map_flags(self):
        test_prog1 = """
        BPF_F_TABLE("hash", int, u64, hash, 1024, BPF_F_NO_PREALLOC);
        """
        b = BPF(text=test_prog1)
        t = b["hash"]
        self.assertEqual(t.flags, 1);

if __name__ == "__main__":
    unittest.main()
