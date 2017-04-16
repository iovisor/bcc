#!/usr/bin/env python
# Copyright (c) 2016 Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

import ctypes as ct
import unittest
from bcc import BPF

class TestSharedTable(unittest.TestCase):
    def test_close_extern(self):
        b1 = BPF(text="""BPF_TABLE_PUBLIC("array", int, int, table1, 10);""")

        with BPF(text="""BPF_TABLE("extern", int, int, table1, 10);""") as b2:
            t2 = b2["table1"]
            t2[ct.c_int(1)] = ct.c_int(10)
            self.assertEqual(len(t2), 10)

        t1 = b1["table1"]
        self.assertEqual(t1[ct.c_int(1)].value, 10)
        self.assertEqual(len(t1), 10)

if __name__ == "__main__":
    unittest.main()
