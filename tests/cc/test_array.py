#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
from ctypes import c_int, c_ulonglong
import random
import time
from unittest import main, TestCase

class TestArray(TestCase):
    def test_simple(self):
        b = BPF(text="""BPF_TABLE("array", int, u64, table1, 128);""")
        t1 = b["table1"]
        t1[c_int(0)] = c_ulonglong(100)
        t1[c_int(127)] = c_ulonglong(1000)
        for i, v in t1.items():
            if i.value == 0:
                self.assertEqual(v.value, 100)
            if i.value == 127:
                self.assertEqual(v.value, 1000)
        self.assertEqual(len(t1), 128)

if __name__ == "__main__":
    main()
