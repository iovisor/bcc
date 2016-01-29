#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# test program for the 'dump_func' method

from bcc import BPF
from unittest import main, TestCase

class TestDumpFunc(TestCase):
    def test_return(self):
        b = BPF(text="""
            int entry(void)
            {
                return 1;
            }""")

        self.assertEqual(
            b"\xb7\x00\x00\x00\x01\x00\x00\x00" +
            b"\x95\x00\x00\x00\x00\x00\x00\x00",
            b.dump_func("entry"))

if __name__ == "__main__":
    main()
