#!/usr/bin/env python
# Copyright (c) 2017 Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

import ctypes as ct
import unittest
from bcc import BPF
from netaddr import IPAddress

class KeyV4(ct.Structure):
    _fields_ = [("prefixlen", ct.c_uint),
                ("data", ct.c_ubyte * 4)]

class KeyV6(ct.Structure):
    _fields_ = [("prefixlen", ct.c_uint),
                ("data", ct.c_ushort * 8)]

class TestLpmTrie(unittest.TestCase):
    def test_lpm_trie_v4(self):
        test_prog1 = """
        BPF_LPM_TRIE(trie, u64, int, 16);
        """
        b = BPF(text=test_prog1)
        t = b["trie"]

        k1 = KeyV4(24, (192, 168, 0, 0))
        v1 = ct.c_int(24)
        t[k1] = v1

        k2 = KeyV4(28, (192, 168, 0, 0))
        v2 = ct.c_int(28)
        t[k2] = v2

        k = KeyV4(32, (192, 168, 0, 15))
        self.assertEqual(t[k].value, 28)

        k = KeyV4(32, (192, 168, 0, 127))
        self.assertEqual(t[k].value, 24)

        with self.assertRaises(KeyError):
            k = KeyV4(32, (172, 16, 1, 127))
            v = t[k]

    def test_lpm_trie_v6(self):
        test_prog1 = """
        struct key_v6 {
            u32 prefixlen;
            u32 data[4];
        };
        BPF_LPM_TRIE(trie, struct key_v6, int, 16);
        """
        b = BPF(text=test_prog1)
        t = b["trie"]

        k1 = KeyV6(64, IPAddress('2a00:1450:4001:814:200e::').words)
        v1 = ct.c_int(64)
        t[k1] = v1

        k2 = KeyV6(96, IPAddress('2a00:1450:4001:814::200e').words)
        v2 = ct.c_int(96)
        t[k2] = v2

        k = KeyV6(128, IPAddress('2a00:1450:4001:814::1024').words)
        self.assertEqual(t[k].value, 96)

        k = KeyV6(128, IPAddress('2a00:1450:4001:814:2046::').words)
        self.assertEqual(t[k].value, 64)

        with self.assertRaises(KeyError):
            k = KeyV6(128, IPAddress('2a00:ffff::').words)
            v = t[k]

if __name__ == "__main__":
    unittest.main()
