#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# test program to count the packets sent to a device in a .5
# second period

from ctypes import c_uint, c_ulong, Structure
from netaddr import IPAddress
from bcc import BPF
from subprocess import check_call
import sys
from unittest import main, TestCase

arg1 = sys.argv.pop(1)
arg2 = ""
if len(sys.argv) > 1:
  arg2 = sys.argv.pop(1)

Key = None
Leaf = None
if arg1.endswith(".b"):
    class Key(Structure):
        _fields_ = [("dip", c_uint),
                    ("sip", c_uint)]
    class Leaf(Structure):
        _fields_ = [("rx_pkts", c_ulong),
                    ("tx_pkts", c_ulong)]

class TestBPFSocket(TestCase):
    def setUp(self):
        b = BPF(arg1, arg2, debug=0)
        fn = b.load_func("on_packet", BPF.SOCKET_FILTER)
        BPF.attach_raw_socket(fn, "eth0")
        self.stats = b.get_table("stats", Key, Leaf)

    def test_ping(self):
        cmd = ["ping", "-f", "-c", "100", "172.16.1.1"]
        check_call(cmd)
        #for key, leaf in self.stats.items():
        #    print(IPAddress(key.sip), "=>", IPAddress(key.dip),
        #          "rx", leaf.rx_pkts, "tx", leaf.tx_pkts)
        key = self.stats.Key(IPAddress("172.16.1.2").value, IPAddress("172.16.1.1").value)
        leaf = self.stats[key]
        self.assertEqual(leaf.rx_pkts, 100)
        self.assertEqual(leaf.tx_pkts, 100)
        del self.stats[key]
        with self.assertRaises(KeyError):
            x = self.stats[key]
        with self.assertRaises(KeyError):
            del self.stats[key]
        self.stats.clear()
        self.assertEqual(len(self.stats), 0)
        self.stats[key] = leaf
        self.assertEqual(len(self.stats), 1)
        self.stats.clear()
        self.assertEqual(len(self.stats), 0)

    def test_empty_key(self):
        # test with a 0 key
        self.stats.clear()
        self.stats[self.stats.Key()] = self.stats.Leaf(100, 200)
        x = self.stats.popitem()
        self.stats[self.stats.Key(10, 20)] = self.stats.Leaf(300, 400)
        with self.assertRaises(KeyError):
            x = self.stats[self.stats.Key()]
        (_, x) = self.stats.popitem()
        self.assertEqual(x.rx_pkts, 300)
        self.assertEqual(x.tx_pkts, 400)
        self.stats.clear()
        self.assertEqual(len(self.stats), 0)
        self.stats[self.stats.Key()] = x
        self.stats[self.stats.Key(0, 1)] = x
        self.stats[self.stats.Key(0, 2)] = x
        self.stats[self.stats.Key(0, 3)] = x
        self.assertEqual(len(self.stats), 4)

if __name__ == "__main__":
    main()
