#!/usr/bin/env python

# test program to count the packets sent to a device in a .5
# second period

from ctypes import c_uint, c_ulong, Structure
from netaddr import IPAddress
from bpf import BPF
from subprocess import check_call
from unittest import main, TestCase

class Key(Structure):
    _fields_ = [("dip", c_uint),
                ("sip", c_uint)]
class Leaf(Structure):
    _fields_ = [("rx_pkts", c_ulong),
                ("tx_pkts", c_ulong)]

class TestBPFSocket(TestCase):
    def setUp(self):
        self.prog = BPF("main", "test1.b", "proto.b", debug=0)
        self.prog.attach("eth0")
        self.stats = self.prog.table("stats", Key, Leaf)

    def test_ping(self):
        cmd = ["ping", "-f", "-c", "100", "172.16.1.1"]
        check_call(cmd)
        #for key in self.stats.iter():
        #    leaf = self.stats.get(key)
        #    print(IPAddress(key.sip), "=>", IPAddress(key.dip),
        #          "rx", leaf.rx_pkts, "tx", leaf.tx_pkts)
        key = Key(IPAddress("172.16.1.2").value, IPAddress("172.16.1.1").value)
        leaf = self.stats.get(key)
        self.assertEqual(leaf.rx_pkts, 100)
        self.assertEqual(leaf.tx_pkts, 100)

if __name__ == "__main__":
    main()
