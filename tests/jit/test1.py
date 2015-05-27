#!/usr/bin/env python

# test program to count the packets sent to a device in a .5
# second period

from ctypes import c_uint, c_ulong, Structure
from netaddr import IPAddress
from bpf import BPF
from subprocess import check_call
import sys
from unittest import main, TestCase

arg1 = sys.argv.pop(1)
arg2 = ""
if len(sys.argv) > 1:
  arg2 = sys.argv.pop(1)

class Key(Structure):
    _fields_ = [("dip", c_uint),
                ("sip", c_uint)]
class Leaf(Structure):
    _fields_ = [("rx_pkts", c_ulong),
                ("tx_pkts", c_ulong)]

class TestBPFSocket(TestCase):
    def setUp(self):
        b = BPF(arg1, arg2, debug=0)
        fn = b.load_func("main", BPF.SOCKET_FILTER)
        BPF.attach_socket(fn, "eth0")
        self.stats = b.get_table("stats", Key, Leaf)

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
