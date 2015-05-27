#!/usr/bin/env python

from ctypes import c_uint, c_ulonglong, Structure
from netaddr import IPAddress
from bpf import BPF
from socket import socket, AF_INET, SOCK_DGRAM
import sys
from time import sleep
from unittest import main, TestCase

arg1 = sys.argv.pop(1)
arg2 = ""
if len(sys.argv) > 1:
  arg2 = sys.argv.pop(1)

class Key(Structure):
    _fields_ = [("dip", c_uint),
                ("sip", c_uint)]
class Leaf(Structure):
    _fields_ = [("xdip", c_uint),
                ("xsip", c_uint),
                ("xlated_pkts", c_ulonglong)]

class TestBPFSocket(TestCase):
    def setUp(self):
        b = BPF(arg1, arg2, debug=0)
        fn = b.load_func("main", BPF.SCHED_CLS)
        BPF.attach_classifier(fn, "eth0")
        self.xlate = b.get_table("xlate", Key, Leaf)

    def test_xlate(self):
        key = Key(IPAddress("172.16.1.1").value, IPAddress("172.16.1.2").value)
        leaf = Leaf(IPAddress("192.168.1.1").value, IPAddress("192.168.1.2").value, 0)
        self.xlate.put(key, leaf)
        udp = socket(AF_INET, SOCK_DGRAM)
        udp.sendto(b"a" * 10, ("172.16.1.1", 5000))
        leaf = self.xlate.get(key)
        self.assertGreater(leaf.xlated_pkts, 0)

if __name__ == "__main__":
    main()
