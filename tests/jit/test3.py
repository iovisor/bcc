#!/usr/bin/env python

from ctypes import c_ushort, c_int, c_ulonglong
from netaddr import IPAddress
from bpf import BPF
from socket import socket, AF_INET, SOCK_DGRAM
import sys
from time import sleep
from unittest import main, TestCase

arg1 = sys.argv.pop(1)

S_EOP = 1
S_ETHER = 2
S_ARP = 3
S_IP = 4

class TestBPFSocket(TestCase):
    def setUp(self):
        b = BPF(dp_file=arg1, debug=0)
        ether_fn = b.load_func("parse_ether", BPF.SCHED_CLS)
        arp_fn = b.load_func("parse_arp", BPF.SCHED_CLS)
        ip_fn = b.load_func("parse_ip", BPF.SCHED_CLS)
        eop_fn = b.load_func("eop", BPF.SCHED_CLS)
        BPF.attach_classifier(ether_fn, "eth0")
        self.jump = b.get_table("jump", c_int, c_int)
        self.jump.put(c_int(S_ARP), c_int(arp_fn.fd))
        self.jump.put(c_int(S_IP), c_int(ip_fn.fd))
        self.jump.put(c_int(S_EOP), c_int(eop_fn.fd))
        self.stats = b.get_table("stats", c_int, c_ulonglong)

    def test_jumps(self):
        udp = socket(AF_INET, SOCK_DGRAM)
        udp.sendto(b"a" * 10, ("172.16.1.1", 5000))
        self.assertGreater(self.stats.get(c_int(S_IP)).value, 0)
        self.assertGreater(self.stats.get(c_int(S_ARP)).value, 0)
        self.assertGreater(self.stats.get(c_int(S_EOP)).value, 1)

if __name__ == "__main__":
    main()
