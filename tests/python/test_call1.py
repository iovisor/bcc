#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from ctypes import c_ushort, c_int, c_ulonglong
from netaddr import IPAddress
from bcc import BPF
from pyroute2 import IPRoute
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
        b = BPF(src_file=arg1, debug=0)
        ether_fn = b.load_func("parse_ether", BPF.SCHED_CLS)
        arp_fn = b.load_func("parse_arp", BPF.SCHED_CLS)
        ip_fn = b.load_func("parse_ip", BPF.SCHED_CLS)
        eop_fn = b.load_func("eop", BPF.SCHED_CLS)
        ip = IPRoute()
        ifindex = ip.link_lookup(ifname="eth0")[0]
        ip.tc("add", "sfq", ifindex, "1:")
        ip.tc("add-filter", "bpf", ifindex, ":1", fd=ether_fn.fd,
              name=ether_fn.name, parent="1:", action="ok", classid=1)
        self.jump = b.get_table("jump", c_int, c_int)
        self.jump[c_int(S_ARP)] = c_int(arp_fn.fd)
        self.jump[c_int(S_IP)] = c_int(ip_fn.fd)
        self.jump[c_int(S_EOP)] = c_int(eop_fn.fd)
        self.stats = b.get_table("stats", c_int, c_ulonglong)

    def test_jumps(self):
        udp = socket(AF_INET, SOCK_DGRAM)
        udp.sendto(b"a" * 10, ("172.16.1.1", 5000))
        udp.close()
        self.assertGreater(self.stats[c_int(S_IP)].value, 0)
        self.assertGreater(self.stats[c_int(S_ARP)].value, 0)
        self.assertGreater(self.stats[c_int(S_EOP)].value, 1)

if __name__ == "__main__":
    main()
