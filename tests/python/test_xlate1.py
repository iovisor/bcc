#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from netaddr import IPAddress
from bcc import BPF
from pyroute2 import IPRoute, protocols
from socket import socket, AF_INET, SOCK_DGRAM
from subprocess import call
import sys
from time import sleep
from unittest import main, TestCase

arg1 = sys.argv.pop(1)
arg2 = ""
if len(sys.argv) > 1:
  arg2 = sys.argv.pop(1)

class TestBPFFilter(TestCase):
    def setUp(self):
        b = BPF(arg1, arg2, debug=0)
        fn = b.load_func("on_packet", BPF.SCHED_ACT)
        ip = IPRoute()
        ifindex = ip.link_lookup(ifname="eth0")[0]
        # set up a network to change the flow:
        #             outside      |       inside
        # 172.16.1.1 - 172.16.1.2  |  192.168.1.1 - 192.16.1.2
        ip.addr("del", index=ifindex, address="172.16.1.2", mask=24)
        ip.addr("add", index=ifindex, address="192.168.1.2", mask=24)
        # add an ingress and egress qdisc
        ip.tc("add", "ingress", ifindex, "ffff:")
        ip.tc("add", "sfq", ifindex, "1:")
        # add same program to both ingress/egress, so pkt is translated in both directions
        action = {"kind": "bpf", "fd": fn.fd, "name": fn.name, "action": "ok"}
        ip.tc("add-filter", "u32", ifindex, ":1", parent="ffff:", action=[action],
                protocol=protocols.ETH_P_ALL, classid=1, target=0x10002, keys=['0x0/0x0+0'])
        ip.tc("add-filter", "u32", ifindex, ":2", parent="1:", action=[action],
                protocol=protocols.ETH_P_ALL, classid=1, target=0x10002, keys=['0x0/0x0+0'])
        self.xlate = b.get_table("xlate")

    def test_xlate(self):
        key1 = self.xlate.Key(IPAddress("172.16.1.2").value, IPAddress("172.16.1.1").value)
        leaf1 = self.xlate.Leaf(IPAddress("192.168.1.2").value, IPAddress("192.168.1.1").value, 0, 0)
        self.xlate[key1] = leaf1
        key2 = self.xlate.Key(IPAddress("192.168.1.1").value, IPAddress("192.168.1.2").value)
        leaf2 = self.xlate.Leaf(IPAddress("172.16.1.1").value, IPAddress("172.16.1.2").value, 0, 0)
        self.xlate[key2] = leaf2
        call(["ping", "-c1", "192.168.1.1"])
        leaf = self.xlate[key1]
        self.assertGreater(leaf.ip_xlated_pkts, 0)
        self.assertGreater(leaf.arp_xlated_pkts, 0)
        leaf = self.xlate[key2]
        self.assertGreater(leaf.ip_xlated_pkts, 0)
        self.assertGreater(leaf.arp_xlated_pkts, 0)

if __name__ == "__main__":
    main()
