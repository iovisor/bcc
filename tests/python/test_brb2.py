#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# This program implements a topology likes below:
#   pem: physical endpoint manager, implemented as a bpf program
#
#     vm1 <--------+  +----> bridge1 <----+
#                  V  V                   V
#                  pem                  router
#                  ^  ^                   ^
#     vm2 <--------+  +----> bridge2 <----+
#
# The vm1, vm2 and router are implemented as namespaces.
# The linux bridge device is used to provice bridge functionality.
# pem bpf will be attached to related network devices for vm1, vm1, bridge1 and bridge2.
#
# vm1 and vm2 are in different subnet. For vm1 to communicate to vm2,
# the packet will have to travel from vm1 to pem, bridge1, router, bridge2, pem, and
# then come to vm2.
#
# When this test is run with verbose mode (ctest -R <test_name> -V),
# the following printout is observed on my local box:
#
# ......
# 9: PING 200.1.1.1 (200.1.1.1) 56(84) bytes of data.
# 9: 64 bytes from 200.1.1.1: icmp_req=1 ttl=63 time=0.090 ms
# 9: 64 bytes from 200.1.1.1: icmp_req=2 ttl=63 time=0.032 ms
# 9:
# 9: --- 200.1.1.1 ping statistics ---
# 9: 2 packets transmitted, 2 received, 0% packet loss, time 999ms
# 9: rtt min/avg/max/mdev = 0.032/0.061/0.090/0.029 ms
# 9: [ ID] Interval       Transfer     Bandwidth
# 9: [  5]  0.0- 1.0 sec  3.80 GBytes  32.6 Gbits/sec
# 9: Starting netserver with host 'IN(6)ADDR_ANY' port '12865' and family AF_UNSPEC
# 9: MIGRATED TCP STREAM TEST from 0.0.0.0 (0.0.0.0) port 0 AF_INET to 200.1.1.1 (200.1.1.1) port 0 AF_INET : demo
# 9: Recv   Send    Send
# 9: Socket Socket  Message  Elapsed
# 9: Size   Size    Size     Time     Throughput
# 9: bytes  bytes   bytes    secs.    10^6bits/sec
# 9:
# 9:  87380  16384  65160    1.00     39940.46
# 9: MIGRATED TCP REQUEST/RESPONSE TEST from 0.0.0.0 (0.0.0.0) port 0 AF_INET to 200.1.1.1 (200.1.1.1) port 0 AF_INET : demo : first burst 0
# 9: Local /Remote
# 9: Socket Size   Request  Resp.   Elapsed  Trans.
# 9: Send   Recv   Size     Size    Time     Rate
# 9: bytes  Bytes  bytes    bytes   secs.    per sec
# 9:
# 9: 16384  87380  1        1       1.00     46387.80
# 9: 16384  87380
# 9: .
# 9: ----------------------------------------------------------------------
# 9: Ran 1 test in 7.495s
# 9:
# 9: OK

from ctypes import c_uint
from bcc import BPF
from pyroute2 import IPRoute, NetNS, IPDB, NSPopen
from utils import NSPopenWithCheck
import sys
from time import sleep
from unittest import main, TestCase
import subprocess
from simulation import Simulation

arg1 = sys.argv.pop(1)
ipr = IPRoute()
ipdb = IPDB(nl=ipr)
sim = Simulation(ipdb)

allocated_interfaces = set(ipdb.interfaces.keys())

def get_next_iface(prefix):
    i = 0
    while True:
        iface = "{0}{1}".format(prefix, i)
        if iface not in allocated_interfaces:
            allocated_interfaces.add(iface)
            return iface
        i += 1

class TestBPFSocket(TestCase):
    def setup_br(self, br, veth_rt_2_br, veth_pem_2_br, veth_br_2_pem):
        # create veth which connecting pem and br
        with ipdb.create(ifname=veth_pem_2_br, kind="veth", peer=veth_br_2_pem) as v:
            v.up()
        ipdb.interfaces[veth_br_2_pem].up().commit()
        subprocess.call(["sysctl", "-q", "-w", "net.ipv6.conf." + veth_pem_2_br + ".disable_ipv6=1"])
        subprocess.call(["sysctl", "-q", "-w", "net.ipv6.conf." + veth_br_2_pem + ".disable_ipv6=1"])

        # set up the bridge and add router interface as one of its slaves
        with ipdb.create(ifname=br, kind="bridge") as br1:
            br1.add_port(ipdb.interfaces[veth_pem_2_br])
            br1.add_port(ipdb.interfaces[veth_rt_2_br])
            br1.up()
        subprocess.call(["sysctl", "-q", "-w", "net.ipv6.conf." + br + ".disable_ipv6=1"])

    def set_default_const(self):
        self.ns1            = "ns1"
        self.ns2            = "ns2"
        self.ns_router      = "ns_router"
        self.br1            = get_next_iface("br")
        self.veth_pem_2_br1 = "v20"
        self.veth_br1_2_pem = "v21"
        self.br2            = get_next_iface("br")
        self.veth_pem_2_br2 = "v22"
        self.veth_br2_2_pem = "v23"

        self.vm1_ip         = "100.1.1.1"
        self.vm2_ip         = "200.1.1.1"
        self.vm1_rtr_ip     = "100.1.1.254"
        self.vm2_rtr_ip     = "200.1.1.254"
        self.vm1_rtr_mask   = "100.1.1.0/24"
        self.vm2_rtr_mask   = "200.1.1.0/24"

    def attach_filter(self, ifname, fd, name):
        ifindex = ipdb.interfaces[ifname].index
        ipr.tc("add", "ingress", ifindex, "ffff:")
        ipr.tc("add-filter", "bpf", ifindex, ":1", fd=fd, name=name,
              parent="ffff:", action="drop", classid=1)

    def config_maps(self):
        # pem just relays packets between VM and its corresponding
        # slave link in the bridge interface
        ns1_ifindex = self.ns1_eth_out.index
        ns2_ifindex = self.ns2_eth_out.index
        br1_ifindex = ipdb.interfaces[self.veth_br1_2_pem].index
        br2_ifindex = ipdb.interfaces[self.veth_br2_2_pem].index
        self.pem_dest[c_uint(ns1_ifindex)] = c_uint(br1_ifindex)
        self.pem_dest[c_uint(br1_ifindex)] = c_uint(ns1_ifindex)
        self.pem_dest[c_uint(ns2_ifindex)] = c_uint(br2_ifindex)
        self.pem_dest[c_uint(br2_ifindex)] = c_uint(ns2_ifindex)

        # tc filter setup with bpf programs attached
        self.attach_filter(self.veth_br1_2_pem, self.pem_fn.fd, self.pem_fn.name)
        self.attach_filter(self.veth_br2_2_pem, self.pem_fn.fd, self.pem_fn.name)

    def test_brb2(self):
        try:
            b = BPF(src_file=arg1, debug=0)
            self.pem_fn = b.load_func("pem", BPF.SCHED_CLS)
            self.pem_dest= b.get_table("pem_dest")
            self.pem_stats = b.get_table("pem_stats")

            # set up the topology
            self.set_default_const()
            (ns1_ipdb, self.ns1_eth_out, _) = sim._create_ns(self.ns1, ipaddr=self.vm1_ip+'/24',
                                                             fn=self.pem_fn, action='drop',
                                                             disable_ipv6=True)
            (ns2_ipdb, self.ns2_eth_out, _) = sim._create_ns(self.ns2, ipaddr=self.vm2_ip+'/24',
                                                             fn=self.pem_fn, action='drop',
                                                             disable_ipv6=True)
            ns1_ipdb.routes.add({'dst': self.vm2_rtr_mask, 'gateway': self.vm1_rtr_ip}).commit()
            ns2_ipdb.routes.add({'dst': self.vm1_rtr_mask, 'gateway': self.vm2_rtr_ip}).commit()

            (_, self.nsrtr_eth0_out, _) = sim._create_ns(self.ns_router, ipaddr=self.vm1_rtr_ip+'/24',
                                                         disable_ipv6=True)
            (rt_ipdb, self.nsrtr_eth1_out, _) = sim._ns_add_ifc(self.ns_router, "eth1", "ns_router2",
                                                                ipaddr=self.vm2_rtr_ip+'/24',
                                                                disable_ipv6=True)
            # enable ip forwarding in router ns
            nsp = NSPopen(rt_ipdb.nl.netns, ["sysctl", "-w", "net.ipv4.ip_forward=1"])
            nsp.wait(); nsp.release()

            # for each VM connecting to pem, there will be a corresponding veth connecting to the bridge
            self.setup_br(self.br1, self.nsrtr_eth0_out.ifname, self.veth_pem_2_br1, self.veth_br1_2_pem)
            self.setup_br(self.br2, self.nsrtr_eth1_out.ifname, self.veth_pem_2_br2, self.veth_br2_2_pem)

            # load the program and configure maps
            self.config_maps()

            # ping
            nsp = NSPopen(ns1_ipdb.nl.netns, ["ping", self.vm2_ip, "-c", "2"]); nsp.wait(); nsp.release()
            # one arp request/reply, 2 icmp request/reply per VM, total 6 packets per VM, 12 packets total
            self.assertEqual(self.pem_stats[c_uint(0)].value, 12)

            nsp_server = NSPopenWithCheck(ns2_ipdb.nl.netns, ["iperf", "-s", "-xSC"])
            sleep(1)
            nsp = NSPopen(ns1_ipdb.nl.netns, ["iperf", "-c", self.vm2_ip, "-t", "1", "-xSC"])
            nsp.wait(); nsp.release()
            nsp_server.kill(); nsp_server.wait(); nsp_server.release()

            nsp_server = NSPopenWithCheck(ns2_ipdb.nl.netns, ["netserver", "-D"])
            sleep(1)
            nsp = NSPopenWithCheck(ns1_ipdb.nl.netns, ["netperf", "-l", "1", "-H", self.vm2_ip, "--", "-m", "65160"])
            nsp.wait(); nsp.release()
            nsp = NSPopen(ns1_ipdb.nl.netns, ["netperf", "-l", "1", "-H", self.vm2_ip, "-t", "TCP_RR"])
            nsp.wait(); nsp.release()
            nsp_server.kill(); nsp_server.wait(); nsp_server.release()

        finally:
            if self.br1 in ipdb.interfaces: ipdb.interfaces[self.br1].remove().commit()
            if self.br2 in ipdb.interfaces: ipdb.interfaces[self.br2].remove().commit()
            if self.veth_pem_2_br1 in ipdb.interfaces: ipdb.interfaces[self.veth_pem_2_br1].remove().commit()
            if self.veth_pem_2_br2 in ipdb.interfaces: ipdb.interfaces[self.veth_pem_2_br2].remove().commit()
            sim.release()
            ipdb.release()


if __name__ == "__main__":
    main()
