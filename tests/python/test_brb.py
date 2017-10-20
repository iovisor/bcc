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
# The bridge is implemented with limited functionality in bpf program.
#
# vm1 and vm2 are in different subnet. For vm1 to communicate to vm2,
# the packet will have to travel from vm1 to pem, bridge1, router, bridge2, pem, and
# then come to vm2.
#
# When this test is run with verbose mode (ctest -R <test_name> -V),
# the following printout is observed on my local box:
#
# ......
# 8: ARPING 100.1.1.254 from 100.1.1.1 eth0
# 8: Unicast reply from 100.1.1.254 [76:62:B5:5C:8C:6F]  0.533ms
# 8: Sent 1 probes (1 broadcast(s))
# 8: Received 1 response(s)
# 8: ARPING 200.1.1.254 from 200.1.1.1 eth0
# 8: Unicast reply from 200.1.1.254 [F2:F0:B4:ED:7B:1B]  0.524ms
# 8: Sent 1 probes (1 broadcast(s))
# 8: Received 1 response(s)
# 8: PING 200.1.1.1 (200.1.1.1) 56(84) bytes of data.
# 8: 64 bytes from 200.1.1.1: icmp_req=1 ttl=63 time=0.074 ms
# 8: 64 bytes from 200.1.1.1: icmp_req=2 ttl=63 time=0.061 ms
# 8:
# 8: --- 200.1.1.1 ping statistics ---
# 8: 2 packets transmitted, 2 received, 0% packet loss, time 999ms
# 8: rtt min/avg/max/mdev = 0.061/0.067/0.074/0.010 ms
# 8: [ ID] Interval       Transfer     Bandwidth
# 8: [  5]  0.0- 1.0 sec  4.00 GBytes  34.3 Gbits/sec
# 8: Starting netserver with host 'IN(6)ADDR_ANY' port '12865' and family AF_UNSPEC
# 8: MIGRATED TCP STREAM TEST from 0.0.0.0 (0.0.0.0) port 0 AF_INET to 200.1.1.1 (200.1.1.1) port 0 AF_INET : demo
# 8: Recv   Send    Send
# 8: Socket Socket  Message  Elapsed
# 8: Size   Size    Size     Time     Throughput
# 8: bytes  bytes   bytes    secs.    10^6bits/sec
# 8:
# 8:  87380  16384  65160    1.00     41991.68
# 8: MIGRATED TCP REQUEST/RESPONSE TEST from 0.0.0.0 (0.0.0.0) port 0 AF_INET to 200.1.1.1 (200.1.1.1) port 0 AF_INET : demo : first burst 0
# 8: Local /Remote
# 8: Socket Size   Request  Resp.   Elapsed  Trans.
# 8: Send   Recv   Size     Size    Time     Rate
# 8: bytes  Bytes  bytes    bytes   secs.    per sec
# 8:
# 8: 16384  87380  1        1       1.00     48645.53
# 8: 16384  87380
# 8: .
# 8: ----------------------------------------------------------------------
# 8: Ran 1 test in 11.296s
# 8:
# 8: OK

from ctypes import c_uint
from netaddr import IPAddress, EUI
from bcc import BPF
from pyroute2 import IPRoute, NetNS, IPDB, NSPopen
from utils import NSPopenWithCheck
import sys
from time import sleep
from unittest import main, TestCase
from simulation import Simulation

arg1 = sys.argv.pop(1)
ipr = IPRoute()
ipdb = IPDB(nl=ipr)
sim = Simulation(ipdb)

class TestBPFSocket(TestCase):
    def set_default_const(self):
        self.ns1            = "ns1"
        self.ns2            = "ns2"
        self.ns_router      = "ns_router"
        self.vm1_ip         = "100.1.1.1"
        self.vm2_ip         = "200.1.1.1"
        self.vm1_rtr_ip     = "100.1.1.254"
        self.vm2_rtr_ip     = "200.1.1.254"
        self.vm1_rtr_mask   = "100.1.1.0/24"
        self.vm2_rtr_mask   = "200.1.1.0/24"

    def get_table(self, b):
        self.jump = b.get_table("jump")

        self.pem_dest = b.get_table("pem_dest")
        self.pem_port = b.get_table("pem_port")
        self.pem_ifindex = b.get_table("pem_ifindex")
        self.pem_stats = b.get_table("pem_stats")

        self.br1_dest = b.get_table("br1_dest")
        self.br1_mac = b.get_table("br1_mac")
        self.br1_rtr = b.get_table("br1_rtr")

        self.br2_dest = b.get_table("br2_dest")
        self.br2_mac = b.get_table("br2_mac")
        self.br2_rtr = b.get_table("br2_rtr")

    def connect_ports(self, prog_id_pem, prog_id_br, curr_pem_pid, curr_br_pid,
                      br_dest_map, br_mac_map, ifindex, vm_mac, vm_ip):
        self.pem_dest[c_uint(curr_pem_pid)] = self.pem_dest.Leaf(prog_id_br, curr_br_pid)
        br_dest_map[c_uint(curr_br_pid)] = br_dest_map.Leaf(prog_id_pem, curr_pem_pid)
        self.pem_port[c_uint(curr_pem_pid)] = c_uint(ifindex)
        self.pem_ifindex[c_uint(ifindex)] = c_uint(curr_pem_pid)
        mac_addr = br_mac_map.Key(int(EUI(vm_mac)))
        br_mac_map[mac_addr] = c_uint(curr_br_pid)

    def config_maps(self):
        # program id
        prog_id_pem = 1
        prog_id_br1 = 2
        prog_id_br2 = 3

        # initial port id and table pointers
        curr_pem_pid = 0
        curr_br1_pid = 0
        curr_br2_pid = 0

        # configure jump table
        self.jump[c_uint(prog_id_pem)] = c_uint(self.pem_fn.fd)
        self.jump[c_uint(prog_id_br1)] = c_uint(self.br1_fn.fd)
        self.jump[c_uint(prog_id_br2)] = c_uint(self.br2_fn.fd)

        # connect pem and br1
        curr_pem_pid = curr_pem_pid + 1
        curr_br1_pid = curr_br1_pid + 1
        self.connect_ports(prog_id_pem, prog_id_br1, curr_pem_pid, curr_br1_pid,
                      self.br1_dest, self.br1_mac,
                      self.ns1_eth_out.index, self.vm1_mac, self.vm1_ip)

        # connect pem and br2
        curr_pem_pid = curr_pem_pid + 1
        curr_br2_pid = curr_br2_pid + 1
        self.connect_ports(prog_id_pem, prog_id_br2, curr_pem_pid, curr_br2_pid,
                      self.br2_dest, self.br2_mac,
                      self.ns2_eth_out.index, self.vm2_mac, self.vm2_ip)

        # connect <br1, rtr> and <br2, rtr>
        self.br1_rtr[c_uint(0)] = c_uint(self.nsrtr_eth0_out.index)
        self.br2_rtr[c_uint(0)] = c_uint(self.nsrtr_eth1_out.index)

    def test_brb(self):
        try:
            b = BPF(src_file=arg1, debug=0)
            self.pem_fn = b.load_func("pem", BPF.SCHED_CLS)
            self.br1_fn = b.load_func("br1", BPF.SCHED_CLS)
            self.br2_fn = b.load_func("br2", BPF.SCHED_CLS)
            self.get_table(b)

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
            self.vm1_mac = ns1_ipdb.interfaces['eth0'].address
            self.vm2_mac = ns2_ipdb.interfaces['eth0'].address

            (_, self.nsrtr_eth0_out, _) = sim._create_ns(self.ns_router, ipaddr=self.vm1_rtr_ip+'/24',
                                                         fn=self.br1_fn, action='drop',
                                                         disable_ipv6=True)
            (rt_ipdb, self.nsrtr_eth1_out, _) = sim._ns_add_ifc(self.ns_router, "eth1", "ns_router2",
                                                                ipaddr=self.vm2_rtr_ip+'/24',
                                                                fn=self.br2_fn, action='drop',
                                                                disable_ipv6=True)
            nsp = NSPopen(rt_ipdb.nl.netns, ["sysctl", "-w", "net.ipv4.ip_forward=1"])
            nsp.wait(); nsp.release()

            # configure maps
            self.config_maps()

            # our bridge is not smart enough, so send arping for router learning to prevent router
            # from sending out arp request
            nsp = NSPopen(ns1_ipdb.nl.netns,
                          ["arping", "-w", "1", "-c", "1", "-I", "eth0", self.vm1_rtr_ip])
            nsp.wait(); nsp.release()
            nsp = NSPopen(ns2_ipdb.nl.netns,
                          ["arping", "-w", "1", "-c", "1", "-I", "eth0", self.vm2_rtr_ip])
            nsp.wait(); nsp.release()

            # ping
            nsp = NSPopen(ns1_ipdb.nl.netns, ["ping", self.vm2_ip, "-c", "2"])
            nsp.wait(); nsp.release()
            # pem_stats only counts pem->bridge traffic, each VM has 4: arping/arp request/2 icmp request
            # total 8 packets should be counted
            self.assertEqual(self.pem_stats[c_uint(0)].value, 8)

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
            sim.release()
            ipdb.release()


if __name__ == "__main__":
    main()
