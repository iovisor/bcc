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

from ctypes import c_ubyte, c_ushort, c_uint, c_ulonglong, Structure
from netaddr import IPAddress
from bpf import BPF
from pyroute2 import IPRoute
from socket import socket, AF_INET, SOCK_DGRAM
import sys
from time import sleep
from unittest import main, TestCase
import subprocess

arg1 = sys.argv.pop(1)

class TestBPFSocket(TestCase):
    def setup_vm_ns(self, ns, veth_in, veth_out):
        subprocess.call(["ip", "link", "add", veth_in, "type", "veth", "peer", "name", veth_out])
        subprocess.call(["ip", "netns", "add", ns])
        subprocess.call(["ip", "link", "set", veth_in, "netns", ns])
        subprocess.call(["ip", "netns", "exec", ns, "ip", "link", "set", veth_in, "name", "eth0"])
        subprocess.call(["ip", "link", "set", veth_out, "up"])

    def config_vm_ns(self, ns, ip_addr, net_mask, ip_gw):
        subprocess.call(["ip", "netns", "exec", ns, "ip", "addr", "add", ip_addr + "/24", "dev", "eth0"])
        subprocess.call(["ip", "netns", "exec", ns, "ip", "link", "set", "eth0", "up"])
        subprocess.call(["ip", "netns", "exec", ns, "route", "add", "-net", net_mask + "/24", "gw", ip_gw])

    def setup_router_ns(self, ns, veth1_in, veth1_out, veth2_in, veth2_out):
        subprocess.call(["ip", "netns", "add", ns])
        subprocess.call(["ip", "link", "add", veth1_in, "type", "veth", "peer", "name", veth1_out])
        subprocess.call(["ip", "link", "set", veth1_in, "netns", ns])
        subprocess.call(["ip", "netns", "exec", ns, "ip", "link", "set", veth1_in, "name", "eth0"])
        subprocess.call(["ip", "link", "add", veth2_in, "type", "veth", "peer", "name", veth2_out])
        subprocess.call(["ip", "link", "set", veth2_in, "netns", ns])
        subprocess.call(["ip", "netns", "exec", ns, "ip", "link", "set", veth2_in, "name", "eth1"])
        subprocess.call(["ip", "link", "set", veth1_out, "up"])
        subprocess.call(["ip", "link", "set", veth2_out, "up"])

    def config_router_ns(self, ns, ip_eth0, ip_eth1):
        subprocess.call(["ip", "netns", "exec", ns, "ip", "addr", "add", ip_eth0 + "/24", "dev", "eth0"])
        subprocess.call(["ip", "netns", "exec", ns, "ip", "link", "set", "eth0", "up"])
        subprocess.call(["ip", "netns", "exec", ns, "ip", "addr", "add", ip_eth1 + "/24", "dev", "eth1"])
        subprocess.call(["ip", "netns", "exec", ns, "ip", "link", "set", "eth1", "up"])

    def setup_br(self, br, veth_rt_2_br):
        # set up the bridge and add router interface as one of its slaves
        subprocess.call(["ip", "link", "add", "name", br, "type", "bridge"])
        subprocess.call(["ip", "link", "set", "dev", veth_rt_2_br, "master", br])
        subprocess.call(["ip", "link", "set", br, "up"])

    def br_add_pem_link(self, br, veth_pem_2_br, veth_br_2_pem):
        subprocess.call(["ip", "link", "add", veth_pem_2_br, "type", "veth", "peer", "name", veth_br_2_pem])
        subprocess.call(["ip", "link", "set", "dev", veth_pem_2_br, "master", br])
        subprocess.call(["ip", "link", "set", veth_pem_2_br, "up"])
        subprocess.call(["ip", "link", "set", veth_br_2_pem, "up"])

    def set_default_const(self):
        self.ns1            = "ns1"
        self.ns1_eth_in     = "v1"
        self.ns1_eth_out    = "v2"
        self.ns2            = "ns2"
        self.ns2_eth_in     = "v3"
        self.ns2_eth_out    = "v4"
        self.ns_router      = "ns_router"
        self.nsrtr_eth0_in  = "v10"
        self.nsrtr_eth0_out = "v11"
        self.nsrtr_eth1_in  = "v12"
        self.nsrtr_eth1_out = "v13"
        self.br1            = "br1"
        self.veth_pem_2_br1 = "v20"
        self.veth_br1_2_pem = "v21"
        self.br2            = "br2"
        self.veth_pem_2_br2 = "v22"
        self.veth_br2_2_pem = "v23"

        self.vm1_ip         = "100.1.1.1"
        self.vm2_ip         = "200.1.1.1"
        self.vm1_rtr_ip     = "100.1.1.254"
        self.vm2_rtr_ip     = "200.1.1.254"
        self.vm1_rtr_mask   = "100.1.1.0"
        self.vm2_rtr_mask   = "200.1.1.0"

    def attach_filter(self, ip, ifname, fd, name):
        ifindex = ip.link_lookup(ifname=ifname)[0]
        ip.tc("add", "ingress", ifindex, "ffff:")
        ip.tc("add-filter", "bpf", ifindex, ":1", fd=fd, name=name,
              parent="ffff:", action="drop", classid=1)

    def config_maps(self):
        b = BPF(src_file=arg1, debug=0)
        pem_fn = b.load_func("pem", BPF.SCHED_CLS)
        self.pem_dest= b.get_table("pem_dest")
        self.pem_stats = b.get_table("pem_stats")
        ip = IPRoute()

        # pem just relays packets between VM and its corresponding
        # slave link in the bridge interface
        ns1_ifindex = ip.link_lookup(ifname=self.ns1_eth_out)[0]
        ns2_ifindex = ip.link_lookup(ifname=self.ns2_eth_out)[0]
        br1_ifindex = ip.link_lookup(ifname=self.veth_br1_2_pem)[0]
        br2_ifindex = ip.link_lookup(ifname=self.veth_br2_2_pem)[0]
        self.pem_dest[c_uint(ns1_ifindex)] = c_uint(br1_ifindex)
        self.pem_dest[c_uint(br1_ifindex)] = c_uint(ns1_ifindex)
        self.pem_dest[c_uint(ns2_ifindex)] = c_uint(br2_ifindex)
        self.pem_dest[c_uint(br2_ifindex)] = c_uint(ns2_ifindex)

        # tc filter setup with bpf programs attached
        self.attach_filter(ip, self.ns1_eth_out, pem_fn.fd, pem_fn.name)
        self.attach_filter(ip, self.ns2_eth_out, pem_fn.fd, pem_fn.name)
        self.attach_filter(ip, self.veth_br1_2_pem, pem_fn.fd, pem_fn.name)
        self.attach_filter(ip, self.veth_br2_2_pem, pem_fn.fd, pem_fn.name)

    def setUp(self):

        # set up the environment
        self.set_default_const()
        self.setup_vm_ns(self.ns1, self.ns1_eth_in, self.ns1_eth_out)
        self.setup_vm_ns(self.ns2, self.ns2_eth_in, self.ns2_eth_out)
        self.config_vm_ns(self.ns1, self.vm1_ip, self.vm2_rtr_mask, self.vm1_rtr_ip)
        self.config_vm_ns(self.ns2, self.vm2_ip, self.vm1_rtr_mask, self.vm2_rtr_ip)
        self.setup_router_ns(self.ns_router, self.nsrtr_eth0_in, self.nsrtr_eth0_out,
                             self.nsrtr_eth1_in, self.nsrtr_eth1_out)
        self.config_router_ns(self.ns_router, self.vm1_rtr_ip, self.vm2_rtr_ip)

        # for each VM connecting to pem, there will be a corresponding veth
        # connecting to the bridge
        self.setup_br(self.br1, self.nsrtr_eth0_out)
        self.br_add_pem_link(self.br1, self.veth_pem_2_br1, self.veth_br1_2_pem)
        self.setup_br(self.br2, self.nsrtr_eth1_out)
        self.br_add_pem_link(self.br2, self.veth_pem_2_br2, self.veth_br2_2_pem)

        # load the program and configure maps
        self.config_maps()

    def test_brb2(self):
        # ping
        subprocess.call(["ip", "netns", "exec", self.ns1, "ping", self.vm2_ip, "-c", "2"])
        # minimum one arp request/reply, 5 icmp request/reply
        self.assertGreater(self.pem_stats[c_uint(0)].value, 11)

        # iperf, run server on the background
        subprocess.Popen(["ip", "netns", "exec", self.ns2, "iperf", "-s", "-xSCD"])
        sleep(1)
        subprocess.call(["ip", "netns", "exec", self.ns1, "iperf", "-c", self.vm2_ip, "-t", "1", "-xSC"])
        subprocess.call(["ip", "netns", "exec", self.ns2, "killall", "iperf"])

        # netperf, run server on the background
        subprocess.Popen(["ip", "netns", "exec", self.ns2, "netserver"])
        sleep(1)
        subprocess.call(["ip", "netns", "exec", self.ns1, "netperf", "-l", "1", "-H", self.vm2_ip, "--", "-m", "65160"])
        subprocess.call(["ip", "netns", "exec", self.ns1, "netperf", "-l", "1", "-H", self.vm2_ip, "-t", "TCP_RR"])
        subprocess.call(["ip", "netns", "exec", self.ns2, "killall", "netserver"])

        # cleanup, tear down the veths and namespaces
        subprocess.call(["ip", "link", "del", self.veth_br1_2_pem])
        subprocess.call(["ip", "link", "del", self.veth_br2_2_pem])
        subprocess.call(["ip", "link", "del", self.br1])
        subprocess.call(["ip", "link", "del", self.br2])
        subprocess.call(["ip", "netns", "del", self.ns1])
        subprocess.call(["ip", "netns", "del", self.ns2])
        subprocess.call(["ip", "netns", "del", self.ns_router])


if __name__ == "__main__":
    main()
