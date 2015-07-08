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

from ctypes import c_ubyte, c_ushort, c_uint, c_ulonglong, Structure
from netaddr import IPAddress, EUI
from bpf import BPF
from pyroute2 import IPRoute
from socket import socket, AF_INET, SOCK_DGRAM
import sys
from time import sleep
from unittest import main, TestCase
import subprocess
import struct

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
        subprocess.call(["ip", "netns", "exec", ns, "ip", "route", "add", net_mask + "/24", "via", ip_gw])

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

        self.vm1_ip         = "100.1.1.1"
        self.vm2_ip         = "200.1.1.1"
        self.vm1_rtr_ip     = "100.1.1.254"
        self.vm2_rtr_ip     = "200.1.1.254"
        self.vm1_rtr_mask   = "100.1.1.0"
        self.vm2_rtr_mask   = "200.1.1.0"

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
                      ip, br_dest_map, br_mac_map,
                      ns_eth_out, vm_mac, vm_ip):
        self.pem_dest[c_uint(curr_pem_pid)] = self.pem_dest.Leaf(prog_id_br, curr_br_pid)
        br_dest_map[c_uint(curr_br_pid)] = br_dest_map.Leaf(prog_id_pem, curr_pem_pid)
        ifindex = ip.link_lookup(ifname=ns_eth_out)[0]
        self.pem_port[c_uint(curr_pem_pid)] = c_uint(ifindex)
        self.pem_ifindex[c_uint(ifindex)] = c_uint(curr_pem_pid)
        mac_addr = br_mac_map.Key(int(EUI(vm_mac.decode())))
        br_mac_map[mac_addr] = c_uint(curr_br_pid)

    def attach_filter(self, ip, ifname, fd, name):
        ifindex = ip.link_lookup(ifname=ifname)[0]
        ip.tc("add", "ingress", ifindex, "ffff:")
        ip.tc("add-filter", "bpf", ifindex, ":1", fd=fd, name=name,
              parent="ffff:", action="drop", classid=1)

    def config_maps(self):
        b = BPF(src_file=arg1, debug=0)
        pem_fn = b.load_func("pem", BPF.SCHED_CLS)
        br1_fn = b.load_func("br1", BPF.SCHED_CLS)
        br2_fn = b.load_func("br2", BPF.SCHED_CLS)
        ip = IPRoute()

        # program id
        prog_id_pem = 1
        prog_id_br1 = 2
        prog_id_br2 = 3

        # initial port id and table pointers
        curr_pem_pid = 0
        curr_br1_pid = 0
        curr_br2_pid = 0
        self.get_table(b)

        # configure jump table
        self.jump[c_uint(prog_id_pem)] = c_uint(pem_fn.fd)
        self.jump[c_uint(prog_id_br1)] = c_uint(br1_fn.fd)
        self.jump[c_uint(prog_id_br2)] = c_uint(br2_fn.fd)

        # connect pem and br1
        curr_pem_pid = curr_pem_pid + 1
        curr_br1_pid = curr_br1_pid + 1
        self.connect_ports(prog_id_pem, prog_id_br1, curr_pem_pid, curr_br1_pid,
                      ip, self.br1_dest, self.br1_mac,
                      self.ns1_eth_out, self.vm1_mac, self.vm1_ip)

        # connect pem and br2
        curr_pem_pid = curr_pem_pid + 1
        curr_br2_pid = curr_br2_pid + 1
        self.connect_ports(prog_id_pem, prog_id_br2, curr_pem_pid, curr_br2_pid,
                      ip, self.br2_dest, self.br2_mac,
                      self.ns2_eth_out, self.vm2_mac, self.vm2_ip)

        # connect <br1, rtr> and <br2, rtr>
        ifindex = ip.link_lookup(ifname=self.nsrtr_eth0_out)[0]
        self.br1_rtr[c_uint(0)] = c_uint(ifindex)
        ifindex = ip.link_lookup(ifname=self.nsrtr_eth1_out)[0]
        self.br2_rtr[c_uint(0)] = c_uint(ifindex)

        # tc filter setup with bpf programs attached
        self.attach_filter(ip, self.ns1_eth_out, pem_fn.fd, pem_fn.name)
        self.attach_filter(ip, self.ns2_eth_out, pem_fn.fd, pem_fn.name)
        self.attach_filter(ip, self.nsrtr_eth0_out, br1_fn.fd, br1_fn.name)
        self.attach_filter(ip, self.nsrtr_eth1_out, br2_fn.fd, br2_fn.name)

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

        # get vm mac address
        self.vm1_mac = subprocess.check_output(["ip", "netns", "exec", self.ns1, "cat", "/sys/class/net/eth0/address"])
        self.vm1_mac = self.vm1_mac.strip()
        self.vm2_mac = subprocess.check_output(["ip", "netns", "exec", self.ns2, "cat", "/sys/class/net/eth0/address"])
        self.vm2_mac = self.vm2_mac.strip()

        # load the program and configure maps
        self.config_maps()

    def test_brb(self):
        try:
            # our bridge is not smart enough, so send arping for router learning to prevent router
            # from sending out arp request
            subprocess.call(["ip", "netns", "exec", self.ns1, "arping", "-w", "1", "-c", "1", "-I", "eth0",
                             self.vm1_rtr_ip])
            subprocess.call(["ip", "netns", "exec", self.ns2, "arping", "-w", "1", "-c", "1", "-I", "eth0",
                             self.vm2_rtr_ip])
            # ping
            subprocess.call(["ip", "netns", "exec", self.ns1, "ping", self.vm2_ip, "-c", "2"])
            # minimum one arp reply, 2 icmp reply
            self.assertGreater(self.pem_stats[c_uint(0)].value, 2)

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

        finally:
            # cleanup, tear down the veths and namespaces
            subprocess.call(["ip", "netns", "del", self.ns1])
            subprocess.call(["ip", "netns", "del", self.ns2])
            subprocess.call(["ip", "netns", "del", self.ns_router])


if __name__ == "__main__":
    main()
