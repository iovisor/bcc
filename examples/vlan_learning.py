#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# This example shows a unique way to use a BPF program to demux any ethernet
# traffic into a pool of worker veth+namespaces (or any ifindex-based
# destination) depending on a configurable mapping of src-mac to ifindex. As
# part of the ingress processing, the program will dynamically learn the source
# ifindex of the matched source mac.

# Simulate a physical network with a vlan aware switch and clients that may
# connect to any vlan. The program will detect the known clients and pass the
# traffic through to a dedicated namespace for processing. Clients may have
# overlapping IP spaces and the traffic will still work.

#                |           bpf program                      |
# cli0 --|       | |----\                     /--|-- worker0  |
# cli1 --| trunk | |----->-handle_p2v(pkt)-> /---|-- worker1  |
# cli2 --|=======|=|----/                   /----|-- worker2  |
# ...  --|       | |---/ <-handle_v2p(pkt)-<-----|--  ...     |
# cliN --|       | |--/                     \----|-- workerM  |
#        |       |  ^                           ^             |
#      phys      |  vlan                      veth            |
#     switch     |  subinterface                              |

from bpf import BPF
from builtins import input
from pyroute2 import IPRoute, NetNS, IPDB, NSPopen
from random import shuffle
from time import sleep
from simulation import Simulation
import sys

ipr = IPRoute()
ipdb = IPDB(nl=ipr)

num_clients = 3
num_vlans = 16

# load the bpf program
b = BPF(src_file="vlan_learning.c", debug=0)
phys_fn = b.load_func("handle_phys2virt", BPF.SCHED_CLS)
virt_fn = b.load_func("handle_virt2phys", BPF.SCHED_CLS)

ingress = b.get_table("ingress")
egress = b.get_table("egress")

class VlanSimulation(Simulation):
    def __init__(self, ipdb):
        super(VlanSimulation, self).__init__(ipdb)

    def start(self):
        # start identical workers each in a namespace
        for i in range(0, num_clients):
            httpmod = ("SimpleHTTPServer" if sys.version_info[0] < 3
                       else "http.server")
            cmd = ["python", "-m", httpmod, "80"]
            self._create_ns("worker%d" % i, cmd=cmd, fn=virt_fn, action="drop",
                            ipaddr="172.16.1.5/24")

        # simulate a physical eth vlan trunk
        with self.ipdb.create(ifname="eth0a", kind="veth", peer="eth0b") as v:
            v.up()
        self.ipdb.interfaces.eth0b.up().commit()

        # connect the trunk to the bridge
        with self.ipdb.create(ifname="br100", kind="bridge") as br100:
            br100.add_port(self.ipdb.interfaces.eth0b)
            br100.up()

        # for each vlan, create a subinterface on the eth...most of these will be
        # unused, but still listening and waiting for a client to send traffic on
        for i in range(2, 2 + num_vlans):
            with self.ipdb.create(ifname="eth0a.%d" % i, kind="vlan",
                                  link=ipdb.interfaces.eth0a, vlan_id=i) as v:
                v.up()
            v = self.ipdb.interfaces["eth0a.%d" % i]
            # add the bpf program for demuxing phys2virt packets
            ipr.tc("add", "ingress", v["index"], "ffff:")
            ipr.tc("add-filter", "bpf", v["index"], ":1", fd=phys_fn.fd,
                   name=phys_fn.name, parent="ffff:", action="drop", classid=1)

        # allocate vlans randomly
        available_vlans = [i for i in range(2, 2 + num_vlans)]
        shuffle(available_vlans)
        available_ips = [[i for i in range(100, 105)] for i in range(0, num_clients)]

        # these are simulations of physical clients
        for i in range(0, num_clients):
            macaddr = ("02:00:00:%.2x:%.2x:%.2x" %
                       ((i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff))

            # assign this client to the given worker
            idx = self.ipdb.interfaces["worker%da" % i]["index"]
            mac = int(macaddr.replace(":", ""), 16)
            ingress[ingress.Key(mac)] = ingress.Leaf(idx, 0, 0)

            # test traffic with curl loop
            cmd = ["bash", "-c",
                   "for i in {1..8}; do curl 172.16.1.5 -o /dev/null; sleep 1; done"]
            br_ifc = self.ipdb.create(ifname="br100.%d" % i, kind="vlan",
                                      link=br100,
                                      vlan_id=available_vlans.pop(0)).commit()
            (out_ifc, in_ifc) = self._create_ns("client%d" % i, in_ifc=br_ifc,
                                                ipaddr="172.16.1.100/24",
                                                macaddr=macaddr, cmd=cmd)[1:3]

try:
    sim = VlanSimulation(ipdb)
    sim.start()
    sleep(10)
    input("Press enter to exit: ")

    stats_collect = {}
    for key, leaf in ingress.items():
        stats_collect[key.value] = [leaf.tx_pkts, leaf.tx_bytes, 0, 0]
    for key, leaf in egress.items():
        x = stats_collect.get(key.value, [0, 0, 0, 0])
        x[2] = leaf.tx_pkts
        x[3] = leaf.tx_bytes
    for k, v in stats_collect.items():
        print("mac %.12x rx pkts = %u, rx bytes = %u" % (k, v[0], v[1]))
        print("                 tx pkts = %u, tx bytes = %u" % (v[2], v[3]))
finally:
    if "eth0a" in ipdb.interfaces: ipdb.interfaces.eth0a.remove().commit()
    if "br100" in ipdb.interfaces: ipdb.interfaces.br100.remove().commit()
    if "sim" in locals(): sim.release()
    ipdb.release()
