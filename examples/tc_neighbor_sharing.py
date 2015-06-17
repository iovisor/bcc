#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# This example shows how a combination of BPF programs can be used to perform
# per-IP classification and rate limiting. The simulation in this example
# shows an example where N+M devices are combined and use 1 WAN. Traffic sent
# from/to the "neighbor" devices have their combined bandwidth capped at
# 128kbit, and the rest of the traffic can use an additional 1Mbit.

# This works by sharing a map between various tc ingress filters, each with
# a related set of bpf functions attached. The map stores a list of dynamically
# learned ip addresses that were seen on the neighbor devices and should be
# throttled.

#                          /------------\                        |
# neigh1 --|->->->->->->->-|            |                        |
# neigh2 --|->->->->->->->-|    <-128kb-|        /------\        |
# neigh3 --|->->->->->->->-|            |  wan0  | wan  |        |
#          | ^             |   br100    |-<-<-<--| sim  |        |
#          | clsfy_neigh() |            |   ^    \------/        |
# lan1 ----|->->->->->->->-|    <--1Mb--|   |                    |
# lan2 ----|->->->->->->->-|            |   classify_wan()       |
#            ^             \------------/                        |
#            pass()                                              |


from bpf import BPF
from pyroute2 import IPRoute, NetNS, IPDB, NSPopen
import sys
from time import sleep

ipr = IPRoute()
ipdb = IPDB(nl=ipr)
b = BPF(src_file="tc_neighbor_sharing.c", debug=0)

wan_fn = b.load_func("classify_wan", BPF.SCHED_CLS)
pass_fn = b.load_func("pass", BPF.SCHED_CLS)
neighbor_fn = b.load_func("classify_neighbor", BPF.SCHED_CLS)

num_neighbors = 3
num_locals = 2

# class to build the simulation network
class SharedNetSimulation(object):

    def __init__(self):
        self.ipdbs = []
        self.namespaces = []
        self.processes = []

        # Create the wan namespace, and attach an ingress filter for throttling
        # inbound (download) traffic
        (self.wan, wan_if) = self._create_ns("wan0", "172.16.1.5/24", None)
        ipr.tc("add", "ingress", wan_if["index"], "ffff:")
        ipr.tc("add-filter", "bpf", wan_if["index"], ":1", fd=wan_fn.fd,
               prio=1, name=wan_fn.name, parent="ffff:", action="drop",
               classid=1, rate="128kbit", burst=1024 * 32, mtu=16 * 1024)
        ipr.tc("add-filter", "bpf", wan_if["index"], ":2", fd=pass_fn.fd,
               prio=2, name=pass_fn.name, parent="ffff:", action="drop",
               classid=2, rate="1024kbit", burst=1024 * 32, mtu=16 * 1024)
        self.wan_if = wan_if

    # helper function to create a namespace and a veth connecting it
    def _create_ns(self, name, ipaddr, fn):
        ns_ipdb = IPDB(nl=NetNS(name))
        ipdb.create(ifname="%sa" % name, kind="veth", peer="%sb" % name).commit()
        with ipdb.interfaces["%sb" % name] as v:
            # move half of veth into namespace
            v.net_ns_fd = ns_ipdb.nl.netns
        with ipdb.interfaces["%sa" % name] as v:
            v.up()
        with ns_ipdb.interfaces["%sb" % name] as v:
            v.ifname = "eth0"
            v.add_ip("%s" % ipaddr)
            v.up()
        ifc = ipdb.interfaces["%sa" % name]
        if fn:
            ipr.tc("add", "ingress", ifc["index"], "ffff:")
            ipr.tc("add-filter", "bpf", ifc["index"], ":1", fd=fn.fd, name=fn.name,
                   parent="ffff:", action="ok", classid=1)
        self.ipdbs.append(ns_ipdb)
        self.namespaces.append(ns_ipdb.nl)
        cmd = ["netserver", "-D"]
        self.processes.append(NSPopen(ns_ipdb.nl.netns, cmd))
        return (ns_ipdb, ifc)

    # start the namespaces that compose the network, interconnect them with the bridge,
    # and attach the tc filters
    def start(self):
        neighbor_list = []
        local_list = []
        for i in range(0, num_neighbors):
            neighbor_list.append(self._create_ns("neighbor%d" % i, "172.16.1.%d/24" % (i + 100), neighbor_fn))
        for i in range(0, num_locals):
            local_list.append(self._create_ns("local%d" % i, "172.16.1.%d/24" % (i + 150), pass_fn))

        with ipdb.create(ifname="br100", kind="bridge") as br100:
            for x in neighbor_list:
                br100.add_port(x[1])
            for x in local_list:
                br100.add_port(x[1])
            br100.add_port(self.wan_if)
            br100.up()

    def release(self):
        for p in self.processes: p.kill(); p.release()
        for db in self.ipdbs: db.release()
        for ns in self.namespaces: ns.remove()

try:
    sim = SharedNetSimulation()
    sim.start()
    print("Network ready. Create a shell in the wan0 namespace and test with netperf")
    print("   (Neighbors are 172.16.1.100-%d, and LAN clients are 172.16.1.150-%d)"
            % (100 + num_neighbors - 1, 150 + num_locals - 1))
    print(" e.g.: ip netns exec wan0 netperf -H 172.16.1.100 -l 2")
    input("Press enter when finished: ")
finally:
    if "sim" in locals(): sim.release()
    if "br100" in ipdb.interfaces: ipdb.interfaces.br100.remove().commit()
    sleep(2)
    ipdb.release()


