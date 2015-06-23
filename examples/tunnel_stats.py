#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from builtins import input
from netaddr import IPNetwork
from pyroute2 import IPRoute, NetNS, IPDB, NSPopen
from random import choice, randint
from simulation import Simulation
from socket import htons
import sys

ipr = IPRoute()
ipdb = IPDB(nl=ipr)

num_hosts = 9
num_vnis = 4
null = open("/dev/null", "w")

class TunnelSimulation(Simulation):
    def __init__(self, ipdb):
        super(TunnelSimulation, self).__init__(ipdb)
        self.available_ips = [list(IPNetwork("192.168.%d.0/24" % i)[1:-1])
                              for i in range(0, num_vnis)]

    def start(self):
        # each entry is tuple of ns_ipdb, out_ifc, in_ifc
        host_info = []
        for i in range(0, num_hosts):
            ipaddr = "172.16.1.%d/24" % (100 + i)
            host_info.append(self._create_ns("host%d" % i, ipaddr=ipaddr))
        with self.ipdb.create(ifname="br100", kind="bridge") as br100:
            for host in host_info: br100.add_port(host[1])
            br100.up()
        # create a vxlan device inside each namespace
        for host in host_info:
            cmd = ["netserver", "-D"]
            self.processes.append(NSPopen(host[0].nl.netns, cmd, stdout=null))
            for i in range(0, num_vnis):
                with host[0].create(ifname="vxlan%d" % i, kind="vxlan", vxlan_id=10000 + i,
                                    vxlan_link=host[0].interfaces.eth0,
                                    vxlan_port=htons(4789), vxlan_group="239.1.1.%d" % (1 + i)) as vx:
                    vx.up()
                with host[0].create(ifname="br%d" % i, kind="bridge") as br:
                    br.add_port(host[0].interfaces["vxlan%d" % i])
                    br.up()
                    with host[0].create(ifname="c%da" % i, kind="veth",
                                        peer="c%db" % i) as c:
                        c.up()
                        c.add_ip("%s/24" % self.available_ips[i].pop(0))
                        c.mtu = 1450
                    br.add_port(host[0].interfaces["c%db" % i])
                    host[0].interfaces["c%db" % i].up().commit()

        # pick one host to start the monitor in
        host = host_info[0]
        cmd = ["python", "tunnel_monitor.py"]
        p = NSPopen(host[0].nl.netns, cmd)
        self.processes.append(p)

try:
    sim = TunnelSimulation(ipdb)
    sim.start()
    input("Press enter to quit:")
finally:
    if "br100" in ipdb.interfaces: ipdb.interfaces.br100.remove().commit()
    sim.release()
    ipdb.release()
    null.close()
