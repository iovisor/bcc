#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from sys import argv
from bcc import BPF
from builtins import input
from ctypes import c_int, c_uint
from http.server import HTTPServer, SimpleHTTPRequestHandler
import json
from netaddr import EUI, IPAddress
from pyroute2 import IPRoute, NetNS, IPDB, NSPopen
from socket import htons, AF_INET
from threading import Thread
from subprocess import call

host_id = int(argv[1])

b = BPF(src_file="tunnel.c")
ingress_fn = b.load_func("handle_ingress", BPF.SCHED_CLS)
egress_fn = b.load_func("handle_egress", BPF.SCHED_CLS)
mac2host = b.get_table("mac2host")
vni2if = b.get_table("vni2if")
conf = b.get_table("conf")

ipr = IPRoute()
ipdb = IPDB(nl=ipr)

ifc = ipdb.interfaces.eth0
mcast = IPAddress("239.1.1.1")

# ifcs to cleanup at the end
ifc_gc = []

def run():
    ipdb.routes.add({"dst": "224.0.0.0/4", "oif": ifc.index}).commit()
    with ipdb.create(ifname="vxlan0", kind="vxlan", vxlan_id=0,
                     vxlan_link=ifc, vxlan_port=4789,
                     vxlan_group=str(mcast), vxlan_flowbased=True,
                     vxlan_collect_metadata=True,
                     vxlan_learning=False) as vx:
        vx.up()
        ifc_gc.append(vx.ifname)

    conf[c_int(1)] = c_int(vx.index)

    ipr.tc("add", "ingress", vx.index, "ffff:")
    ipr.tc("add-filter", "bpf", vx.index, ":1", fd=ingress_fn.fd,
           name=ingress_fn.name, parent="ffff:", action="drop", classid=1)

    for i in range(0, 2):
        vni = 10000 + i
        with ipdb.create(ifname="br%d" % i, kind="bridge") as br:
            v = ipdb.create(ifname="dummy%d" % i, kind="dummy").up().commit()
            mcast_key = mac2host.Key(0xFFFFFFFFFFFF, v.index, 0)
            mcast_leaf = mac2host.Leaf(vni, mcast.value, 0, 0)
            mac2host[mcast_key] = mcast_leaf

            ipr.tc("add", "sfq", v.index, "1:")
            ipr.tc("add-filter", "bpf", v.index, ":1", fd=egress_fn.fd,
                   name=egress_fn.name, parent="1:", action="drop", classid=1)
            br.add_port(v)
            br.up()
            ifc_gc.append(v.ifname)
            ifc_gc.append(br.ifname)
            vni2if[c_uint(vni)] = c_int(v.index)
            ipaddr = "99.1.%d.%d/24" % (i, host_id + 1)
            br.add_ip(ipaddr)

try:
    run()
    ipdb.release()
    input("")
    print("---")
    for k, v in mac2host.items():
        print(EUI(k.mac), k.ifindex, IPAddress(v.remote_ipv4),
              v.tunnel_id, v.rx_pkts, v.tx_pkts)
finally:
    for v in ifc_gc: call(["ip", "link", "del", v])
