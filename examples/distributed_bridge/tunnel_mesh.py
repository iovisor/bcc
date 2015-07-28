#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from sys import argv
from bpf import BPF
from builtins import input
from ctypes import c_int, c_uint
from http.server import HTTPServer, SimpleHTTPRequestHandler
import json
from netaddr import EUI, IPAddress
from pyroute2 import IPRoute, NetNS, IPDB, NSPopen
from socket import htons, AF_INET
from threading import Thread

num_hosts = int(argv[1])
host_id = int(argv[2])

b = BPF(src_file="tunnel_mesh.c")
ingress_fn = b.load_func("handle_ingress", BPF.SCHED_CLS)
egress_fn = b.load_func("handle_egress", BPF.SCHED_CLS)
tunkey2if = b.get_table("tunkey2if")
if2tunkey = b.get_table("if2tunkey")
conf = b.get_table("conf")

ipr = IPRoute()
ipdb = IPDB(nl=ipr)

ifc = ipdb.interfaces.eth0

# ifcs to cleanup at the end
ifc_gc = []

def run():
    with ipdb.create(ifname="vxlan0", kind="vxlan", vxlan_id=0,
                     vxlan_link=ifc, vxlan_port=htons(4789),
                     vxlan_flowbased=True,
                     vxlan_collect_metadata=True,
                     vxlan_learning=False) as vx:
        vx.up()
        ifc_gc.append(vx.ifname)

    conf[c_int(1)] = c_int(vx.index)

    ipr.tc("add", "ingress", vx.index, "ffff:")
    ipr.tc("add-filter", "bpf", vx.index, ":1", fd=ingress_fn.fd,
           name=ingress_fn.name, parent="ffff:", action="drop", classid=1)

    for j in range(0, 2):
        vni = 10000 + j
        with ipdb.create(ifname="br%d" % j, kind="bridge") as br:
            for i in range(0, num_hosts):
                if i != host_id:
                    v = ipdb.create(ifname="dummy%d%d" % (j , i), kind="dummy").up().commit()
                    ipaddr = "172.16.1.%d" % (100 + i)
                    tunkey2if_key = tunkey2if.Key(vni, IPAddress(ipaddr))
                    tunkey2if_leaf = tunkey2if.Leaf(v.index)
                    tunkey2if[tunkey2if_key] = tunkey2if_leaf

                    if2tunkey_key = if2tunkey.Key(v.index)
                    if2tunkey_leaf = if2tunkey.Leaf(vni, IPAddress(ipaddr))
                    if2tunkey[if2tunkey_key] = if2tunkey_leaf

                    ipr.tc("add", "sfq", v.index, "1:")
                    ipr.tc("add-filter", "bpf", v.index, ":1", fd=egress_fn.fd,
                       name=egress_fn.name, parent="1:", action="drop", classid=1)
                    br.add_port(v)
                    br.up()
                    ifc_gc.append(v.ifname)
            ifc_gc.append(br.ifname)

try:
    run()
    input("")
    print("---")
finally:
    for v in ifc_gc: ipdb.interfaces[v].remove().commit()
    ipdb.release()
