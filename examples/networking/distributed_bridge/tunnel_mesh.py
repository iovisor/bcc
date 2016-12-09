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
from subprocess import call, Popen, PIPE

num_hosts = int(argv[1])
host_id = int(argv[2])
dhcp = int(argv[3])
gretap = int(argv[4])

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

# dhcp server and client processes
d_serv = []
d_client = []

def run():
    if gretap:
        with ipdb.create(ifname="gretap1", kind="gretap", gre_ikey=0, gre_okey=0,
                         gre_local='172.16.1.%d' % (100 + host_id),
                         gre_ttl=16, gre_collect_metadata=1) as vx:
            vx.up()
            ifc_gc.append(vx.ifname)
    else:
        with ipdb.create(ifname="vxlan0", kind="vxlan", vxlan_id=0,
                         vxlan_link=ifc, vxlan_port=4789,
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
                    tunkey2if_key = tunkey2if.Key(vni)
                    tunkey2if_key.remote_ipv4 = IPAddress(ipaddr)
                    tunkey2if_leaf = tunkey2if.Leaf(v.index)
                    tunkey2if[tunkey2if_key] = tunkey2if_leaf

                    if2tunkey_key = if2tunkey.Key(v.index)
                    if2tunkey_leaf = if2tunkey.Leaf(vni)
                    if2tunkey_leaf.remote_ipv4 = IPAddress(ipaddr)
                    if2tunkey[if2tunkey_key] = if2tunkey_leaf

                    ipr.tc("add", "sfq", v.index, "1:")
                    ipr.tc("add-filter", "bpf", v.index, ":1", fd=egress_fn.fd,
                       name=egress_fn.name, parent="1:", action="drop", classid=1)
                    br.add_port(v)
                    br.up()
                    ifc_gc.append(v.ifname)
            if dhcp == 0:
                ipaddr = "99.1.%d.%d/24" % (j, host_id + 1)
                br.add_ip(ipaddr)
            ifc_gc.append(br.ifname)

    # dhcp server only runs on host 0
    if dhcp == 1 and host_id == 0:
        for j in range(0, 2):
            v1 = "dhcp%d_v1" % j
            v2 = "dhcp%d_v2" % j
            br = ipdb.interfaces["br%d" % j]
            with ipdb.create(ifname=v1, kind="veth", peer=v2) as v:
                    v.up()
            br.add_port(ipdb.interfaces[v1]).commit()
            dhcp_v2 = ipdb.interfaces[v2]
            dhcp_v2.add_ip("99.1.%d.1/24" % j).up().commit()

            call(["/bin/rm", "-f", "/tmp/dnsmasq.%d.leases" % j])
            cmd = ["dnsmasq", "-d", "--bind-interfaces", "--strict-order",
                   "--conf-file=",
                   "--dhcp-range", "99.1.%d.2,99.1.%d.254,255.255.255.0,12h" % (j, j),
                   "--dhcp-no-override", "--except-interface=lo",
                   "--interface=dhcp%d_v2" % j,
                   "--dhcp-authoritative",
                   "--dhcp-leasefile=/tmp/dnsmasq.%d.leases" % j]
            d_serv.append(Popen(cmd, stdout=PIPE, stderr=PIPE))

    # dhcp client to assign ip address for each bridge
    if dhcp == 1:
        for j in range(0, 2):
            call(["/bin/rm", "-rf", "/tmp/dhcp_%d_%d" % (host_id, j)])
            call(["mkdir", "/tmp/dhcp_%d_%d" % (host_id, j)])
            call(["touch", "/tmp/dhcp_%d_%d/dhclient.conf" % (host_id, j)])
            call(["touch", "/tmp/dhcp_%d_%d/dhclient.lease" % (host_id, j)])
            cmd = ["dhclient", "-d", "br%d" % j,
                   "-cf", "/tmp/dhcp_%d_%d/dhclient.conf" % (host_id, j),
                   "-lf", "/tmp/dhcp_%d_%d/dhclient.lease" % (host_id, j)]
            d_client.append(Popen(cmd, stdout=PIPE, stderr=PIPE))

            # make sure we get address for eth0
            retry = -1
            while retry < 0:
                check = Popen(["ip", "addr", "show", "br%d" % j], stdout=PIPE, stderr=PIPE)
                out = check.stdout.read()
                checkip = b"99.1.%d" % j
                retry = out.find(checkip)

try:
    run()
    input("")
finally:
    for v in ifc_gc: call(["ip", "link", "del", v])
    ipdb.release()
    for p in d_client: p.kill()
    for p in d_serv: p.kill()
