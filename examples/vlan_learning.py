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
from ctypes import c_uint, c_int, c_ulonglong, Structure
from pyroute2 import IPRoute, NetNS, IPDB, NSPopen
from random import shuffle
from time import sleep
import sys

ipr = IPRoute()
ipr.bind(async=True)
ipdb = IPDB(nl=ipr)

num_workers = 3
num_clients = 9
num_vlans = 16

class ifindex_leaf_t(Structure):
    _fields_ = [("out_ifindex", c_int),
                ("tx_pkts", c_ulonglong),
                ("tx_bytes", c_ulonglong)]

# load the bpf program
b = BPF(src_file="examples/vlan_learning.c", debug=0)
phys_fn = b.load_func("handle_phys2virt", BPF.SCHED_CLS)
virt_fn = b.load_func("handle_virt2phys", BPF.SCHED_CLS)

ingress = b.get_table("ingress", c_ulonglong, ifindex_leaf_t)
egress = b.get_table("egress", c_ulonglong, ifindex_leaf_t)

ipdb_workers = []
ipdb_clients = []
ns_workers = []
ns_clients = []
worker_processes = []
client_processes = []

# start the worker namespaces: 1 veth pair, 1 http daemon
for i in range(0, num_workers):
    worker = IPDB(nl=NetNS("worker%d" % i))
    ipdb.create(ifname="wrk%dp0" % i, kind="veth", peer="wrk%dp1" % i).commit()
    with ipdb.interfaces["wrk%dp0" % i] as v:
        v.net_ns_fd = worker.nl.netns
    with ipdb.interfaces["wrk%dp1" % i] as v:
        ipr.tc("add", "ingress", v["index"], "ffff:")
        ipr.tc("add-filter", "bpf", v["index"], ":1", fd=virt_fn.fd,
               name=virt_fn.name, parent="ffff:", action="drop", classid=1)
        v.up()
    # use the same ip address in each namespace, clients only need to know
    # one destination IP!
    with worker.interfaces["wrk%dp0" % i] as v:
        v.ifname = "eth0"
        v.add_ip("172.16.1.5/24")
        v.up()
    httpmod = "SimpleHTTPServer" if sys.version_info[0] < 3 else "http.server"
    worker_processes.append(NSPopen(worker.nl.netns, ["python", "-m", httpmod, "80"]))
    ipdb_workers.append(worker)
    ns_workers.append(worker.nl)

# simulate a physical eth vlan trunk
with ipdb.create(ifname="eth0a", kind="veth", peer="eth0b") as v:
    v.up()
ipdb.interfaces.eth0b.up().commit()
# connect the veth to the bridge
with ipdb.create(ifname="br100", kind="bridge") as br100:
    br100.add_port(ipdb.interfaces.eth0b)
    br100.up()

# for each vlan, create a subinterface on the eth...most of these will be
# unused, but still listening and waiting for a client to send traffic on
for i in range(2, 2 + num_vlans):
    with ipdb.create(ifname="eth0a.%d" % i, kind="vlan",
                     link=ipdb.interfaces.eth0a, vlan_id=i) as v:
        v.up()
    v = ipdb.interfaces["eth0a.%d" % i]
    # add the bpf program for demuxing phys2virt packets
    ipr.tc("add", "ingress", v["index"], "ffff:")
    ipr.tc("add-filter", "bpf", v["index"], ":1", fd=phys_fn.fd,
           name=phys_fn.name, parent="ffff:", action="drop", classid=1)

# allocate vlans randomly
available_vlans = [i for i in range(2, 2 + num_vlans)]
shuffle(available_vlans)
available_ips = [[i for i in range(100, 105)] for i in range(0, num_workers)]

# these are simulations of physical clients
for i in range(0, num_clients):
    worker_choice = i % num_workers
    client = IPDB(nl=NetNS("client%d" % i))
    with ipdb.create(ifname="br100.%d" % i, kind="vlan",
                     link=br100, vlan_id=available_vlans.pop(0)) as v:
        v.net_ns_fd = client.nl.netns
    ipaddr = "172.16.1.%d" % available_ips[worker_choice].pop(0)
    with client.interfaces["br100.%d" % i] as v:
        v.add_ip("%s/24" % ipaddr)
        v.ifname = "eth0"
        v.address = "02:00:00:%.2x:%.2x:%.2x" % ((i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff)
        v.up()
    macaddr = client.interfaces.eth0.address
    # program arp manually
    p = NSPopen(ipdb_workers[worker_choice].nl.netns, ["arp", "-s", ipaddr, macaddr])
    p.communicate()

    # assign this client to the given worker
    idx = ipdb.interfaces["wrk%dp1" % worker_choice]["index"]
    mac = int(macaddr.replace(":", ""), 16)
    ingress.update(c_ulonglong(mac), ifindex_leaf_t(idx, 0, 0))

    cmd = ["bash", "-c", "for i in {1..8}; do curl 172.16.1.5 -o /dev/null; sleep 1; done"]
    client_processes.append(NSPopen(client.nl.netns, cmd))

    ipdb_clients.append(client)
    ns_clients.append(client.nl)

# IPDBs are no longer needed
for db in ipdb_workers: db.release()
for db in ipdb_clients: db.release()

sleep(10)
input("Press enter to exit: ")

stats_collect = {}
for key in ingress.iter():
    leaf = ingress.lookup(key)
    stats_collect[key.value] = [leaf.tx_pkts, leaf.tx_bytes, 0, 0]
for key in egress.iter():
    leaf = egress.lookup(key)
    x = stats_collect.get(key.value, [0, 0, 0, 0])
    x[2] = leaf.tx_pkts
    x[3] = leaf.tx_bytes
for k, v in stats_collect.items():
    print("mac %.12x rx pkts = %u, rx bytes = %u" % (k, v[0], v[1]))
    print("                 tx pkts = %u, tx bytes = %u" % (v[2], v[3]))

print("Killing worker processes")
for w in worker_processes:
    w.kill()
    w.release()

for c in client_processes:
    c.kill()
    c.release()

print("Removing namespaces and simulation interfaces")
for ns in ns_workers: ns.remove()
for ns in ns_clients: ns.remove()
ipdb.interfaces.br100.remove().commit()
ipdb.interfaces.eth0a.remove().commit()
sleep(2)
ipdb.release()
