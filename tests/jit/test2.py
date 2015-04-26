#!/usr/bin/env python

# test program to count the packets sent to a device in a .5
# second period

import time
import netaddr
from ctypes import *
from src.bpf import BPF

prog = BPF("socket1", "tests/test2.dp", "tests/proto.dph")

class Key(Structure):
    _fields_ = [("dip", c_uint),
                ("sip", c_uint)]
class Leaf(Structure):
    _fields_ = [("rx_pkts", c_ulong),
                ("tx_pkts", c_ulong)]

prog.attach("eth0")
stats = prog.table("stats", Key, Leaf)

time.sleep(0.5)

for key in stats.iter():
    leaf = stats.get(key)
    print(netaddr.IPAddress(key.sip), "=>", netaddr.IPAddress(key.dip),
          "rx", leaf.rx_pkts, "tx", leaf.tx_pkts)
