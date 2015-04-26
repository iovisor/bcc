#!/usr/bin/env python

import time
from netaddr import IPAddress
from ctypes import *
from src.bpf import BPF

prog = BPF("classifier", "tests/test3.dp", "tests/proto.dph",
        BPF.BPF_PROG_TYPE_SCHED_CLS, debug=1)

class Key(Structure):
    _fields_ = [("dip", c_uint),
                ("sip", c_uint)]
class Leaf(Structure):
    _fields_ = [("xdip", c_uint),
                ("xsip", c_uint),
                ("xlated_pkts", c_ulonglong)]

prog.attach_filter(4, 10, 1)
xlate = prog.table("xlate", Key, Leaf)
xlate.put(Key(IPAddress("172.16.2.1").value, IPAddress("172.16.2.2").value),
        Leaf(IPAddress("192.168.1.1").value, IPAddress("192.168.1.2").value, 0))
while True:
    print("==============================")
    for key in xlate.iter():
        leaf = xlate.get(key)
        print(IPAddress(key.sip), "=>", IPAddress(key.dip),
              "xlated_pkts", leaf.xlated_pkts)
    time.sleep(1)
