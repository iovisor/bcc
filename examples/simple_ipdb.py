#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# This example shows how to use pyroute2 to attach a BPF program to an
# interface. Pyroute2 does contain some quirks with regard to program
# termination, especially take care when using IPDB and leaving exceptions
# uncaught (catch them).

from bpf import BPF
from pyroute2 import IPRoute, IPDB

ipr = IPRoute()
ipdb = IPDB(nl=ipr)

text = """
int hello(struct __sk_buff *skb) {
  return 1;
}
"""

try:
    b = BPF(text=text, debug=0)
    fn = b.load_func("hello", BPF.SCHED_CLS)
    ifc = ipdb.create(ifname="t1a", kind="veth", peer="t1b").commit()

    ipr.tc("add", "ingress", ifc["index"], "ffff:")
    ipr.tc("add-filter", "bpf", ifc["index"], ":1", fd=fn.fd,
           name=fn.name, parent="ffff:", action="ok", classid=1)
    ipr.tc("add", "sfq", ifc["index"], "1:")
    ipr.tc("add-filter", "bpf", ifc["index"], ":1", fd=fn.fd,
           name=fn.name, parent="1:", action="ok", classid=1)
finally:
    if "ifc" in locals(): ifc.remove().commit()
    ipdb.release()
