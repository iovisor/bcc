import atexit
from pyroute2 import IPRoute, NetNS, IPDB, NSPopen

class Simulation(object):
    """
    Helper class for controlling multiple namespaces. Inherit from
    this class and setup your namespaces.
    """

    def __init__(self, ipdb):
        self.ipdb = ipdb
        self.ipdbs = {}
        self.namespaces = []
        self.processes = []
        self.released = False

    # helper function to create a namespace and a veth connecting it
    def _create_ns(self, name, in_ifc=None, out_ifc=None, ipaddr=None,
                   macaddr=None, fn=None, cmd=None, action="ok"):
        ns_ipdb = IPDB(nl=NetNS(name))
        if in_ifc:
            in_ifname = in_ifc.ifname
        else:
            out_ifc = self.ipdb.create(ifname="%sa" % name, kind="veth",
                                       peer="%sb" % name).commit()
            in_ifc = self.ipdb.interfaces[out_ifc.peer]
            in_ifname = in_ifc.ifname
        with in_ifc as v:
            # move half of veth into namespace
            v.net_ns_fd = ns_ipdb.nl.netns
        in_ifc = ns_ipdb.interfaces[in_ifname]
        if out_ifc: out_ifc.up().commit()
        with in_ifc as v:
            v.ifname = "eth0"
            if ipaddr: v.add_ip("%s" % ipaddr)
            if macaddr: v.address = macaddr
            v.up()
        if fn and out_ifc:
            self.ipdb.nl.tc("add", "ingress", out_ifc["index"], "ffff:")
            self.ipdb.nl.tc("add-filter", "bpf", out_ifc["index"], ":1",
                            fd=fn.fd, name=fn.name, parent="ffff:",
                            action=action, classid=1)
        self.ipdbs[ns_ipdb.nl.netns] = ns_ipdb
        self.namespaces.append(ns_ipdb.nl)
        if cmd:
            self.processes.append(NSPopen(ns_ipdb.nl.netns, cmd))
        return (ns_ipdb, out_ifc, in_ifc)

    def release(self):
        if self.released: return
        self.released = True
        for p in self.processes:
            if p.released: continue
            p.kill(); p.wait(); p.release()
        for name, db in self.ipdbs.items(): db.release()
        for ns in self.namespaces: ns.remove()

