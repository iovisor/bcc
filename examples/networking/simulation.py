import os
import subprocess
import pyroute2
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

    # helper function to add additional ifc to namespace
    # if called directly outside Simulation class, "ifc_base_name" should be
    # different from "name", the "ifc_base_name" and "name" are the same for
    # the first ifc created by namespace
    def _ns_add_ifc(self, name, ns_ifc, ifc_base_name=None, in_ifc=None,
                    out_ifc=None, ipaddr=None, macaddr=None, fn=None, cmd=None,
                    action="ok", disable_ipv6=False):
        if name in self.ipdbs:
            ns_ipdb = self.ipdbs[name]
        else:
            try:
                nl=NetNS(name)
                self.namespaces.append(nl)
            except KeyboardInterrupt:
                # remove the namespace if it has been created
                pyroute2.netns.remove(name)
                raise
            ns_ipdb = IPDB(nl)
            self.ipdbs[nl.netns] = ns_ipdb
            if disable_ipv6:
                cmd1 = ["sysctl", "-q", "-w",
                       "net.ipv6.conf.default.disable_ipv6=1"]
                nsp = NSPopen(ns_ipdb.nl.netns, cmd1)
                nsp.wait(); nsp.release()
            ns_ipdb.interfaces.lo.up().commit()
        if in_ifc:
            in_ifname = in_ifc.ifname
            with in_ifc as v:
                # move half of veth into namespace
                v.net_ns_fd = ns_ipdb.nl.netns
        else:
            # delete the potentially leaf-over veth interfaces
            ipr = IPRoute()
            for i in ipr.link_lookup(ifname='%sa' % ifc_base_name): ipr.link_remove(i)
            ipr.close()
            try:
                out_ifc = self.ipdb.create(ifname="%sa" % ifc_base_name, kind="veth",
                                           peer="%sb" % ifc_base_name).commit()
                in_ifc = self.ipdb.interfaces[out_ifc.peer]
                in_ifname = in_ifc.ifname
                with in_ifc as v:
                    v.net_ns_fd = ns_ipdb.nl.netns
            except KeyboardInterrupt:
                # explicitly remove the interface
                out_ifname = "%sa" % ifc_base_name
                if out_ifname in self.ipdb.interfaces: self.ipdb.interfaces[out_ifname].remove().commit()
                raise

        if out_ifc: out_ifc.up().commit()
        ns_ipdb.interfaces.lo.up().commit()
        ns_ipdb.initdb()
        in_ifc = ns_ipdb.interfaces[in_ifname]
        with in_ifc as v:
            v.ifname = ns_ifc
            if ipaddr: v.add_ip("%s" % ipaddr)
            if macaddr: v.address = macaddr
            v.up()
        if disable_ipv6:
            cmd1 = ["sysctl", "-q", "-w",
                   "net.ipv6.conf.%s.disable_ipv6=1" % out_ifc.ifname]
            subprocess.call(cmd1)
        if fn and out_ifc:
            self.ipdb.nl.tc("add", "ingress", out_ifc["index"], "ffff:")
            self.ipdb.nl.tc("add-filter", "bpf", out_ifc["index"], ":1",
                            fd=fn.fd, name=fn.name, parent="ffff:",
                            action=action, classid=1)
        if cmd:
            self.processes.append(NSPopen(ns_ipdb.nl.netns, cmd))
        return (ns_ipdb, out_ifc, in_ifc)

    # helper function to create a namespace and a veth connecting it
    def _create_ns(self, name, in_ifc=None, out_ifc=None, ipaddr=None,
                   macaddr=None, fn=None, cmd=None, action="ok", disable_ipv6=False):
        (ns_ipdb, out_ifc, in_ifc) = self._ns_add_ifc(name, "eth0", name, in_ifc, out_ifc,
                                                      ipaddr, macaddr, fn, cmd, action,
                                                      disable_ipv6)
        return (ns_ipdb, out_ifc, in_ifc)

    def release(self):
        if self.released: return
        self.released = True
        for p in self.processes:
            if p.released: continue
            try:
                p.kill()
                p.wait()
            except:
                pass
            finally:
                p.release()
        for name, db in self.ipdbs.items(): db.release()
        for ns in self.namespaces: ns.remove()

