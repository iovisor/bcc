#!/usr/bin/env python3

# Copyright (c) Barefoot Networks, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# Testing example for P4->EBPF compiler
#
# This program exercises the simple.c EBPF program
# generated from the simple.p4 source file.

import subprocess
import ctypes
import time
import sys
import os
from bcc import BPF
from pyroute2 import IPRoute, NSPopen, NetNS
from netaddr import IPAddress

### This part is a simple generic network simulaton toolkit

class Base(object):
    def __init__(self):
        self.verbose = True

    def message(self, *args):
        if self.verbose:
            print(*args)


class Endpoint(Base):
    # a network interface really
    def __init__(self, ipaddress, ethaddress):
        Base.__init__(self)
        self.mac_addr = ethaddress
        self.ipaddress = ipaddress
        self.prefixlen = 24
        self.parent = None

    def __str__(self):
        return "Endpoint " + str(self.ipaddress)

    def set_parent(self, parent):
        assert isinstance(parent, Node)
        self.parent = parent

    def get_ip_address(self):
        return IPAddress(self.ipaddress)


class Node(Base):
    # Used to represent one of clt, sw, srv
    # Each lives in its own namespace
    def __init__(self, name):
        Base.__init__(self)
        self.name = name
        self.endpoints = []
        self.get_ns()  # as a side-effect creates namespace

    def add_endpoint(self, endpoint):
        assert isinstance(endpoint, Endpoint)
        self.endpoints.append(endpoint)
        endpoint.set_parent(self)

    def __str__(self):
        return "Node " + self.name

    def get_ns_name(self):
        return self.name

    def get_ns(self):
        nsname = self.get_ns_name()
        ns = NetNS(nsname)
        return ns

    def remove(self):
        ns = self.get_ns();
        ns.close()
        ns.remove()

    def execute(self, command):
        # Run a command in the node's namespace
        # Return the command's exit code
        self.message(self.name, "Executing", command)
        nsn = self.get_ns_name()
        pipe = NSPopen(nsn, command)
        result = pipe.wait()
        pipe.release()
        return result

    def set_arp(self, destination):
        assert isinstance(destination, Endpoint)
        command = ["arp", "-s", str(destination.ipaddress),
                   str(destination.mac_addr)]
        self.execute(command)


class NetworkBase(Base):
    def __init__(self):
        Base.__init__(self)
        self.ipr = IPRoute()
        self.nodes = []

    def add_node(self, node):
        assert isinstance(node, Node)
        self.nodes.append(node)

    def get_interface_name(self, source, dest):
        assert isinstance(source, Node)
        assert isinstance(dest, Node)
        interface_name = "veth-" + source.name + "-" + dest.name
        return interface_name

    def get_interface(self, ifname):
        interfaces = self.ipr.link_lookup(ifname=ifname)
        if len(interfaces) != 1:
            raise Exception("Could not identify interface " + ifname)
        ix = interfaces[0]
        assert isinstance(ix, int)
        return ix

    def set_interface_ipaddress(self, node, ifname, address, mask):
        # Ask a node to set the specified interface address
        if address is None:
            return

        assert isinstance(node, Node)
        command = ["ip", "addr", "add", str(address) + "/" + str(mask),
                   "dev", str(ifname)]
        result = node.execute(command)
        assert(result == 0)

    def create_link(self, src, dest):
        assert isinstance(src, Endpoint)
        assert isinstance(dest, Endpoint)

        ifname = self.get_interface_name(src.parent, dest.parent)
        destname = self.get_interface_name(dest.parent, src.parent)
        self.ipr.link_create(ifname=ifname, kind="veth", peer=destname)

        self.message("Create", ifname, "link")

        # Set source endpoint information
        ix = self.get_interface(ifname)
        self.ipr.link("set", index=ix, address=src.mac_addr)
        # push source endpoint into source namespace
        self.ipr.link("set", index=ix,
                      net_ns_fd=src.parent.get_ns_name(), state="up")
        # Set interface ip address; seems to be
        # lost of set prior to moving to namespace
        self.set_interface_ipaddress(
            src.parent, ifname, src.ipaddress , src.prefixlen)

        # Sef destination endpoint information
        ix = self.get_interface(destname)
        self.ipr.link("set", index=ix, address=dest.mac_addr)
        # push destination endpoint into the destination namespace
        self.ipr.link("set", index=ix,
                      net_ns_fd=dest.parent.get_ns_name(), state="up")
        # Set interface ip address
        self.set_interface_ipaddress(dest.parent, destname,
                                     dest.ipaddress, dest.prefixlen)

    def show_interfaces(self, node):
        cmd = ["ip", "addr"]
        if node is None:
            # Run with no namespace
            subprocess.call(cmd)
        else:
            # Run in node's namespace
            assert isinstance(node, Node)
            self.message("Enumerating all interfaces in ", node.name)
            node.execute(cmd)

    def delete(self):
        self.message("Deleting virtual network")
        for n in self.nodes:
            n.remove()
        self.ipr.close()


### Here begins the concrete instantiation of the network
# Network setup:
# Each of these is a separate namespace.
#
#                        62:ce:1b:48:3e:61          a2:59:94:cf:51:09
#      96:a4:85:fe:2a:11           62:ce:1b:48:3e:60
#              /------------------\     /-----------------\
#      ----------                 --------                ---------
#      |  clt   |                 |  sw  |                |  srv  |
#      ----------                 --------                ---------
#       10.0.0.11                                         10.0.0.10
#

class SimulatedNetwork(NetworkBase):
    def __init__(self):
        NetworkBase.__init__(self)

        self.client = Node("clt")
        self.add_node(self.client)
        self.client_endpoint = Endpoint("10.0.0.11", "96:a4:85:fe:2a:11")
        self.client.add_endpoint(self.client_endpoint)

        self.server = Node("srv")
        self.add_node(self.server)
        self.server_endpoint = Endpoint("10.0.0.10", "a2:59:94:cf:51:09")
        self.server.add_endpoint(self.server_endpoint)

        self.switch = Node("sw")
        self.add_node(self.switch)
        self.sw_clt_endpoint = Endpoint(None, "62:ce:1b:48:3e:61")
        self.sw_srv_endpoint = Endpoint(None, "62:ce:1b:48:3e:60")
        self.switch.add_endpoint(self.sw_clt_endpoint)
        self.switch.add_endpoint(self.sw_srv_endpoint)

    def run_method_in_node(self, node, method, args):
        # run a method of the SimulatedNetwork class in a different namespace
        # return the exit code
        assert isinstance(node, Node)
        assert isinstance(args, list)
        torun = __file__
        args.insert(0, torun)
        args.insert(1, method)
        return node.execute(args)  # runs the command argv[0] method args

    def instantiate(self):
        # Creates the various namespaces
        self.message("Creating virtual network")

        self.message("Create client-switch link")
        self.create_link(self.client_endpoint, self.sw_clt_endpoint)

        self.message("Create server-switch link")
        self.create_link(self.server_endpoint, self.sw_srv_endpoint)

        self.show_interfaces(self.client)
        self.show_interfaces(self.server)
        self.show_interfaces(self.switch)

        self.message("Set ARP mappings")
        self.client.set_arp(self.server_endpoint)
        self.server.set_arp(self.client_endpoint)

    def setup_switch(self):
        # This method is run in the switch namespace.
        self.message("Compiling and loading BPF program")

        b = BPF(src_file="./simple.c", debug=0)
        fn = b.load_func("ebpf_filter", BPF.SCHED_CLS)

        self.message("BPF program loaded")

        self.message("Discovering tables")
        routing_tbl = b.get_table("routing")
        routing_miss_tbl = b.get_table("ebpf_routing_miss")
        cnt_tbl = b.get_table("cnt")

        self.message("Hooking up BPF classifiers using TC")

        interfname = self.get_interface_name(self.switch, self.server)
        sw_srv_idx = self.get_interface(interfname)
        self.ipr.tc("add", "ingress", sw_srv_idx, "ffff:")
        self.ipr.tc("add-filter", "bpf", sw_srv_idx, ":1", fd=fn.fd,
                    name=fn.name, parent="ffff:", action="ok", classid=1)

        interfname = self.get_interface_name(self.switch, self.client)
        sw_clt_idx = self.get_interface(interfname)
        self.ipr.tc("add", "ingress", sw_clt_idx, "ffff:")
        self.ipr.tc("add-filter", "bpf", sw_clt_idx, ":1", fd=fn.fd,
                    name=fn.name, parent="ffff:", action="ok", classid=1)

        self.message("Populating tables from the control plane")
        cltip = self.client_endpoint.get_ip_address()
        srvip = self.server_endpoint.get_ip_address()

        # BCC does not support tbl.Leaf when the type contains a union,
        # so we have to make up the value type manually.  Unfortunately
        # these sizes are not portable...

        class Forward(ctypes.Structure):
            _fields_ = [("port", ctypes.c_ushort)]

        class Nop(ctypes.Structure):
            _fields_ = []

        class Union(ctypes.Union):
            _fields_ = [("nop", Nop),
                        ("forward", Forward)]

        class Value(ctypes.Structure):
            _fields_ = [("action", ctypes.c_uint),
                        ("u", Union)]

        if False:
            # This is how it should ideally be done, but it does not work
            routing_tbl[routing_tbl.Key(int(cltip))] = routing_tbl.Leaf(
                1, sw_clt_idx)
            routing_tbl[routing_tbl.Key(int(srvip))] = routing_tbl.Leaf(
                1, sw_srv_idx)
        else:
            v1 = Value()
            v1.action = 1
            v1.u.forward.port = sw_clt_idx

            v2 = Value()
            v2.action = 1;
            v2.u.forward.port = sw_srv_idx

            routing_tbl[routing_tbl.Key(int(cltip))] = v1
            routing_tbl[routing_tbl.Key(int(srvip))] = v2

        self.message("Dumping table contents")
        for key, leaf in routing_tbl.items():
            self.message(str(IPAddress(key.key_field_0)),
                         leaf.action, leaf.u.forward.port)

    def run(self):
        self.message("Pinging server from client")
        ping = ["ping", self.server_endpoint.ipaddress, "-c", "2"]
        result = self.client.execute(ping)
        if result != 0:
            raise Exception("Test failed")
        else:
            print("Test succeeded!")

    def prepare_switch(self):
        self.message("Configuring switch")
        # Re-invokes this script in the switch namespace;
        # this causes the setup_switch method to be run in that context.
        # This is the same as running self.setup_switch()
        # but in the switch namespace
        self.run_method_in_node(self.switch, "setup_switch", [])


def compile(source, destination):
    try:
        status = subprocess.call(
            "../compiler/p4toEbpf.py " + source + " -o " + destination,
            shell=True)
        if status < 0:
            print("Child was terminated by signal", -status, file=sys.stderr)
        else:
            print("Child returned", status, file=sys.stderr)
    except OSError as e:
        print("Execution failed:", e, file=sys.stderr)
        raise e

def start_simulation():
    compile("testprograms/simple.p4", "simple.c")
    network = SimulatedNetwork()
    network.instantiate()
    network.prepare_switch()
    network.run()
    network.delete()
    os.remove("simple.c")

def main(argv):
    print(str(argv))
    if len(argv) == 1:
        # Main entry point: start simulation
        start_simulation()
    else:
        # We are invoked with some arguments (probably in a different namespace)
        # First argument is a method name, rest are method arguments.
        # Create a SimulatedNetwork and invoke the specified method with the
        # specified arguments.
        network = SimulatedNetwork()
        methodname = argv[1]
        arguments = argv[2:]
        method = getattr(network, methodname)
        method(*arguments)

if __name__ == '__main__':
    main(sys.argv)

