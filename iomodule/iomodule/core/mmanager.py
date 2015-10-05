# Copyright 2015 PLUMgrid
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import bcc
from ctypes import c_int
import os
import pyroute2
from . import utils

_dir = os.path.dirname(__file__)

class ModuleManager(object):
    MAX_INDEX = 32767
    def __init__(self, *args, **kwargs):
        self.b = bcc.BPF(os.path.join(_dir, "patch.c"))
        self.netdev_fn = self.b.load_func("recv_netdev", self.b.SCHED_ACT)
        self.tailcall_fn = self.b.load_func("recv_tailcall", self.b.SCHED_ACT)
        self._index = 0
        self._indices = utils.BitArray(self.MAX_INDEX + 1)
        self._connections = {}
        self.ipr = kwargs.get("ipr", pyroute2.IPRoute())
        self.ipdb = kwargs.get("ipdb", pyroute2.IPDB(nl=self.ipr))

    def get_index_pair(self, name, iom):
        if name in self._connections:
            (i, m) = self._connections[name]
            # repeat call by owner iomodule, return same pair
            if m == iom:
                return (-(i << 1), -((i << 1) ^ 1))
            # peer call, invert the indices
            return (-((i << 1) ^ 1), -(i << 1))
        index = self._index
        index += 1
        sentinel = self._index
        while index != sentinel:
            if index > self.MAX_INDEX: index = 1
            if not self._indices[index]:
                self._index = index
                self._indices[index] = True
                self._connections[name] = (index, iom)
                return (-(index << 1), -((index << 1) ^ 1))
            index += 1
        raise Exception("Unable to allocate new index")

    def add_ingress_action(self, ifindex, fn):
        action = dict(kind="bpf", fd=fn.fd, name=fn.name, action="drop")
        self.ipr.tc("add", "ingress", ifindex, "ffff:")
        self.ipr.tc("add-filter", "u32", ifindex, ":1", parent="ffff:",
                action=action, protocol=pyroute2.protocols.ETH_P_ALL,
                classid=1, target=0x10000, keys=["0x0/0x0+0"])

    def connect(self, ifc1, ifc2, iom1, iom2):
        if ifc1 > 0 and ifc2 > 0:
            self.b["patch"][c_int(ifc1)] = c_int(ifc2)
            self.b["patch"][c_int(ifc2)] = c_int(ifc1)
            self.add_ingress_action(ifc1, self.netdev_fn)
            self.add_ingress_action(ifc2, self.netdev_fn)
        elif ifc1 < 0 and ifc2 > 0:
            self.b["patch"][c_int(ifc1)] = c_int(ifc2)
            self.b["patch"][c_int(ifc2)] = c_int(ifc1)
            self.b["forward"][c_int(-ifc1)] = c_int(iom1.fd())
            self.b["forward"][c_int(-ifc1 ^ 1)] = c_int(self.tailcall_fn.fd)
            # todo: share forward table with all programs
            iom1.b["forward"][c_int(-ifc1 ^ 1)] = c_int(self.tailcall_fn.fd)
            self.add_ingress_action(ifc2, self.netdev_fn)
        elif ifc2 < 0 and ifc1 > 0:
            self.b["patch"][c_int(ifc2)] = c_int(ifc1)
            self.b["patch"][c_int(ifc1)] = c_int(ifc2)
            self.b["forward"][c_int(-ifc2)] = c_int(iom2.fd())
            self.b["forward"][c_int(-ifc2 ^ 1)] = c_int(self.tailcall_fn.fd)
            # todo: share forward table with all programs
            iom2.b["forward"][c_int(-ifc2 ^ 1)] = c_int(self.tailcall_fn.fd)
            self.add_ingress_action(ifc1, self.netdev_fn)
        else:
            if -ifc1 ^ 1 != -ifc2:
                raise Exception("bpf ifc indices are not a matched pair")
            self.b["forward"][c_int(-ifc2)] = c_int(iom2.fd())
            self.b["forward"][c_int(-ifc1)] = c_int(iom1.fd())
            # todo: share forward table with all programs
            iom1.b["forward"][c_int(-ifc2)] = c_int(iom2.fd())
            iom2.b["forward"][c_int(-ifc1)] = c_int(iom1.fd())

    def disconnect(self, conn):
        pass
