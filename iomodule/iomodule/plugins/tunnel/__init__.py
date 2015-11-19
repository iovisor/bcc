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

import atexit
import bcc
import netaddr
import pyroute2
import os
import socket

from iomodule.core import iomodule

_dir = os.path.dirname(__file__)

class Tunnel(iomodule.IOModule):
    _capabilities_ = ["vxlan", "ebpf"]
    _uuid_ = "27bdfc7a-60be-4b0b-882e-a52677362bb5"

    def __init__(self, *args, **kwargs):
        super(Tunnel, self).__init__(*args, **kwargs)
        self.b = bcc.BPF(os.path.join(_dir, "tunnel.c"))
        self.tunnel_fn = self.b.load_func("recv_tunnel", self.b.SCHED_ACT)
        self.local_fn = self.b.load_func("recv_local", self.b.SCHED_ACT)
        self.config = kwargs.get("config", {})
        self.if2t = self.b["if2tunkey"]
        self.t2if = self.b["tunkey2if"]
        self.conf = self.b["conf"]

        with self.mm().ipdb.create(ifname=self.name, kind="vxlan", vxlan_id=0,
                vxlan_link=self.mm().ipdb.interfaces.lo,
                vxlan_port=socket.htons(4789), vxlan_collect_metadata=True,
                vxlan_learning=False) as vx:
            vx.up()
        self.vni = 1
        self.vx = vx.index

        self.conf[self.conf.Key(1)] = self.conf.Leaf(self.vx)
        self.mm().add_ingress_action(self.vx, self.tunnel_fn)

    def _ifc_create(self, name, *args, **kwargs):
        (idx1, idx2) = self.mm().get_index_pair(name, self)
        ipaddr = netaddr.IPAddress(self.config.get("peer_ip", "0.0.0.0"))
        self.t2if[self.t2if.Key(self.vni, ipaddr)] = self.t2if.Leaf(idx1)
        self.if2t[self.if2t.Key(idx1)] = self.if2t.Leaf(self.vni, ipaddr)
        self.vni += 1
        return idx2

    def fd(self):
        return self.local_fn.fd

    def __del__(self):
        pyroute2.IPRoute().link_remove(index=self.vx)

cls = Tunnel
