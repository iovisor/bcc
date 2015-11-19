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
import ctypes
import os
import tempfile
import sys
import netaddr
sys.path.append("/home/bblanco/work/bcc/src/cc/frontends/p4/compiler")
import target
from p4_hlir.main import HLIR
from ebpfProgram import EbpfProgram
from compilationException import *
from programSerializer import ProgramSerializer

from iomodule.core import iomodule

_dir = os.path.dirname(__file__)

class P4Switch(iomodule.IOModule):
    _capabilities_ = ["ebpf"]
    _uuid_ = "e0cf1765-dc5a-4b4f-9f0d-b23f718e3262"

    def __init__(self, *args, **kwargs):
        super(P4Switch, self).__init__(*args, **kwargs)
        config = kwargs.get("config", {})
        if not config:
            raise Exception("required config argument missing")
        p4cfg = config.get("p4", {})
        p4text = p4cfg.get("text")
        if not p4text:
            raise Exception("required config.p4.text argument missing")
        p4args = p4cfg.get("args", [])
        is_router = p4cfg.get("is_router", False)
        with tempfile.NamedTemporaryFile() as f:
            f.write(p4text)
            f.flush()
            h = HLIR(f.name)
            h.build()
            target_config = target.BccConfig()
            e = EbpfProgram("1.p4", h, is_router, target_config)
            serializer = ProgramSerializer()
            e.toC(serializer)
            self.b = bcc.BPF(text=serializer.toString())
            self.fn = self.b.load_func("ebpf_filter", self.b.SCHED_ACT)

    def _ifc_create(self, name, *args, **kwargs):
        (idx1, idx2) = self.mm().get_index_pair(name, self)
        config = kwargs.get("config", {})
        nexthop = config.get("nexthop", [])
        t = self.b.get_table("routing")
        for nh in nexthop:
            action_hit = ctypes.c_uint(1)
            key = t.Key(netaddr.IPAddress(nh).value)
            leaf = t.leaf_scanf("{ 1 { { %d } } }" % idx1)
            t[key] = leaf
        #t[t.Key(vrf, netaddr.IPAddress("0.0.0.0").value)] = t.Leaf(action_hit, ctypes.c_ushort(idx1))
        return idx2

    def fd(self):
        return self.fn.fd

cls = P4Switch
