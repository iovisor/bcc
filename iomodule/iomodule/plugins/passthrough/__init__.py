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
from iomodule.core import iomodule

class Passthrough(iomodule.IOModule):
    _capabilities_ = ["ebpf"]
    _uuid_ = "8f2edac8-3816-4610-9030-0d21a6e6b348"

    def __init__(self, *args, **kwargs):
        super(Passthrough, self).__init__(*args, **kwargs)
        self.b = bcc.BPF("passthrough.c")
        self.fn = self.b.load_func("recv", self.b.SCHED_ACT)
        self.half = None

    def _ifc_create(self, name):
        (idx1, idx2) = self.mm.get_index_pair(name)
        print("ifc_create", name, idx1, idx2)
        if self.half:
            self.b["pairs"][c_int(self.half)] = c_int(idx1)
            self.b["pairs"][c_int(idx1)] = c_int(self.half)
            print("connecting", self.half, idx1)
            self.half = None
        else:
            self.half = idx1
        return idx2

    def fd(self):
        return self.fn.fd

cls = Passthrough
