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
import pyroute2
from iomodule.core import iomodule

class Bridge(iomodule.IOModule):
    _capabilities_ = ["netns"]
    _uuid_ = "1982ffb5-0dec-42c8-b4fb-8d1df2ec66ea"

    def __init__(self, *args, **kwargs):
        super(Bridge, self).__init__(*args, **kwargs)
        self.config = kwargs.get("config", {})
        self.ipdb = pyroute2.IPDB(nl=pyroute2.NetNS(self.name))
        with self.ipdb.create(ifname="br0", kind="bridge") as br:
            if self.config.get("ipaddr"):
                br.add_ip(self.config["ipaddr"])
            if self.config.get("mac"):
                br.address=self.config["mac"]
            br.up()
        if self.config.get("arp"):
            cmd = ["arp", "-s"] + self.config["arp"].split(" ")
            nsp = pyroute2.NSPopen(self.ipdb.nl.netns, cmd)
            nsp.wait(); nsp.release()
        self.num_ifcs = 0
        atexit.register(self.release)

    def _ifc_create(self, name, *args, **kwargs):
        with self.mm().ipdb.create(kind="veth",
                ifname="%s.%d" % (self.name, self.num_ifcs),
                peer="%s.%db" % (self.name, self.num_ifcs)) as ifc1:
            ifc1.up()
        with self.mm().ipdb.interfaces["%s.%db" % (self.name, self.num_ifcs)] as ifc2:
            ifc2.net_ns_fd = self.ipdb.nl.netns
            ifc2.ifname = name
        self.ipdb.interfaces.br0.add_port(ifc2).commit()
        self.ipdb.interfaces.br0.up().commit()
        self.ipdb.interfaces[name].up().commit()
        self.num_ifcs += 1
        return ifc1.index

    def release(self):
        self.ipdb.nl.remove()
        self.ipdb.release()

cls = Bridge
