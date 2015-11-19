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

import pyroute2
from . import iomodule

class Interfaces(iomodule.IOModule):
    _capabilities_ = []
    _uuid_ = "7795ec54-e6b2-48d2-a9b9-291c897a9430"

    def __init__(self, *args, **kwargs):
        super(Interfaces, self).__init__(*args, **kwargs)

    def _ifc_create(self, name, *args, **kwargs):
        if name not in self.mm().ipdb.interfaces:
            raise Exception("%s not in interface list" % name)
        return self.mm().ipdb.interfaces[name].index

    def ifc_lookup(self, name):
        links = self.mm().ipdb.nl.link_lookup(ifname=name)
        if len(links) == 0:
            return None
        return links[0]

cls = Interfaces
