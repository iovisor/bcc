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

import weakref

from . import mmanager

class IOModule(object):
    _capabilities_ = []
    _uuid_ = ""

    def __init__(self, *args, **kwargs):
        self.name = kwargs.get("name", "(nil)")
        self.mm = weakref.ref(kwargs.get("mmanager"))
        if not isinstance(self.mm(), mmanager.ModuleManager):
            raise Exception("Argument mmanager must be provided")
        self.interfaces = {}

    def ifc_create(self, name, *args, **kwargs):
        if name in self.interfaces:
            raise Exception("interface %s already exists" % name)
        i = self._ifc_create(name, *args, **kwargs)
        self.interfaces[name] = i
        return i

    def ifc_delete(self, name):
        pass

    def ifc_lookup(self, name):
        return self.interfaces.get(name)

    def is_bpf(self):
        return "ebpf" in self._capabilities_

    @classmethod
    def capabilities(cls):
        return cls._capabilities_

    @classmethod
    def uuid(cls):
        return cls._uuid_

    @classmethod
    def typename(cls):
        return cls.__name__
