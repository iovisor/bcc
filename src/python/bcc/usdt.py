# Copyright 2016 Sasha Goldshtein
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

from .libbcc import lib, _USDT_CB, _USDT_PROBE_CB

class USDTProbe(object):
    def __init__(self, usdt):
        self.provider = usdt.provider
        self.name = usdt.name
        self.bin_path = usdt.bin_path
        self.semaphore = usdt.semaphore
        self.num_locations = usdt.num_locations
        self.num_arguments = usdt.num_arguments

    def __str__(self):
        return "%s %s:%s [sema 0x%x]\n  %d location(s)\n  %d argument(s)" % \
               (self.bin_path, self.provider, self.name, self.semaphore,
                self.num_locations, self.num_arguments)

class USDT(object):
    def __init__(self, pid=None, path=None):
        if pid:
            self.pid = pid
            self.context = lib.bcc_usdt_new_frompid(pid)
            if self.context == None:
                raise Exception("USDT failed to instrument PID %d" % pid)
        elif path:
            self.path = path
            self.context = lib.bcc_usdt_new_frompath(path)
            if self.context == None:
                raise Exception("USDT failed to instrument path %s" % path)
        else:
            raise Exception("either a pid or a binary path must be specified")

    def enable_probe(self, probe, fn_name):
        if lib.bcc_usdt_enable_probe(self.context, probe, fn_name) != 0:
            raise Exception("failed to enable probe '%s'" % probe)

    def get_text(self):
        return lib.bcc_usdt_genargs(self.context)

    def enumerate_probes(self):
        probes = []
        def _add_probe(probe):
            probes.append(USDTProbe(probe.contents))

        lib.bcc_usdt_foreach(self.context, _USDT_CB(_add_probe))
        return probes

    # This is called by the BPF module's __init__ when it realizes that there
    # is a USDT context and probes need to be attached.
    def attach_uprobes(self, bpf):
        probes = []
        def _add_probe(binpath, fn_name, addr, pid):
            probes.append((binpath, fn_name, addr, pid))

        lib.bcc_usdt_foreach_uprobe(self.context, _USDT_PROBE_CB(_add_probe))

        for (binpath, fn_name, addr, pid) in probes:
            bpf.attach_uprobe(name=binpath, fn_name=fn_name,
                              addr=addr, pid=pid)

