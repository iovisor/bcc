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
import ctypes as ct
from .libbcc import lib, bcc_symbol

class ProcessSymbols(object):
    def __init__(self, pid):
        """
        Initializes the process symbols store for the specified pid.
        Call refresh_code_ranges() periodically if you anticipate changes
        in the set of loaded libraries or their addresses.
        """
        self.cache = lib.bcc_symcache_new(pid)

    def refresh_code_ranges(self):
        lib.bcc_symcache_refresh(self.cache)

    def decode_addr(self, addr):
        """
        Given an address, return the best symbolic representation of it.
        If it doesn't fall in any module, return its hex string. If it
        falls within a module but we don't have a symbol for it, return
        the hex string and the module. If we do have a symbol for it,
        return the symbol and the module, e.g. "readline+0x10 [bash]".
        """
        sym = bcc_symbol()
        psym = ct.pointer(sym)
        if lib.bcc_symcache_resolve(self.cache, addr, psym) < 0:
            if sym.module and sym.offset:
                return "0x%x [%s]" % (sym.offset, sym.module)
            return "%x" % addr
        return "%s+0x%x [%s]" % (sym.name, sym.offset, sym.module)
