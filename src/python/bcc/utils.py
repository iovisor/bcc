# Copyright 2016 Catalysts GmbH
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
import sys
import traceback
import warnings

from .libbcc import lib, bcc_symbol_option

class SymbolCache(object):
    def __init__(self, pid):
        self.cache = lib.bcc_symcache_new(
                pid, ct.cast(None, ct.POINTER(bcc_symbol_option)))

    def resolve(self, addr, demangle):
        """
        Return a tuple of the symbol (function), its offset from the beginning
        of the function, and the module in which it lies. For example:
            ("start_thread", 0x202, "/usr/lib/.../libpthread-2.24.so")
        If the symbol cannot be found but we know which module it is in,
        return the module name and the offset from the beginning of the
        module. If we don't even know the module, return the absolute
        address as the offset.
        """
        sym = bcc_symbol()
        if demangle:
            res = lib.bcc_symcache_resolve(self.cache, addr, ct.byref(sym))
        else:
            res = lib.bcc_symcache_resolve_no_demangle(self.cache, addr,
                                                       ct.byref(sym))
        if res < 0:
            if sym.module and sym.offset:
                return (None, sym.offset,
                        ct.cast(sym.module, ct.c_char_p).value)
            return (None, addr, None)
        if demangle:
            name_res = sym.demangle_name
            lib.bcc_symbol_free_demangle_name(ct.byref(sym))
        else:
            name_res = sym.name
        return (name_res, sym.offset, ct.cast(sym.module, ct.c_char_p).value)

    def resolve_name(self, module, name):
        module = _assert_is_bytes(module)
        name = _assert_is_bytes(name)
        addr = ct.c_ulonglong()
        if lib.bcc_symcache_resolve_name(self.cache, module, name,
                ct.byref(addr)) < 0:
            return -1
        return addr.value


def _read_cpu_range(path):
    cpus = []
    with open(path, 'r') as f:
        cpus_range_str = f.read()
        for cpu_range in cpus_range_str.split(','):
            rangeop = cpu_range.find('-')
            if rangeop == -1:
                cpus.append(int(cpu_range))
            else:
                start = int(cpu_range[:rangeop])
                end = int(cpu_range[rangeop+1:])
                cpus.extend(range(start, end+1))
    return cpus

def get_online_cpus():
    return _read_cpu_range('/sys/devices/system/cpu/online')

def get_possible_cpus():
    return _read_cpu_range('/sys/devices/system/cpu/possible')

def detect_language(candidates, pid):
    res = lib.bcc_procutils_language(pid)
    language = ct.cast(res, ct.c_char_p).value.decode()
    return language if language in candidates else None

FILESYSTEMENCODING = sys.getfilesystemencoding()

def printb(s, file=sys.stdout):
    """
    printb(s)

    print a bytes object to stdout and flush
    """
    buf = file.buffer if hasattr(file, "buffer") else file

    buf.write(s)
    buf.write(b"\n")
    file.flush()

class ArgString(object):
    """
    ArgString(arg)

    encapsulate a system argument that can be easily coerced to a bytes()
    object, which is better for comparing to kernel or probe data (which should
    never be en/decode()'ed).
    """
    def __init__(self, arg):
        if sys.version_info[0] >= 3:
            self.s = arg
        else:
            self.s = arg.decode(FILESYSTEMENCODING)

    def __bytes__(self):
        return self.s.encode(FILESYSTEMENCODING)

    def __str__(self):
        return self.__bytes__()

def warn_with_traceback(message, category, filename, lineno, file=None, line=None):
    log = file if hasattr(file, "write") else sys.stderr
    traceback.print_stack(f=sys._getframe(2), file=log)
    log.write(warnings.formatwarning(message, category, filename, lineno, line))

# uncomment to get full tracebacks for invalid uses of python3+str in arguments
#warnings.showwarning = warn_with_traceback

_strict_bytes = False
def _assert_is_bytes(arg):
    if arg is None:
        return arg
    if _strict_bytes:
        assert type(arg) is bytes, "not a bytes object: %r" % arg
    elif type(arg) is not bytes:
        warnings.warn("not a bytes object: %r" % arg, DeprecationWarning, 2)
        return ArgString(arg).__bytes__()
    return arg
def get_syscall_prefix():
    # test bpf syscall kernel func name
    ksyms = SymbolCache(-1)
    if ksyms.resolve_name(None, "sys_bpf") != -1:
        return "sys_"
    if ksyms.resolve_name(None, "__x64_sys_bpf") != -1:
        return "__x64_sys_"
    # none of them, just return "sys_", later api
    # calls will return error
    return "sys_"
