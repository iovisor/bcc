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
from collections import MutableMapping
import ctypes as ct
import json
import os
import sys
basestring = (unicode if sys.version_info[0] < 3 else str)

lib = ct.CDLL("libbpfprog.so")

# keep in sync with bpf_common.h
lib.bpf_module_create.restype = ct.c_void_p
lib.bpf_module_create.argtypes = [ct.c_char_p, ct.c_char_p, ct.c_uint]
lib.bpf_module_create_from_string.restype = ct.c_void_p
lib.bpf_module_create_from_string.argtypes = [ct.c_char_p, ct.c_uint]
lib.bpf_module_destroy.restype = None
lib.bpf_module_destroy.argtypes = [ct.c_void_p]
lib.bpf_module_license.restype = ct.c_char_p
lib.bpf_module_license.argtypes = [ct.c_void_p]
lib.bpf_module_kern_version.restype = ct.c_uint
lib.bpf_module_kern_version.argtypes = [ct.c_void_p]
lib.bpf_function_start.restype = ct.c_void_p
lib.bpf_function_start.argtypes = [ct.c_void_p, ct.c_char_p]
lib.bpf_function_size.restype = ct.c_size_t
lib.bpf_function_size.argtypes = [ct.c_void_p, ct.c_char_p]
lib.bpf_table_fd.restype = ct.c_int
lib.bpf_table_fd.argtypes = [ct.c_void_p, ct.c_char_p]
lib.bpf_table_key_desc.restype = ct.c_char_p
lib.bpf_table_key_desc.argtypes = [ct.c_void_p, ct.c_char_p]
lib.bpf_table_leaf_desc.restype = ct.c_char_p
lib.bpf_table_leaf_desc.argtypes = [ct.c_void_p, ct.c_char_p]

# keep in sync with libbpf.h
lib.bpf_get_next_key.restype = ct.c_int
lib.bpf_get_next_key.argtypes = [ct.c_int, ct.c_void_p, ct.c_void_p]
lib.bpf_lookup_elem.restype = ct.c_int
lib.bpf_lookup_elem.argtypes = [ct.c_int, ct.c_void_p, ct.c_void_p]
lib.bpf_update_elem.restype = ct.c_int
lib.bpf_update_elem.argtypes = [ct.c_int, ct.c_void_p, ct.c_void_p,
        ct.c_ulonglong]
lib.bpf_delete_elem.restype = ct.c_int
lib.bpf_delete_elem.argtypes = [ct.c_int, ct.c_void_p]
lib.bpf_open_raw_sock.restype = ct.c_int
lib.bpf_open_raw_sock.argtypes = [ct.c_char_p]
lib.bpf_attach_socket.restype = ct.c_int
lib.bpf_attach_socket.argtypes = [ct.c_int, ct.c_int]
lib.bpf_prog_load.restype = ct.c_int
lib.bpf_prog_load.argtypes = [ct.c_int, ct.c_void_p, ct.c_size_t,
        ct.c_char_p, ct.c_uint]
lib.bpf_attach_kprobe.restype = ct.c_int
lib.bpf_attach_kprobe.argtypes = [ct.c_int, ct.c_char_p, ct.c_char_p, ct.c_int, ct.c_int, ct.c_int]
lib.bpf_detach_kprobe.restype = ct.c_int
lib.bpf_detach_kprobe.argtypes = [ct.c_char_p]

open_kprobes = {}

@atexit.register
def cleanup_kprobes():
    for k, v in open_kprobes.items():
        os.close(v)
        desc = "-:kprobes/%s" % k
        lib.bpf_detach_kprobe(desc.encode("ascii"))

class BPF(object):
    SOCKET_FILTER = 1
    KPROBE = 2
    SCHED_CLS = 3
    SCHED_ACT = 4

    class Function(object):
        def __init__(self, bpf, name, fd):
            self.bpf = bpf
            self.name = name
            self.fd = fd

    class Table(MutableMapping):
        def __init__(self, bpf, map_fd, keytype, leaftype):
            self.bpf = bpf
            self.map_fd = map_fd
            self.Key = keytype
            self.Leaf = leaftype

        def __getitem__(self, key):
            key_p = ct.pointer(key)
            leaf = self.Leaf()
            leaf_p = ct.pointer(leaf)
            res = lib.bpf_lookup_elem(self.map_fd,
                    ct.cast(key_p, ct.c_void_p),
                    ct.cast(leaf_p, ct.c_void_p))
            if res < 0:
                raise KeyError
            return leaf

        def __setitem__(self, key, leaf):
            key_p = ct.pointer(key)
            leaf_p = ct.pointer(leaf)
            res = lib.bpf_update_elem(self.map_fd,
                    ct.cast(key_p, ct.c_void_p),
                    ct.cast(leaf_p, ct.c_void_p), 0)
            if res < 0:
                raise Exception("Could not update table")

        def __len__(self):
            i = 0
            for k in self: i += 1
            return i

        def __delitem__(self, key):
            key_p = ct.pointer(key)
            res = lib.bpf_delete_elem(self.map_fd, ct.cast(key_p, ct.c_void_p))
            if res < 0:
                raise KeyError

        def __iter__(self):
            return BPF.Table.Iter(self, self.Key)

        def iter(self): return self.__iter__()
        def keys(self): return self.__iter__()

        class Iter(object):
            def __init__(self, table, keytype):
                self.Key = keytype
                self.table = table
                self.key = self.Key()
            def __iter__(self):
                return self
            def __next__(self):
                return self.next()
            def next(self):
                self.key = self.table.next(self.key)
                return self.key

        def next(self, key):
            next_key = self.Key()
            next_key_p = ct.pointer(next_key)
            key_p = ct.pointer(key)
            res = lib.bpf_get_next_key(self.map_fd,
                    ct.cast(key_p, ct.c_void_p),
                    ct.cast(next_key_p, ct.c_void_p))
            if res < 0:
                raise StopIteration()
            return next_key

    def __init__(self, src_file="", hdr_file="", text=None, debug=0):
        self.debug = debug
        self.funcs = {}
        if text:
            self.module = lib.bpf_module_create_from_string(text.encode("ascii"), self.debug)
        else:
            self.module = lib.bpf_module_create(src_file.encode("ascii"),
                    hdr_file.encode("ascii"), self.debug)

        if self.module == None:
            raise Exception("Failed to compile BPF module %s" % src_file)

    def load_func(self, func_name, prog_type):
        if lib.bpf_function_start(self.module, func_name.encode("ascii")) == None:
            raise Exception("Unknown program %s" % func_name)

        fd = lib.bpf_prog_load(prog_type,
                lib.bpf_function_start(self.module, func_name.encode("ascii")),
                lib.bpf_function_size(self.module, func_name.encode("ascii")),
                lib.bpf_module_license(self.module),
                lib.bpf_module_kern_version(self.module))

        if fd < 0:
            print((ct.c_char * 65536).in_dll(lib, "bpf_log_buf").value)
            #print(ct.c_char_p.in_dll(lib, "bpf_log_buf").value)
            raise Exception("Failed to load BPF program %s" % func_name)

        fn = BPF.Function(self, func_name, fd)
        self.funcs[func_name] = fn

        return fn

    str2ctype = {
        u"_Bool": ct.c_bool,
        u"char": ct.c_char,
        u"wchar_t": ct.c_wchar,
        u"char": ct.c_byte,
        u"unsigned char": ct.c_ubyte,
        u"short": ct.c_short,
        u"unsigned short": ct.c_ushort,
        u"int": ct.c_int,
        u"unsigned int": ct.c_uint,
        u"long": ct.c_long,
        u"unsigned long": ct.c_ulong,
        u"long long": ct.c_longlong,
        u"unsigned long long": ct.c_ulonglong,
        u"float": ct.c_float,
        u"double": ct.c_double,
        u"long double": ct.c_longdouble
    }
    @staticmethod
    def _decode_table_type(desc):
        if isinstance(desc, basestring):
            return BPF.str2ctype[desc]
        fields = []
        for t in desc[1]:
            if len(t) == 2:
                fields.append((t[0], BPF._decode_table_type(t[1])))
            elif len(t) == 3:
                fields.append((t[0], BPF._decode_table_type(t[1]), t[2]))
        cls = type(str(desc[0]), (ct.Structure,), dict(_fields_=fields))
        return cls

    def get_table(self, name, keytype=None, leaftype=None):
        map_fd = lib.bpf_table_fd(self.module, name.encode("ascii"))
        if map_fd < 0:
            raise Exception("Failed to find BPF Table %s" % name)
        if not keytype:
            key_desc = lib.bpf_table_key_desc(self.module, name.encode("ascii"))
            if not key_desc:
                raise Exception("Failed to load BPF Table %s key desc" % name)
            keytype = BPF._decode_table_type(json.loads(key_desc.decode()))
        if not leaftype:
            leaf_desc = lib.bpf_table_leaf_desc(self.module, name.encode("ascii"))
            if not leaf_desc:
                raise Exception("Failed to load BPF Table %s leaf desc" % name)
            leaftype = BPF._decode_table_type(json.loads(leaf_desc.decode()))
        return BPF.Table(self, map_fd, keytype, leaftype)

    @staticmethod
    def attach_raw_socket(fn, dev):
        if not isinstance(fn, BPF.Function):
            raise Exception("arg 1 must be of type BPF.Function")
        sock = lib.bpf_open_raw_sock(dev.encode("ascii"))
        if sock < 0:
            errstr = os.strerror(ct.get_errno())
            raise Exception("Failed to open raw device %s: %s" % (dev, errstr))
        res = lib.bpf_attach_socket(sock, fn.fd)
        if res < 0:
            errstr = os.strerror(ct.get_errno())
            raise Exception("Failed to attach BPF to device %s: %s"
                    % (dev, errstr))
        fn.sock = sock

    @staticmethod
    def attach_kprobe(fn, event, pid=0, cpu=-1, group_fd=-1):
        if not isinstance(fn, BPF.Function):
            raise Exception("arg 1 must be of type BPF.Function")
        ev_name = "p_" + event.replace("+", "_")
        desc = "p:kprobes/%s %s" % (ev_name, event)
        res = lib.bpf_attach_kprobe(fn.fd, ev_name.encode("ascii"),
                desc.encode("ascii"), pid, cpu, group_fd)
        if res < 0:
            raise Exception("Failed to attach BPF to kprobe")
        open_kprobes[ev_name] = res
        return res

    @staticmethod
    def detach_kprobe(event):
        ev_name = "p_" + event.replace("+", "_")
        if ev_name not in open_kprobes:
            raise Exception("Kprobe %s is not attached" % event)
        os.close(open_kprobes[ev_name])
        desc = "-:kprobes/%s" % ev_name
        res = lib.bpf_detach_kprobe(desc.encode("ascii"))
        if res < 0:
            raise Exception("Failed to detach BPF from kprobe")
        del open_kprobes[ev_name]

    @staticmethod
    def attach_kretprobe(fn, event, pid=-1, cpu=0, group_fd=-1):
        if not isinstance(fn, BPF.Function):
            raise Exception("arg 1 must be of type BPF.Function")
        ev_name = "r_" + event.replace("+", "_")
        desc = "r:kprobes/%s %s" % (ev_name, event)
        res = lib.bpf_attach_kprobe(fn.fd, ev_name.encode("ascii"),
                desc.encode("ascii"), pid, cpu, group_fd)
        if res < 0:
            raise Exception("Failed to attach BPF to kprobe")
        open_kprobes[ev_name] = res
        return res

    @staticmethod
    def detach_kretprobe(event):
        ev_name = "r_" + event.replace("+", "_")
        if ev_name not in open_kprobes:
            raise Exception("Kretprobe %s is not attached" % event)
        os.close(open_kprobes[ev_name])
        desc = "-:kprobes/%s" % ev_name
        res = lib.bpf_detach_kprobe(desc.encode("ascii"))
        if res < 0:
            raise Exception("Failed to detach BPF from kprobe")
        del open_kprobes[ev_name]

