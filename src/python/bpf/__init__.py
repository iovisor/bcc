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

from __future__ import print_function
import atexit
from collections import MutableMapping
import ctypes as ct
import fcntl
import json
import os
from subprocess import Popen, PIPE
import sys
basestring = (unicode if sys.version_info[0] < 3 else str)

lib = ct.CDLL("libbcc.so")

# keep in sync with bpf_common.h
lib.bpf_module_create_b.restype = ct.c_void_p
lib.bpf_module_create_b.argtypes = [ct.c_char_p, ct.c_char_p, ct.c_uint]
lib.bpf_module_create_c.restype = ct.c_void_p
lib.bpf_module_create_c.argtypes = [ct.c_char_p, ct.c_uint]
lib.bpf_module_create_c_from_string.restype = ct.c_void_p
lib.bpf_module_create_c_from_string.argtypes = [ct.c_char_p, ct.c_uint]
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
lib.bpf_table_id.restype = ct.c_ulonglong
lib.bpf_table_id.argtypes = [ct.c_void_p, ct.c_char_p]
lib.bpf_table_fd.restype = ct.c_int
lib.bpf_table_fd.argtypes = [ct.c_void_p, ct.c_char_p]
lib.bpf_table_type_id.restype = ct.c_int
lib.bpf_table_type_id.argtypes = [ct.c_void_p, ct.c_ulonglong]
lib.bpf_table_key_desc.restype = ct.c_char_p
lib.bpf_table_key_desc.argtypes = [ct.c_void_p, ct.c_char_p]
lib.bpf_table_leaf_desc.restype = ct.c_char_p
lib.bpf_table_leaf_desc.argtypes = [ct.c_void_p, ct.c_char_p]
lib.bpf_table_key_snprintf.restype = ct.c_int
lib.bpf_table_key_snprintf.argtypes = [ct.c_void_p, ct.c_ulonglong,
        ct.c_char_p, ct.c_ulonglong, ct.c_void_p]
lib.bpf_table_leaf_snprintf.restype = ct.c_int
lib.bpf_table_leaf_snprintf.argtypes = [ct.c_void_p, ct.c_ulonglong,
        ct.c_char_p, ct.c_ulonglong, ct.c_void_p]
lib.bpf_table_key_sscanf.restype = ct.c_int
lib.bpf_table_key_sscanf.argtypes = [ct.c_void_p, ct.c_ulonglong,
        ct.c_char_p, ct.c_void_p]
lib.bpf_table_leaf_sscanf.restype = ct.c_int
lib.bpf_table_leaf_sscanf.argtypes = [ct.c_void_p, ct.c_ulonglong,
        ct.c_char_p, ct.c_void_p]

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
        ct.c_char_p, ct.c_uint, ct.c_char_p, ct.c_uint]
lib.bpf_attach_kprobe.restype = ct.c_int
lib.bpf_attach_kprobe.argtypes = [ct.c_int, ct.c_char_p,
        ct.c_char_p, ct.c_int, ct.c_int, ct.c_int]
lib.bpf_detach_kprobe.restype = ct.c_int
lib.bpf_detach_kprobe.argtypes = [ct.c_char_p]

open_kprobes = {}
tracefile = None
TRACEFS = "/sys/kernel/debug/tracing"

@atexit.register
def cleanup_kprobes():
    for k, v in open_kprobes.items():
        os.close(v)
        desc = "-:kprobes/%s" % k
        lib.bpf_detach_kprobe(desc.encode("ascii"))
    if tracefile:
        tracefile.close()

class BPF(object):
    SOCKET_FILTER = 1
    KPROBE = 2
    SCHED_CLS = 3
    SCHED_ACT = 4

    HASH = 1
    ARRAY = 2
    PROG_ARRAY = 3

    class Function(object):
        def __init__(self, bpf, name, fd):
            self.bpf = bpf
            self.name = name
            self.fd = fd

    class Table(MutableMapping):
        def __init__(self, bpf, map_id, map_fd, keytype, leaftype):
            self.bpf = bpf
            self.map_id = map_id
            self.map_fd = map_fd
            self.Key = keytype
            self.Leaf = leaftype
            self.ttype = lib.bpf_table_type_id(self.bpf.module, self.map_id)

        def key_sprintf(self, key):
            key_p = ct.pointer(key)
            buf = ct.create_string_buffer(ct.sizeof(self.Key) * 8)
            res = lib.bpf_table_key_snprintf(self.bpf.module, self.map_id,
                    buf, len(buf), key_p)
            if res < 0:
                raise Exception("Could not printf key")
            return buf.value

        def leaf_sprintf(self, leaf):
            leaf_p = ct.pointer(leaf)
            buf = ct.create_string_buffer(ct.sizeof(self.Leaf) * 8)
            res = lib.bpf_table_leaf_snprintf(self.bpf.module, self.map_id,
                    buf, len(buf), leaf_p)
            if res < 0:
                raise Exception("Could not printf leaf")
            return buf.value

        def key_scanf(self, key_str):
            key = self.Key()
            key_p = ct.pointer(key)
            res = lib.bpf_table_key_sscanf(self.bpf.module, self.map_id,
                    key_str, key_p)
            if res < 0:
                raise Exception("Could not scanf key")
            return key

        def leaf_scanf(self, leaf_str):
            leaf = self.Leaf()
            leaf_p = ct.pointer(leaf)
            res = lib.bpf_table_leaf_sscanf(self.bpf.module, self.map_id,
                    leaf_str, leaf_p)
            if res < 0:
                raise Exception("Could not scanf leaf")
            return leaf

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
            ttype = lib.bpf_table_type_id(self.bpf.module, self.map_id)
            # Deleting from array type maps does not have an effect, so
            # zero out the entry instead.
            if ttype in (BPF.ARRAY, BPF.PROG_ARRAY):
                leaf = self.Leaf()
                leaf_p = ct.pointer(leaf)
                res = lib.bpf_update_elem(self.map_fd,
                        ct.cast(key_p, ct.c_void_p),
                        ct.cast(leaf_p, ct.c_void_p), 0)
                if res < 0:
                    raise Exception("Could not clear item")
            else:
                res = lib.bpf_delete_elem(self.map_fd,
                        ct.cast(key_p, ct.c_void_p))
                if res < 0:
                    raise KeyError

        def clear(self):
            if self.ttype in (BPF.ARRAY, BPF.PROG_ARRAY):
                # Special case clear, since this class is currently behaving
                # like a dict but popitem on an array causes an infinite loop.
                # TODO: derive Table from array.array instead
                for k in self.keys():
                    self.__delitem__(k)
            else:
                super(BPF.Table, self).clear()


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

    @staticmethod
    def _find_file(filename):
        """ If filename is invalid, search in ./ of argv[0] """
        if filename:
            if not os.path.isfile(filename):
                t = "/".join([os.path.abspath(os.path.dirname(sys.argv[0])), filename])
                if os.path.isfile(t):
                    filename = t
                else:
                    raise Exception("Could not find file %s" % filename)
        return filename

    def __init__(self, src_file="", hdr_file="", text=None, debug=0):
        """Create a a new BPF module with the given source code.

        Note:
            All fields are marked as optional, but either `src_file` or `text`
            must be supplied, and not both.

        Args:
            src_file (Optional[str]): Path to a source file for the module
            hdr_file (Optional[str]): Path to a helper header file for the `src_file`
            text (Optional[str]): Contents of a source file for the module
            debug (Optional[int]): Flags used for debug prints, can be |'d together
                0x1: print LLVM IR to stderr
                0x2: print BPF bytecode to stderr
        """

        self.debug = debug
        self.funcs = {}
        self.tables = {}
        if text:
            self.module = lib.bpf_module_create_c_from_string(text.encode("ascii"), self.debug)
        else:
            src_file = BPF._find_file(src_file)
            hdr_file = BPF._find_file(hdr_file)
            if src_file.endswith(".b"):
                self.module = lib.bpf_module_create_b(src_file.encode("ascii"),
                        hdr_file.encode("ascii"), self.debug)
            else:
                self.module = lib.bpf_module_create_c(src_file.encode("ascii"),
                        self.debug)

        if self.module == None:
            raise Exception("Failed to compile BPF module %s" % src_file)

    def load_func(self, func_name, prog_type):
        if func_name in self.funcs:
            return self.funcs[func_name]

        if lib.bpf_function_start(self.module, func_name.encode("ascii")) == None:
            raise Exception("Unknown program %s" % func_name)

        log_buf = ct.create_string_buffer(65536) if self.debug else None

        fd = lib.bpf_prog_load(prog_type,
                lib.bpf_function_start(self.module, func_name.encode("ascii")),
                lib.bpf_function_size(self.module, func_name.encode("ascii")),
                lib.bpf_module_license(self.module),
                lib.bpf_module_kern_version(self.module),
                log_buf, ct.sizeof(log_buf) if log_buf else 0)

        if self.debug & 0x2:
            print(log_buf.value.decode(), file=sys.stderr)

        if fd < 0:
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
        map_id = lib.bpf_table_id(self.module, name.encode("ascii"))
        map_fd = lib.bpf_table_fd(self.module, name.encode("ascii"))
        if map_fd < 0:
            raise KeyError
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
        return BPF.Table(self, map_id, map_fd, keytype, leaftype)

    def __getitem__(self, key):
        if key not in self.tables:
            self.tables[key] = self.get_table(key)
        return self.tables[key]

    def __setitem__(self, key, leaf):
        self.tables[key] = leaf

    def __len__(self):
        return len(self.tables)

    def __delitem__(self, key):
        del self.tables[key]

    def __iter__(self):
        return self.tables.__iter__()

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
    def _get_kprobe_functions(event_re):
        p = Popen(["awk", "$1 ~ /%s/ { print $1 }" % event_re,
            "%s/available_filter_functions" % TRACEFS], stdout=PIPE)
        lines = p.communicate()[0].decode().split()
        return [line.rstrip() for line in lines if line != "\n"]

    def attach_kprobe(self, event="", fn_name="", event_re="",
            pid=0, cpu=-1, group_fd=-1):

        # allow the caller to glob multiple functions together
        if event_re:
            for line in BPF._get_kprobe_functions(event_re):
                self.attach_kprobe(event=line, fn_name=fn_name, pid=pid,
                        cpu=cpu, group_fd=group_fd)
            return

        fn = self.load_func(fn_name, BPF.KPROBE)
        ev_name = "p_" + event.replace("+", "_")
        desc = "p:kprobes/%s %s" % (ev_name, event)
        res = lib.bpf_attach_kprobe(fn.fd, ev_name.encode("ascii"),
                desc.encode("ascii"), pid, cpu, group_fd)
        if res < 0:
            raise Exception("Failed to attach BPF to kprobe")
        open_kprobes[ev_name] = res
        return self

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

    def attach_kretprobe(self, event="", fn_name="", event_re="",
            pid=-1, cpu=0, group_fd=-1):

        # allow the caller to glob multiple functions together
        if event_re:
            for line in BPF._get_kprobe_functions(event_re):
                self.attach_kretprobe(event=line, fn_name=fn_name, pid=pid,
                        cpu=cpu, group_fd=group_fd)
            return

        fn = self.load_func(fn_name, BPF.KPROBE)
        ev_name = "r_" + event.replace("+", "_")
        desc = "r:kprobes/%s %s" % (ev_name, event)
        res = lib.bpf_attach_kprobe(fn.fd, ev_name.encode("ascii"),
                desc.encode("ascii"), pid, cpu, group_fd)
        if res < 0:
            raise Exception("Failed to attach BPF to kprobe")
        open_kprobes[ev_name] = res
        return self

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

    @staticmethod
    def trace_open(nonblocking=False):
        """trace_open(nonblocking=False)

        Open the trace_pipe if not already open
        """

        global tracefile
        if not tracefile:
            tracefile = open("%s/trace_pipe" % TRACEFS)
            if nonblocking:
                fd = tracefile.fileno()
                fl = fcntl.fcntl(fd, fcntl.F_GETFL)
                fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        return tracefile

    @staticmethod
    def trace_readline_fields(nonblocking=False):
        """trace_readline_fields(nonblocking=False)

        Read from the kernel debug trace pipe and return a tuple of the
        fields (task, pid, cpu, flags, timestamp, msg) or None if no
        line was read (nonblocking=True)
        """
        line = BPF.trace_readline(nonblocking)
        if line:
            # don't print messages related to lost events
            if line.startswith("CPU:"): return
            task = line[:16].lstrip()
            line = line[17:]
            ts_end = line.find(":")
            pid, cpu, flags, ts = line[:ts_end].split()
            cpu = cpu[1:-1]
            msg = line[ts_end + 4:]
            return (task, int(pid), int(cpu), flags, float(ts), msg)
        return

    @staticmethod
    def trace_readline(nonblocking=False):
        """trace_readline(nonblocking=False)

        Read from the kernel debug trace pipe and return one line
        If nonblocking is False, this will block until ctrl-C is pressed.
        """

        trace = BPF.trace_open(nonblocking)

        line = None
        try:
            line = trace.readline(1024).rstrip()
        except IOError:
            pass
        except KeyboardInterrupt:
            exit()
        return line

    @staticmethod
    def trace_print(fmt=None):
        """trace_print(fmt=None)

        Read from the kernel debug trace pipe and print on stdout.
        If fmt is specified, apply as a format string to the output. See
        trace_readline_fields for the members of the tuple
        example: trace_print(fmt="pid {1}, msg = {5}")
        """

        while True:
            if fmt:
                fields = BPF.trace_readline_fields(nonblocking=False)
                if not fields: continue
                line = fmt.format(*fields)
            else:
                line = BPF.trace_readline(nonblocking=False)
            print(line)
            sys.stdout.flush()
