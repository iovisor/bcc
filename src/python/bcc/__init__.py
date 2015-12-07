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
import multiprocessing
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
lib.bpf_num_functions.restype = ct.c_ulonglong
lib.bpf_num_functions.argtypes = [ct.c_void_p]
lib.bpf_function_name.restype = ct.c_char_p
lib.bpf_function_name.argtypes = [ct.c_void_p, ct.c_ulonglong]
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
lib.bpf_attach_kprobe.restype = ct.c_void_p
_CB_TYPE = ct.CFUNCTYPE(None, ct.py_object, ct.c_int,
        ct.c_ulonglong, ct.POINTER(ct.c_ulonglong))
_RAW_CB_TYPE = ct.CFUNCTYPE(None, ct.py_object, ct.c_void_p, ct.c_int)
lib.bpf_attach_kprobe.argtypes = [ct.c_int, ct.c_char_p, ct.c_char_p, ct.c_int,
        ct.c_int, ct.c_int, _CB_TYPE, ct.py_object]
lib.bpf_detach_kprobe.restype = ct.c_int
lib.bpf_detach_kprobe.argtypes = [ct.c_char_p]
lib.bpf_open_perf_buffer.restype = ct.c_void_p
lib.bpf_open_perf_buffer.argtypes = [_RAW_CB_TYPE, ct.py_object, ct.c_int, ct.c_int]
lib.perf_reader_poll.restype = ct.c_int
lib.perf_reader_poll.argtypes = [ct.c_int, ct.POINTER(ct.c_void_p), ct.c_int]
lib.perf_reader_free.restype = None
lib.perf_reader_free.argtypes = [ct.c_void_p]
lib.perf_reader_fd.restype = int
lib.perf_reader_fd.argtypes = [ct.c_void_p]

open_kprobes = {}
tracefile = None
TRACEFS = "/sys/kernel/debug/tracing"
KALLSYMS = "/proc/kallsyms"
ksym_addrs = []
ksym_names = []
ksym_loaded = 0
stars_max = 40

@atexit.register
def cleanup_kprobes():
    for k, v in open_kprobes.items():
        lib.perf_reader_free(v)
        if isinstance(k, str):
            desc = "-:kprobes/%s" % k
            lib.bpf_detach_kprobe(desc.encode("ascii"))
    open_kprobes.clear()
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
    PERF_EVENT_ARRAY = 4

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
            self._cbs = {}

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

        def open_perf_buffer(self, callback):
            """open_perf_buffers(callback)

            Opens a set of per-cpu ring buffer to receive custom perf event
            data from the bpf program. The callback will be invoked for each
            event submitted from the kernel, up to millions per second.
            """

            for i in range(0, multiprocessing.cpu_count()):
                self._open_perf_buffer(i, callback)

        def _open_perf_buffer(self, cpu, callback):
            fn = _RAW_CB_TYPE(lambda _, data, size: callback(cpu, data, size))
            reader = lib.bpf_open_perf_buffer(fn, None, -1, cpu)
            if not reader:
                raise Exception("Could not open perf buffer")
            fd = lib.perf_reader_fd(reader)
            self[self.Key(cpu)] = self.Leaf(fd)
            open_kprobes[(id(self), cpu)] = reader
            # keep a refcnt
            self._cbs[cpu] = fn

        def close_perf_buffer(self, key):
            reader = open_kprobes.get((id(self), key))
            if reader:
                lib.perf_reader_free(reader)
                del(open_kprobes[(id(self), key)])
            del self._cbs[key]

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
            if ttype in (BPF.ARRAY, BPF.PROG_ARRAY, BPF.PERF_EVENT_ARRAY):
                leaf = self.Leaf()
                leaf_p = ct.pointer(leaf)
                res = lib.bpf_update_elem(self.map_fd,
                        ct.cast(key_p, ct.c_void_p),
                        ct.cast(leaf_p, ct.c_void_p), 0)
                if res < 0:
                    raise Exception("Could not clear item")
                if ttype == BPF.PERF_EVENT_ARRAY:
                    self.close_perf_buffer(key)
            else:
                res = lib.bpf_delete_elem(self.map_fd,
                        ct.cast(key_p, ct.c_void_p))
                if res < 0:
                    raise KeyError

        def clear(self):
            # default clear uses popitem, which can race with the bpf prog
            for k in self.keys():
                self.__delitem__(k)

        @staticmethod
        def _stars(val, val_max, width):
            i = 0
            text = ""
            while (1):
                if (i > (width * val / val_max) - 1) or (i > width - 1):
                    break
                text += "*"
                i += 1
            if val > val_max:
                text = text[:-1] + "+"
            return text

        def print_log2_hist(self, val_type="value", section_header="Bucket ptr",
                section_print_fn=None):
            """print_log2_hist(val_type="value", section_header="Bucket ptr",
                               section_print_fn=None)

            Prints a table as a log2 histogram. The table must be stored as
            log2. The val_type argument is optional, and is a column header.
            If the histogram has a secondary key, multiple tables will print
            and section_header can be used as a header description for each.
            If section_print_fn is not None, it will be passed the bucket value
            to format into a string as it sees fit.
            """
            if isinstance(self.Key(), ct.Structure):
                tmp = {}
                f1 = self.Key._fields_[0][0]
                f2 = self.Key._fields_[1][0]
                for k, v in self.items():
                    bucket = getattr(k, f1)
                    vals = tmp[bucket] = tmp.get(bucket, [0] * 65)
                    slot = getattr(k, f2)
                    vals[slot] = v.value
                for bucket, vals in tmp.items():
                    if section_print_fn:
                        print("\n%s = %s" % (section_header,
                            section_print_fn(bucket)))
                    else:
                        print("\n%s = %r" % (section_header, bucket))
                    self._print_log2_hist(vals, val_type, 0)
            else:
                vals = [0] * 65
                for k, v in self.items():
                    vals[k.value] = v.value
                self._print_log2_hist(vals, val_type, 0)

        def _print_log2_hist(self, vals, val_type, val_max):
            global stars_max
            log2_dist_max = 64
            idx_max = -1

            for i, v in enumerate(vals):
                if v > 0: idx_max = i
                if v > val_max: val_max = v

            if idx_max <= 32:
                header = "     %-19s : count     distribution"
                body = "%10d -> %-10d : %-8d |%-*s|"
                stars = stars_max
            else:
                header = "               %-29s : count     distribution"
                body = "%20d -> %-20d : %-8d |%-*s|"
                stars = int(stars_max / 2)

            if idx_max > 0:
                print(header % val_type);
            for i in range(1, idx_max + 1):
                low = (1 << i) >> 1
                high = (1 << i) - 1
                if (low == high):
                    low -= 1
                val = vals[i]
                print(body % (low, high, val, stars,
                              self._stars(val, val_max, stars)))


        def __iter__(self):
            return BPF.Table.Iter(self, self.Key)

        def iter(self): return self.__iter__()
        def keys(self): return self.__iter__()

        class Iter(object):
            def __init__(self, table, keytype):
                self.Key = keytype
                self.table = table
                k = self.Key()
                kp = ct.pointer(k)
                # if 0 is a valid key, try a few alternatives
                if k in table:
                    ct.memset(kp, 0xff, ct.sizeof(k))
                    if k in table:
                        ct.memset(kp, 0x55, ct.sizeof(k))
                        if k in table:
                            raise Exception("Unable to allocate iterator")
                self.key = k
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

    def __init__(self, src_file="", hdr_file="", text=None, cb=None, debug=0):
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

        self._reader_cb_impl = _CB_TYPE(BPF._reader_cb)
        self._user_cb = cb
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

        # If any "kprobe__" prefixed functions were defined, they will be
        # loaded and attached here.
        self._trace_autoload()

    def load_funcs(self, prog_type=KPROBE):
        """load_funcs(prog_type=KPROBE)

        Load all functions in this BPF module with the given type.
        Returns a list of the function handles."""

        fns = []
        for i in range(0, lib.bpf_num_functions(self.module)):
            func_name = lib.bpf_function_name(self.module, i).decode()
            fns.append(self.load_func(func_name, prog_type))

        return fns

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

    def dump_func(self, func_name):
        """
        Return the eBPF bytecodes for the specified function as a string
        """
        if lib.bpf_function_start(self.module, func_name.encode("ascii")) == None:
            raise Exception("Unknown program %s" % func_name)

        start, = lib.bpf_function_start(self.module, func_name.encode("ascii")),
        size, = lib.bpf_function_size(self.module, func_name.encode("ascii")),
        return ct.string_at(start, size)

    str2ctype = {
        u"_Bool": ct.c_bool,
        u"char": ct.c_char,
        u"wchar_t": ct.c_wchar,
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
                if isinstance(t[2], list):
                    fields.append((t[0], BPF._decode_table_type(t[1]) * t[2][0]))
                else:
                    fields.append((t[0], BPF._decode_table_type(t[1]), t[2]))
            else:
                raise Exception("Failed to decode type %s" % str(t))
        base = ct.Structure
        if len(desc) > 2:
            if desc[2] == u"union":
                base = ct.Union
            elif desc[2] == u"struct":
                base = ct.Structure
        cls = type(str(desc[0]), (base,), dict(_fields_=fields))
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

    def _reader_cb(self, pid, callchain_num, callchain):
        if self._user_cb:
            cc = tuple(callchain[i] for i in range(0, callchain_num))
            self._user_cb(pid, cc)

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
        with open("%s/../kprobes/blacklist" % TRACEFS) as f:
            blacklist = [line.split()[1] for line in f.readlines()]
        return [line.rstrip() for line in lines if
                (line != "\n" and line not in blacklist)]

    def attach_kprobe(self, event="", fn_name="", event_re="",
            pid=-1, cpu=0, group_fd=-1):

        # allow the caller to glob multiple functions together
        if event_re:
            for line in BPF._get_kprobe_functions(event_re):
                try:
                    self.attach_kprobe(event=line, fn_name=fn_name, pid=pid,
                            cpu=cpu, group_fd=group_fd)
                except:
                    pass
            return

        fn = self.load_func(fn_name, BPF.KPROBE)
        ev_name = "p_" + event.replace("+", "_").replace(".", "_")
        desc = "p:kprobes/%s %s" % (ev_name, event)
        res = lib.bpf_attach_kprobe(fn.fd, ev_name.encode("ascii"),
                desc.encode("ascii"), pid, cpu, group_fd,
                self._reader_cb_impl, ct.cast(id(self), ct.py_object))
        res = ct.cast(res, ct.c_void_p)
        if res == None:
            raise Exception("Failed to attach BPF to kprobe")
        open_kprobes[ev_name] = res
        return self

    @staticmethod
    def detach_kprobe(event):
        ev_name = "p_" + event.replace("+", "_").replace(".", "_")
        if ev_name not in open_kprobes:
            raise Exception("Kprobe %s is not attached" % event)
        lib.perf_reader_free(open_kprobes[ev_name])
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
                try:
                    self.attach_kretprobe(event=line, fn_name=fn_name, pid=pid,
                            cpu=cpu, group_fd=group_fd)
                except:
                    pass
            return

        fn = self.load_func(fn_name, BPF.KPROBE)
        ev_name = "r_" + event.replace("+", "_").replace(".", "_")
        desc = "r:kprobes/%s %s" % (ev_name, event)
        res = lib.bpf_attach_kprobe(fn.fd, ev_name.encode("ascii"),
                desc.encode("ascii"), pid, cpu, group_fd,
                self._reader_cb_impl, ct.cast(id(self), ct.py_object))
        res = ct.cast(res, ct.c_void_p)
        if res == None:
            raise Exception("Failed to attach BPF to kprobe")
        open_kprobes[ev_name] = res
        return self

    @staticmethod
    def detach_kretprobe(event):
        ev_name = "r_" + event.replace("+", "_").replace(".", "_")
        if ev_name not in open_kprobes:
            raise Exception("Kretprobe %s is not attached" % event)
        lib.perf_reader_free(open_kprobes[ev_name])
        desc = "-:kprobes/%s" % ev_name
        res = lib.bpf_detach_kprobe(desc.encode("ascii"))
        if res < 0:
            raise Exception("Failed to detach BPF from kprobe")
        del open_kprobes[ev_name]

    def _trace_autoload(self):
        # Cater to one-liner case where attach_kprobe is omitted and C function
        # name matches that of the kprobe.
        if len(open_kprobes) == 0:
            for i in range(0, lib.bpf_num_functions(self.module)):
                func_name = lib.bpf_function_name(self.module, i).decode()
                if func_name.startswith("kprobe__"):
                    fn = self.load_func(func_name, BPF.KPROBE)
                    self.attach_kprobe(event=fn.name[8:], fn_name=fn.name)
                elif func_name.startswith("kretprobe__"):
                    fn = self.load_func(func_name, BPF.KPROBE)
                    self.attach_kretprobe(event=fn.name[11:], fn_name=fn.name)

    def trace_open(self, nonblocking=False):
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

    def trace_fields(self, nonblocking=False):
        """trace_fields(nonblocking=False)

        Read from the kernel debug trace pipe and return a tuple of the
        fields (task, pid, cpu, flags, timestamp, msg) or None if no
        line was read (nonblocking=True)
        """
        try:
            while True:
                line = self.trace_readline(nonblocking)
                if not line and nonblocking: return (None,) * 6
                # don't print messages related to lost events
                if line.startswith("CPU:"): continue
                task = line[:16].lstrip()
                line = line[17:]
                ts_end = line.find(":")
                pid, cpu, flags, ts = line[:ts_end].split()
                cpu = cpu[1:-1]
                msg = line[ts_end + 4:]
                return (task, int(pid), int(cpu), flags, float(ts), msg)
        except KeyboardInterrupt:
            exit()

    def trace_readline(self, nonblocking=False):
        """trace_readline(nonblocking=False)

        Read from the kernel debug trace pipe and return one line
        If nonblocking is False, this will block until ctrl-C is pressed.
        """

        trace = self.trace_open(nonblocking)

        line = None
        try:
            line = trace.readline(1024).rstrip()
        except IOError:
            pass
        except KeyboardInterrupt:
            exit()
        return line

    def trace_print(self, fmt=None):
        """trace_print(self, fmt=None)

        Read from the kernel debug trace pipe and print on stdout.
        If fmt is specified, apply as a format string to the output. See
        trace_fields for the members of the tuple
        example: trace_print(fmt="pid {1}, msg = {5}")
        """

        try:
            while True:
                if fmt:
                    fields = self.trace_fields(nonblocking=False)
                    if not fields: continue
                    line = fmt.format(*fields)
                else:
                    line = self.trace_readline(nonblocking=False)
                print(line)
                sys.stdout.flush()
        except KeyboardInterrupt:
            exit()

    @staticmethod
    def _load_kallsyms():
        global ksym_loaded, ksym_addrs, ksym_names
        if ksym_loaded:
            return
        try:
            syms = open(KALLSYMS, "r")
        except:
            raise Exception("Could not read %s" % KALLSYMS)
        line = syms.readline()
        for line in iter(syms):
            cols = line.split()
            name = cols[2]
            addr = int(cols[0], 16)
            ksym_addrs.append(addr)
            ksym_names.append(name)
        syms.close()
        ksym_loaded = 1

    @staticmethod
    def _ksym_addr2index(addr):
        global ksym_addrs
        start = -1
        end = len(ksym_addrs)
        while end != start + 1:
            mid = int((start + end) / 2)
            if addr < ksym_addrs[mid]:
                end = mid
            else:
                start = mid
        return start

    @staticmethod
    def ksym(addr):
        """ksym(addr)

        Translate a kernel memory address into a kernel function name, which is
        returned. This is a simple translator that uses /proc/kallsyms.
        """
        global ksym_names
        BPF._load_kallsyms()
        idx = BPF._ksym_addr2index(addr)
        if idx == -1:
            return "[unknown]"
        return ksym_names[idx]

    @staticmethod
    def ksymaddr(addr):
        """ksymaddr(addr)

        Translate a kernel memory address into a kernel function name plus the
        instruction offset as a hexidecimal number, which is returned as a
        string. This is a simple translator that uses /proc/kallsyms.
        """
        global ksym_addrs, ksym_names
        BPF._load_kallsyms()
        idx = BPF._ksym_addr2index(addr)
        if idx == -1:
            return "[unknown]"
        offset = int(addr - ksym_addrs[idx])
        return ksym_names[idx] + hex(offset)

    @staticmethod
    def num_open_kprobes():
        """num_open_kprobes()

        Get the number of open K[ret]probes. Can be useful for scenarios where
        event_re is used while attaching and detaching probes
        """
        return len(open_kprobes)

    def kprobe_poll(self, timeout = -1):
        """kprobe_poll(self)

        Poll from the ring buffers for all of the open kprobes, calling the
        cb() that was given in the BPF constructor for each entry.
        """
        try:
            readers = (ct.c_void_p * len(open_kprobes))()
            for i, v in enumerate(open_kprobes.values()):
                readers[i] = v
            lib.perf_reader_poll(len(open_kprobes), readers, timeout)
        except KeyboardInterrupt:
            exit()

