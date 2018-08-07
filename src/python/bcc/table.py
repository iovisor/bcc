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

from collections import MutableMapping
import ctypes as ct
from functools import reduce
import multiprocessing
import os
import errno

from .libbcc import lib, _RAW_CB_TYPE, _LOST_CB_TYPE
from .perf import Perf
from .utils import get_online_cpus
from .utils import get_possible_cpus
from subprocess import check_output

BPF_MAP_TYPE_HASH = 1
BPF_MAP_TYPE_ARRAY = 2
BPF_MAP_TYPE_PROG_ARRAY = 3
BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4
BPF_MAP_TYPE_PERCPU_HASH = 5
BPF_MAP_TYPE_PERCPU_ARRAY = 6
BPF_MAP_TYPE_STACK_TRACE = 7
BPF_MAP_TYPE_CGROUP_ARRAY = 8
BPF_MAP_TYPE_LRU_HASH = 9
BPF_MAP_TYPE_LRU_PERCPU_HASH = 10
BPF_MAP_TYPE_LPM_TRIE = 11
BPF_MAP_TYPE_ARRAY_OF_MAPS = 12
BPF_MAP_TYPE_HASH_OF_MAPS = 13
BPF_MAP_TYPE_DEVMAP = 14
BPF_MAP_TYPE_SOCKMAP = 15
BPF_MAP_TYPE_CPUMAP = 16
BPF_MAP_TYPE_XSKMAP = 17
BPF_MAP_TYPE_SOCKHASH = 18

stars_max = 40
log2_index_max = 65
linear_index_max = 1025

# helper functions, consider moving these to a utils module
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


def _print_log2_hist(vals, val_type, strip_leading_zero):
    global stars_max
    log2_dist_max = 64
    idx_max = -1
    val_max = 0

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
        print(header % val_type)

    for i in range(1, idx_max + 1):
        low = (1 << i) >> 1
        high = (1 << i) - 1
        if (low == high):
            low -= 1
        val = vals[i]

        if strip_leading_zero:
            if val:
                print(body % (low, high, val, stars,
                              _stars(val, val_max, stars)))
                strip_leading_zero = False
        else:
            print(body % (low, high, val, stars,
                          _stars(val, val_max, stars)))

def _print_linear_hist(vals, val_type):
    global stars_max
    log2_dist_max = 64
    idx_max = -1
    val_max = 0

    for i, v in enumerate(vals):
        if v > 0: idx_max = i
        if v > val_max: val_max = v

    header = "     %-13s : count     distribution"
    body = "        %-10d : %-8d |%-*s|"
    stars = stars_max

    if idx_max >= 0:
        print(header % val_type);
    for i in range(0, idx_max + 1):
        val = vals[i]
        print(body % (i, val, stars,
                      _stars(val, val_max, stars)))


def Table(bpf, map_id, map_fd, keytype, leaftype, **kwargs):
    """Table(bpf, map_id, map_fd, keytype, leaftype, **kwargs)

    Create a python object out of a reference to a bpf table handle"""

    ttype = lib.bpf_table_type_id(bpf.module, map_id)
    t = None
    if ttype == BPF_MAP_TYPE_HASH:
        t = HashTable(bpf, map_id, map_fd, keytype, leaftype)
    elif ttype == BPF_MAP_TYPE_ARRAY:
        t = Array(bpf, map_id, map_fd, keytype, leaftype)
    elif ttype == BPF_MAP_TYPE_PROG_ARRAY:
        t = ProgArray(bpf, map_id, map_fd, keytype, leaftype)
    elif ttype == BPF_MAP_TYPE_PERF_EVENT_ARRAY:
        t = PerfEventArray(bpf, map_id, map_fd, keytype, leaftype)
    elif ttype == BPF_MAP_TYPE_PERCPU_HASH:
        t = PerCpuHash(bpf, map_id, map_fd, keytype, leaftype, **kwargs)
    elif ttype == BPF_MAP_TYPE_PERCPU_ARRAY:
        t = PerCpuArray(bpf, map_id, map_fd, keytype, leaftype, **kwargs)
    elif ttype == BPF_MAP_TYPE_LPM_TRIE:
        t = LpmTrie(bpf, map_id, map_fd, keytype, leaftype)
    elif ttype == BPF_MAP_TYPE_STACK_TRACE:
        t = StackTrace(bpf, map_id, map_fd, keytype, leaftype)
    elif ttype == BPF_MAP_TYPE_LRU_HASH:
        t = LruHash(bpf, map_id, map_fd, keytype, leaftype)
    elif ttype == BPF_MAP_TYPE_LRU_PERCPU_HASH:
        t = LruPerCpuHash(bpf, map_id, map_fd, keytype, leaftype)
    elif ttype == BPF_MAP_TYPE_CGROUP_ARRAY:
        t = CgroupArray(bpf, map_id, map_fd, keytype, leaftype)
    elif ttype == BPF_MAP_TYPE_DEVMAP:
        t = DevMap(bpf, map_id, map_fd, keytype, leaftype)
    elif ttype == BPF_MAP_TYPE_CPUMAP:
        t = CpuMap(bpf, map_id, map_fd, keytype, leaftype)
    if t == None:
        raise Exception("Unknown table type %d" % ttype)
    return t


class TableBase(MutableMapping):

    def __init__(self, bpf, map_id, map_fd, keytype, leaftype):
        self.bpf = bpf
        self.map_id = map_id
        self.map_fd = map_fd
        self.Key = keytype
        self.Leaf = leaftype
        self.ttype = lib.bpf_table_type_id(self.bpf.module, self.map_id)
        self.flags = lib.bpf_table_flags_id(self.bpf.module, self.map_id)
        self._cbs = {}

    def key_sprintf(self, key):
        buf = ct.create_string_buffer(ct.sizeof(self.Key) * 8)
        res = lib.bpf_table_key_snprintf(self.bpf.module, self.map_id, buf,
                                         len(buf), ct.byref(key))
        if res < 0:
            raise Exception("Could not printf key")
        return buf.value

    def leaf_sprintf(self, leaf):
        buf = ct.create_string_buffer(ct.sizeof(self.Leaf) * 8)
        res = lib.bpf_table_leaf_snprintf(self.bpf.module, self.map_id, buf,
                                          len(buf), ct.byref(leaf))
        if res < 0:
            raise Exception("Could not printf leaf")
        return buf.value

    def key_scanf(self, key_str):
        key = self.Key()
        res = lib.bpf_table_key_sscanf(self.bpf.module, self.map_id, key_str,
                                       ct.byref(key))
        if res < 0:
            raise Exception("Could not scanf key")
        return key

    def leaf_scanf(self, leaf_str):
        leaf = self.Leaf()
        res = lib.bpf_table_leaf_sscanf(self.bpf.module, self.map_id, leaf_str,
                                        ct.byref(leaf))
        if res < 0:
            raise Exception("Could not scanf leaf")
        return leaf

    def __getitem__(self, key):
        leaf = self.Leaf()
        res = lib.bpf_lookup_elem(self.map_fd, ct.byref(key), ct.byref(leaf))
        if res < 0:
            raise KeyError
        return leaf

    def __setitem__(self, key, leaf):
        res = lib.bpf_update_elem(self.map_fd, ct.byref(key), ct.byref(leaf), 0)
        if res < 0:
            errstr = os.strerror(ct.get_errno())
            raise Exception("Could not update table: %s" % errstr)

    def __delitem__(self, key):
        res = lib.bpf_delete_elem(self.map_fd, ct.byref(key))
        if res < 0:
            raise KeyError

    # override the MutableMapping's implementation of these since they
    # don't handle KeyError nicely
    def itervalues(self):
        for key in self:
            # a map entry may be deleted in between discovering the key and
            # fetching the value, suppress such errors
            try:
                yield self[key]
            except KeyError:
                pass

    def iteritems(self):
        for key in self:
            try:
                yield (key, self[key])
            except KeyError:
                pass

    def items(self):
        return [item for item in self.iteritems()]

    def values(self):
        return [value for value in self.itervalues()]

    def clear(self):
        # default clear uses popitem, which can race with the bpf prog
        for k in self.keys():
            self.__delitem__(k)

    def zero(self):
        # Even though this is not very efficient, we grab the entire list of
        # keys before enumerating it. This helps avoid a potential race where
        # the leaf assignment changes a hash table bucket that is being
        # enumerated by the same loop, and may lead to a hang.
        for k in list(self.keys()):
            self[k] = self.Leaf()

    def __iter__(self):
        return TableBase.Iter(self)

    def iter(self): return self.__iter__()
    def keys(self): return self.__iter__()

    class Iter(object):
        def __init__(self, table):
            self.table = table
            self.key = None
        def __iter__(self):
            return self
        def __next__(self):
            return self.next()
        def next(self):
            self.key = self.table.next(self.key)
            return self.key

    def next(self, key):
        next_key = self.Key()

        if key is None:
            res = lib.bpf_get_first_key(self.map_fd, ct.byref(next_key),
                                        ct.sizeof(self.Key))
        else:
            res = lib.bpf_get_next_key(self.map_fd, ct.byref(key),
                                       ct.byref(next_key))

        if res < 0:
            raise StopIteration()
        return next_key

    def print_log2_hist(self, val_type="value", section_header="Bucket ptr",
            section_print_fn=None, bucket_fn=None, strip_leading_zero=None,
            bucket_sort_fn=None):
        """print_log2_hist(val_type="value", section_header="Bucket ptr",
                           section_print_fn=None, bucket_fn=None,
                           strip_leading_zero=None, bucket_sort_fn=None):

        Prints a table as a log2 histogram. The table must be stored as
        log2. The val_type argument is optional, and is a column header.
        If the histogram has a secondary key, multiple tables will print
        and section_header can be used as a header description for each.
        If section_print_fn is not None, it will be passed the bucket value
        to format into a string as it sees fit. If bucket_fn is not None,
        it will be used to produce a bucket value for the histogram keys.
        If the value of strip_leading_zero is not False, prints a histogram
        that is omitted leading zeros from the beginning.
        If bucket_sort_fn is not None, it will be used to sort the buckets
        before iterating them, and it is useful when there are multiple fields
        in the secondary key.
        The maximum index allowed is log2_index_max (65), which will
        accommodate any 64-bit integer in the histogram.
        """
        if isinstance(self.Key(), ct.Structure):
            tmp = {}
            f1 = self.Key._fields_[0][0]
            f2 = self.Key._fields_[1][0]
            for k, v in self.items():
                bucket = getattr(k, f1)
                if bucket_fn:
                    bucket = bucket_fn(bucket)
                vals = tmp[bucket] = tmp.get(bucket, [0] * log2_index_max)
                slot = getattr(k, f2)
                vals[slot] = v.value

            buckets = list(tmp.keys())
            if bucket_sort_fn:
                buckets = bucket_sort_fn(buckets)

            for bucket in buckets:
                vals = tmp[bucket]
                if section_print_fn:
                    print("\n%s = %s" % (section_header,
                        section_print_fn(bucket)))
                else:
                    print("\n%s = %r" % (section_header, bucket))
                _print_log2_hist(vals, val_type, strip_leading_zero)
        else:
            vals = [0] * log2_index_max
            for k, v in self.items():
                vals[k.value] = v.value
            _print_log2_hist(vals, val_type, strip_leading_zero)

    def print_linear_hist(self, val_type="value", section_header="Bucket ptr",
            section_print_fn=None, bucket_fn=None, bucket_sort_fn=None):
        """print_linear_hist(val_type="value", section_header="Bucket ptr",
                           section_print_fn=None, bucket_fn=None,
                           bucket_sort_fn=None)

        Prints a table as a linear histogram. This is intended to span integer
        ranges, eg, from 0 to 100. The val_type argument is optional, and is a
        column header.  If the histogram has a secondary key, multiple tables
        will print and section_header can be used as a header description for
        each.  If section_print_fn is not None, it will be passed the bucket
        value to format into a string as it sees fit. If bucket_fn is not None,
        it will be used to produce a bucket value for the histogram keys.
        If bucket_sort_fn is not None, it will be used to sort the buckets
        before iterating them, and it is useful when there are multiple fields
        in the secondary key.
        The maximum index allowed is linear_index_max (1025), which is hoped
        to be sufficient for integer ranges spanned.
        """
        if isinstance(self.Key(), ct.Structure):
            tmp = {}
            f1 = self.Key._fields_[0][0]
            f2 = self.Key._fields_[1][0]
            for k, v in self.items():
                bucket = getattr(k, f1)
                if bucket_fn:
                    bucket = bucket_fn(bucket)
                vals = tmp[bucket] = tmp.get(bucket, [0] * linear_index_max)
                slot = getattr(k, f2)
                vals[slot] = v.value

            buckets = tmp.keys()
            if bucket_sort_fn:
                buckets = bucket_sort_fn(buckets)

            for bucket in buckets:
                vals = tmp[bucket]
                if section_print_fn:
                    print("\n%s = %s" % (section_header,
                        section_print_fn(bucket)))
                else:
                    print("\n%s = %r" % (section_header, bucket))
                _print_linear_hist(vals, val_type)
        else:
            vals = [0] * linear_index_max
            for k, v in self.items():
                try:
                    vals[k.value] = v.value
                except IndexError:
                    # Improve error text. If the limit proves a nusiance, this
                    # function be rewritten to avoid having one.
                    raise IndexError(("Index in print_linear_hist() of %d " +
                        "exceeds max of %d.") % (k.value, linear_index_max))
            _print_linear_hist(vals, val_type)


class HashTable(TableBase):
    def __init__(self, *args, **kwargs):
        super(HashTable, self).__init__(*args, **kwargs)

    def __len__(self):
        i = 0
        for k in self: i += 1
        return i

class LruHash(HashTable):
    def __init__(self, *args, **kwargs):
        super(LruHash, self).__init__(*args, **kwargs)

class ArrayBase(TableBase):
    def __init__(self, *args, **kwargs):
        super(ArrayBase, self).__init__(*args, **kwargs)
        self.max_entries = int(lib.bpf_table_max_entries_id(self.bpf.module,
                self.map_id))

    def _normalize_key(self, key):
        if isinstance(key, int):
            if key < 0:
                key = len(self) + key
            key = self.Key(key)
        if not isinstance(key, ct._SimpleCData):
            raise IndexError("Array index must be an integer type")
        if key.value >= len(self):
            raise IndexError("Array index out of range")
        return key

    def __len__(self):
        return self.max_entries

    def __getitem__(self, key):
        key = self._normalize_key(key)
        return super(ArrayBase, self).__getitem__(key)

    def __setitem__(self, key, leaf):
        key = self._normalize_key(key)
        super(ArrayBase, self).__setitem__(key, leaf)

    def __delitem__(self, key):
        key = self._normalize_key(key)
        super(ArrayBase, self).__delitem__(key)

    def clearitem(self, key):
        key = self._normalize_key(key)
        leaf = self.Leaf()
        res = lib.bpf_update_elem(self.map_fd, ct.byref(key), ct.byref(leaf), 0)
        if res < 0:
            raise Exception("Could not clear item")

    def __iter__(self):
        return ArrayBase.Iter(self, self.Key)

    class Iter(object):
        def __init__(self, table, keytype):
            self.Key = keytype
            self.table = table
            self.i = -1

        def __iter__(self):
            return self
        def __next__(self):
            return self.next()
        def next(self):
            self.i += 1
            if self.i == len(self.table):
                raise StopIteration()
            return self.Key(self.i)

class Array(ArrayBase):
    def __init__(self, *args, **kwargs):
        super(Array, self).__init__(*args, **kwargs)

    def __delitem__(self, key):
        # Delete in Array type does not have an effect, so zero out instead
        self.clearitem(key)

class ProgArray(ArrayBase):
    def __init__(self, *args, **kwargs):
        super(ProgArray, self).__init__(*args, **kwargs)

    def __setitem__(self, key, leaf):
        if isinstance(leaf, int):
            leaf = self.Leaf(leaf)
        if isinstance(leaf, self.bpf.Function):
            leaf = self.Leaf(leaf.fd)
        super(ProgArray, self).__setitem__(key, leaf)

class FileDesc:
    def __init__(self, fd):
        if (fd is None) or (fd < 0):
            raise Exception("Invalid file descriptor")
        self.fd = fd

    def clean_up(self):
        if (self.fd is not None) and (self.fd >= 0):
            os.close(self.fd)
            self.fd = None

    def __del__(self):
        self.clean_up()

    def __enter__(self, *args, **kwargs):
        return self

    def __exit__(self, *args, **kwargs):
        self.clean_up()

class CgroupArray(ArrayBase):
    def __init__(self, *args, **kwargs):
        super(CgroupArray, self).__init__(*args, **kwargs)

    def __setitem__(self, key, leaf):
        if isinstance(leaf, int):
            super(CgroupArray, self).__setitem__(key, self.Leaf(leaf))
        elif isinstance(leaf, str):
            # TODO: Add os.O_CLOEXEC once we move to Python version >3.3
            with FileDesc(os.open(leaf, os.O_RDONLY)) as f:
                super(CgroupArray, self).__setitem__(key, self.Leaf(f.fd))
        else:
            raise Exception("Cgroup array key must be either FD or cgroup path")

class PerfEventArray(ArrayBase):

    def __init__(self, *args, **kwargs):
        super(PerfEventArray, self).__init__(*args, **kwargs)
        self._open_key_fds = {}

    def __del__(self):
        keys = list(self._open_key_fds.keys())
        for key in keys:
            del self[key]

    def __delitem__(self, key):
        if key not in self._open_key_fds:
            return
        # Delete entry from the array
        super(PerfEventArray, self).__delitem__(key)
        key_id = (id(self), key)
        if key_id in self.bpf.perf_buffers:
            # The key is opened for perf ring buffer
            lib.perf_reader_free(self.bpf.perf_buffers[key_id])
            del self.bpf.perf_buffers[key_id]
            del self._cbs[key]
        else:
            # The key is opened for perf event read
            lib.bpf_close_perf_event_fd(self._open_key_fds[key])
        del self._open_key_fds[key]

    def open_perf_buffer(self, callback, page_cnt=8, lost_cb=None):
        """open_perf_buffers(callback)

        Opens a set of per-cpu ring buffer to receive custom perf event
        data from the bpf program. The callback will be invoked for each
        event submitted from the kernel, up to millions per second. Use
        page_cnt to change the size of the per-cpu ring buffer. The value
        must be a power of two and defaults to 8.
        """

        if page_cnt & (page_cnt - 1) != 0:
            raise Exception("Perf buffer page_cnt must be a power of two")

        for i in get_online_cpus():
            self._open_perf_buffer(i, callback, page_cnt, lost_cb)

    def _open_perf_buffer(self, cpu, callback, page_cnt, lost_cb):
        def raw_cb_(_, data, size):
            try:
                callback(cpu, data, size)
            except IOError as e:
                if e.errno == errno.EPIPE:
                    exit()
                else:
                    raise e
        def lost_cb_(_, lost):
            try:
                lost_cb(lost)
            except IOError as e:
                if e.errno == errno.EPIPE:
                    exit()
                else:
                    raise e
        fn = _RAW_CB_TYPE(raw_cb_)
        lost_fn = _LOST_CB_TYPE(lost_cb_) if lost_cb else ct.cast(None, _LOST_CB_TYPE)
        reader = lib.bpf_open_perf_buffer(fn, lost_fn, None, -1, cpu, page_cnt)
        if not reader:
            raise Exception("Could not open perf buffer")
        fd = lib.perf_reader_fd(reader)
        self[self.Key(cpu)] = self.Leaf(fd)
        self.bpf.perf_buffers[(id(self), cpu)] = reader
        # keep a refcnt
        self._cbs[cpu] = (fn, lost_fn)
        # The actual fd is held by the perf reader, add to track opened keys
        self._open_key_fds[cpu] = -1

    def _open_perf_event(self, cpu, typ, config):
        fd = lib.bpf_open_perf_event(typ, config, -1, cpu)
        if fd < 0:
            raise Exception("bpf_open_perf_event failed")
        self[self.Key(cpu)] = self.Leaf(fd)
        self._open_key_fds[cpu] = fd

    def open_perf_event(self, typ, config):
        """open_perf_event(typ, config)

        Configures the table such that calls from the bpf program to
        table.perf_read(CUR_CPU_IDENTIFIER) will return the hardware
        counter denoted by event ev on the local cpu.
        """
        for i in get_online_cpus():
            self._open_perf_event(i, typ, config)


class PerCpuHash(HashTable):
    def __init__(self, *args, **kwargs):
        self.reducer = kwargs.pop("reducer", None)
        super(PerCpuHash, self).__init__(*args, **kwargs)
        self.sLeaf = self.Leaf
        self.total_cpu = len(get_possible_cpus())
        # This needs to be 8 as hard coded into the linux kernel.
        self.alignment = ct.sizeof(self.sLeaf) % 8
        if self.alignment is 0:
            self.Leaf = self.sLeaf * self.total_cpu
        else:
            # Currently Float, Char, un-aligned structs are not supported
            if self.sLeaf == ct.c_uint:
                self.Leaf = ct.c_uint64 * self.total_cpu
            elif self.sLeaf == ct.c_int:
                self.Leaf = ct.c_int64 * self.total_cpu
            else:
                raise IndexError("Leaf must be aligned to 8 bytes")

    def getvalue(self, key):
        result = super(PerCpuHash, self).__getitem__(key)
        if self.alignment is 0:
            ret = result
        else:
            ret = (self.sLeaf * self.total_cpu)()
            for i in range(0, self.total_cpu):
                ret[i] = result[i]
        return ret

    def __getitem__(self, key):
        if self.reducer:
            return reduce(self.reducer, self.getvalue(key))
        else:
            return self.getvalue(key)

    def __setitem__(self, key, leaf):
        super(PerCpuHash, self).__setitem__(key, leaf)

    def sum(self, key):
        if isinstance(self.Leaf(), ct.Structure):
            raise IndexError("Leaf must be an integer type for default sum functions")
        return self.sLeaf(sum(self.getvalue(key)))

    def max(self, key):
        if isinstance(self.Leaf(), ct.Structure):
            raise IndexError("Leaf must be an integer type for default max functions")
        return self.sLeaf(max(self.getvalue(key)))

    def average(self, key):
        result = self.sum(key)
        return result.value / self.total_cpu

class LruPerCpuHash(PerCpuHash):
    def __init__(self, *args, **kwargs):
        super(LruPerCpuHash, self).__init__(*args, **kwargs)

class PerCpuArray(ArrayBase):
    def __init__(self, *args, **kwargs):
        self.reducer = kwargs.pop("reducer", None)
        super(PerCpuArray, self).__init__(*args, **kwargs)
        self.sLeaf = self.Leaf
        self.total_cpu = len(get_possible_cpus())
        # This needs to be 8 as hard coded into the linux kernel.
        self.alignment = ct.sizeof(self.sLeaf) % 8
        if self.alignment is 0:
            self.Leaf = self.sLeaf * self.total_cpu
        else:
            # Currently Float, Char, un-aligned structs are not supported
            if self.sLeaf == ct.c_uint:
                self.Leaf = ct.c_uint64 * self.total_cpu
            elif self.sLeaf == ct.c_int:
                self.Leaf = ct.c_int64 * self.total_cpu
            else:
                raise IndexError("Leaf must be aligned to 8 bytes")

    def getvalue(self, key):
        result = super(PerCpuArray, self).__getitem__(key)
        if self.alignment is 0:
            ret = result
        else:
            ret = (self.sLeaf * self.total_cpu)()
            for i in range(0, self.total_cpu):
                ret[i] = result[i]
        return ret

    def __getitem__(self, key):
        if (self.reducer):
            return reduce(self.reducer, self.getvalue(key))
        else:
            return self.getvalue(key)

    def __setitem__(self, key, leaf):
        super(PerCpuArray, self).__setitem__(key, leaf)

    def __delitem__(self, key):
        # Delete in this type does not have an effect, so zero out instead
        self.clearitem(key)

    def sum(self, key):
        if isinstance(self.Leaf(), ct.Structure):
            raise IndexError("Leaf must be an integer type for default sum functions")
        return self.sLeaf(sum(self.getvalue(key)))

    def max(self, key):
        if isinstance(self.Leaf(), ct.Structure):
            raise IndexError("Leaf must be an integer type for default max functions")
        return self.sLeaf(max(self.getvalue(key)))

    def average(self, key):
        result = self.sum(key)
        return result.value / self.total_cpu

class LpmTrie(TableBase):
    def __init__(self, *args, **kwargs):
        super(LpmTrie, self).__init__(*args, **kwargs)

    def __len__(self):
        raise NotImplementedError


class StackTrace(TableBase):
    MAX_DEPTH = 127

    def __init__(self, *args, **kwargs):
        super(StackTrace, self).__init__(*args, **kwargs)

    class StackWalker(object):
        def __init__(self, stack, resolve=None):
            self.stack = stack
            self.n = -1
            self.resolve = resolve

        def __iter__(self):
            return self

        def __next__(self):
            return self.next()

        def next(self):
            self.n += 1
            if self.n == StackTrace.MAX_DEPTH:
                raise StopIteration()

            addr = self.stack.ip[self.n]
            if addr == 0 :
                raise StopIteration()

            return self.resolve(addr) if self.resolve else addr

    def walk(self, stack_id, resolve=None):
        return StackTrace.StackWalker(self[self.Key(stack_id)], resolve)

    def __len__(self):
        i = 0
        for k in self: i += 1
        return i

    def clear(self):
        pass

class DevMap(ArrayBase):
    def __init__(self, *args, **kwargs):
        super(DevMap, self).__init__(*args, **kwargs)

class CpuMap(ArrayBase):
    def __init__(self, *args, **kwargs):
        super(CpuMap, self).__init__(*args, **kwargs)
