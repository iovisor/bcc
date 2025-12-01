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
try:
    from collections.abc import MutableMapping
except ImportError:
    from collections import MutableMapping
from time import strftime
import ctypes as ct
from functools import reduce
import os
import errno
import re
import sys
import platform

from .libbcc import lib, _RAW_CB_TYPE, _LOST_CB_TYPE, _RINGBUF_CB_TYPE, bcc_perf_buffer_opts
from .utils import get_online_cpus
from .utils import get_possible_cpus

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
BPF_MAP_TYPE_CGROUP_STORAGE = 19
BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20
BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21
BPF_MAP_TYPE_QUEUE = 22
BPF_MAP_TYPE_STACK = 23
BPF_MAP_TYPE_SK_STORAGE = 24
BPF_MAP_TYPE_DEVMAP_HASH = 25
BPF_MAP_TYPE_STRUCT_OPS = 26
BPF_MAP_TYPE_RINGBUF = 27
BPF_MAP_TYPE_INODE_STORAGE = 28
BPF_MAP_TYPE_TASK_STORAGE = 29

map_type_name = {
    BPF_MAP_TYPE_HASH: "HASH",
    BPF_MAP_TYPE_ARRAY: "ARRAY",
    BPF_MAP_TYPE_PROG_ARRAY: "PROG_ARRAY",
    BPF_MAP_TYPE_PERF_EVENT_ARRAY: "PERF_EVENT_ARRAY",
    BPF_MAP_TYPE_PERCPU_HASH: "PERCPU_HASH",
    BPF_MAP_TYPE_PERCPU_ARRAY: "PERCPU_ARRAY",
    BPF_MAP_TYPE_STACK_TRACE: "STACK_TRACE",
    BPF_MAP_TYPE_CGROUP_ARRAY: "CGROUP_ARRAY",
    BPF_MAP_TYPE_LRU_HASH: "LRU_HASH",
    BPF_MAP_TYPE_LRU_PERCPU_HASH: "LRU_PERCPU_HASH",
    BPF_MAP_TYPE_LPM_TRIE: "LPM_TRIE",
    BPF_MAP_TYPE_ARRAY_OF_MAPS: "ARRAY_OF_MAPS",
    BPF_MAP_TYPE_HASH_OF_MAPS: "HASH_OF_MAPS",
    BPF_MAP_TYPE_DEVMAP: "DEVMAP",
    BPF_MAP_TYPE_SOCKMAP: "SOCKMAP",
    BPF_MAP_TYPE_CPUMAP: "CPUMAP",
    BPF_MAP_TYPE_XSKMAP: "XSKMAP",
    BPF_MAP_TYPE_SOCKHASH: "SOCKHASH",
    BPF_MAP_TYPE_CGROUP_STORAGE: "CGROUP_STORAGE",
    BPF_MAP_TYPE_REUSEPORT_SOCKARRAY: "REUSEPORT_SOCKARRAY",
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE: "PERCPU_CGROUP_STORAGE",
    BPF_MAP_TYPE_QUEUE: "QUEUE",
    BPF_MAP_TYPE_STACK: "STACK",
    BPF_MAP_TYPE_SK_STORAGE: "SK_STORAGE",
    BPF_MAP_TYPE_DEVMAP_HASH: "DEVMAP_HASH",
    BPF_MAP_TYPE_STRUCT_OPS: "STRUCT_OPS",
    BPF_MAP_TYPE_RINGBUF: "RINGBUF",
    BPF_MAP_TYPE_INODE_STORAGE: "INODE_STORAGE",
    BPF_MAP_TYPE_TASK_STORAGE: "TASK_STORAGE",
}

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

def get_json_hist(vals, val_type, section_bucket=None):
    return _get_json_hist(vals, val_type, section_bucket=None)

def _get_json_hist(vals, val_type, section_bucket=None):
    hist_list = []
    max_nonzero_idx = 0
    for i in range(len(vals)):
        if vals[i] != 0:
            max_nonzero_idx = i
    index = 1
    prev = 0
    for i in range(len(vals)):
        if i != 0 and i <= max_nonzero_idx:
            index = index * 2

            list_obj = {}
            list_obj['interval-start'] = prev
            list_obj['interval-end'] = int(index) - 1
            list_obj['count'] = int(vals[i])

            hist_list.append(list_obj)

            prev = index
    histogram = {"ts": strftime("%Y-%m-%d %H:%M:%S"), "val_type": val_type, "data": hist_list}
    if section_bucket:
        histogram[section_bucket[0]] = section_bucket[1]
    return histogram

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

def _print_linear_hist(vals, val_type, strip_leading_zero):
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
        print(header % val_type)
    for i in range(0, idx_max + 1):
        val = vals[i]

        if strip_leading_zero:
            if val:
                print(body % (i, val, stars,
                              _stars(val, val_max, stars)))
                strip_leading_zero = False
        else:
                print(body % (i, val, stars,
                              _stars(val, val_max, stars)))


def get_table_type_name(ttype):
    try:
        return map_type_name[ttype]
    except KeyError:
        return "<unknown>"


def _get_event_class(event_map):
    ct_mapping = {
        'char'              : ct.c_char,
        's8'                : ct.c_char,
        'unsigned char'     : ct.c_ubyte,
        'u8'                : ct.c_ubyte,
        'u8 *'              : ct.c_char_p,
        'char *'            : ct.c_char_p,
        'short'             : ct.c_short,
        's16'               : ct.c_short,
        'unsigned short'    : ct.c_ushort,
        'u16'               : ct.c_ushort,
        'int'               : ct.c_int,
        's32'               : ct.c_int,
        'enum'              : ct.c_int,
        'unsigned int'      : ct.c_uint,
        'u32'               : ct.c_uint,
        'long'              : ct.c_long,
        'unsigned long'     : ct.c_ulong,
        'long long'         : ct.c_longlong,
        's64'               : ct.c_longlong,
        'unsigned long long': ct.c_ulonglong,
        'u64'               : ct.c_ulonglong,
        '__int128'          : (ct.c_longlong * 2),
        'unsigned __int128' : (ct.c_ulonglong * 2),
        'void *'            : ct.c_void_p,
    }

    # handle array types e.g. "int [16]", "char[16]" or "unsigned char[16]"
    array_type = re.compile(r"(\S+(?: \S+)*) ?\[([0-9]+)\]$")

    fields = []
    num_fields = lib.bpf_perf_event_fields(event_map.bpf.module, event_map._name)
    i = 0
    while i < num_fields:
        field = lib.bpf_perf_event_field(event_map.bpf.module, event_map._name, i).decode()
        m = re.match(r"(.*)#(.*)", field)
        field_name = m.group(1)
        field_type = m.group(2)

        if re.match(r"enum .*", field_type):
            field_type = "enum"

        m = array_type.match(field_type)
        try:
            if m:
                fields.append((field_name, ct_mapping[m.group(1)] * int(m.group(2))))
            else:
                fields.append((field_name, ct_mapping[field_type]))
        except KeyError:
            # Using print+sys.exit instead of raising exceptions,
            # because exceptions are caught by the caller.
            print("Type: '%s' not recognized. Please define the data with ctypes manually."
                  % field_type, file=sys.stderr)
            sys.exit(1)
        i += 1
    return type('', (ct.Structure,), {'_fields_': fields})


def Table(bpf, map_id, map_fd, keytype, leaftype, name, **kwargs):
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
        t = PerfEventArray(bpf, map_id, map_fd, keytype, leaftype, name)
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
    elif ttype == BPF_MAP_TYPE_XSKMAP:
        t = XskMap(bpf, map_id, map_fd, keytype, leaftype)
    elif ttype == BPF_MAP_TYPE_ARRAY_OF_MAPS:
        t = MapInMapArray(bpf, map_id, map_fd, keytype, leaftype)
    elif ttype == BPF_MAP_TYPE_HASH_OF_MAPS:
        t = MapInMapHash(bpf, map_id, map_fd, keytype, leaftype)
    elif ttype == BPF_MAP_TYPE_QUEUE or ttype == BPF_MAP_TYPE_STACK:
        t = QueueStack(bpf, map_id, map_fd, leaftype)
    elif ttype == BPF_MAP_TYPE_RINGBUF:
        t = RingBuf(bpf, map_id, map_fd, keytype, leaftype, name)
    if t == None:
        raise Exception("Unknown table type %d" % ttype)
    return t


class TableBase(MutableMapping):

    def __init__(self, bpf, map_id, map_fd, keytype, leaftype, name=None):
        self.bpf = bpf
        self.map_id = map_id
        self.map_fd = map_fd
        self.Key = keytype
        self.Leaf = leaftype
        self.ttype = lib.bpf_table_type_id(self.bpf.module, self.map_id)
        self.flags = lib.bpf_table_flags_id(self.bpf.module, self.map_id)
        self._cbs = {}
        self._name = name
        self.max_entries = int(lib.bpf_table_max_entries_id(self.bpf.module,
                self.map_id))

    def get_fd(self):
        return self.map_fd

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

    def _alloc_keys_values(self, alloc_k=False, alloc_v=False, count=None):
        """Allocate keys and/or values arrays. Useful for in items_*_batch.

        Args:
            alloc_k (bool): True to allocate keys array, False otherwise.
            Default is False.
            alloc_v (bool): True to allocate values array, False otherwise.
            Default is False.
            count (int): number of elements in the array(s) to allocate. If
            count is None then it allocates the maximum number of elements i.e
            self.max_entries.

        Returns:
            tuple: (count, keys, values). Where count is ct.c_uint32,
            and keys and values an instance of ct.Array
        Raises:
            ValueError: If count is less than 1 or greater than
            self.max_entries.
        """
        keys = values = None
        if not alloc_k and not alloc_v:
            return (ct.c_uint32(0), None, None)

        if not count:  # means alloc maximum size
            count = self.max_entries
        elif count < 1 or count > self.max_entries:
            raise ValueError("Wrong count")

        if alloc_k:
            keys = (self.Key * count)()
        if alloc_v:
            values = (self.Leaf * count)()

        return (ct.c_uint32(count), keys, values)

    def _sanity_check_keys_values(self, keys=None, values=None):
        """Check if the given keys or values have the right type and size.

        Args:
            keys (ct.Array): keys array to check
            values (ct.Array): values array to check
        Returns:
            ct.c_uint32 : the size of the array(s)
        Raises:
            ValueError: If length of arrays is less than 1 or greater than
            self.max_entries, or when both arrays length are different.
            TypeError: If the keys and values are not an instance of ct.Array
        """
        arr_len = 0
        for elem in [keys, values]:
            if elem:
                if not isinstance(elem, ct.Array):
                    raise TypeError

                arr_len = len(elem)
                if arr_len < 1 or arr_len > self.max_entries:
                    raise ValueError("Array's length is wrong")

        if keys and values:
            # check both length are equal
            if len(keys) != len(values):
                raise ValueError("keys array length != values array length")

        return ct.c_uint32(arr_len)

    def items_lookup_batch(self):
        """Look up all the key-value pairs in the map.

        Args:
            None
        Yields:
            tuple: The tuple of (key,value) for every entries that have
            been looked up.
        Notes: lookup batch on a keys subset is not supported by the kernel.
        """
        for k, v in self._items_lookup_and_optionally_delete_batch(delete=False):
            yield(k, v)
        return

    def items_delete_batch(self, ct_keys=None):
        """Delete the key-value pairs related to the keys given as parameters.
        Note that if no key are given, it is faster to call
        lib.bpf_lookup_and_delete_batch than create keys array and then call
        lib.bpf_delete_batch on these keys.

        Args:
            ct_keys (ct.Array): keys array to delete. If an array of keys is
            given then it deletes all the related keys-values.
            If keys is None (default) then it deletes all entries.
        Yields:
            tuple: The tuple of (key,value) for every entries that have
            been deleted.
        Raises:
            Exception: If bpf syscall return value indicates an error.
        """
        if ct_keys is not None:
            ct_cnt = self._sanity_check_keys_values(keys=ct_keys)
            res = lib.bpf_delete_batch(self.map_fd,
                                       ct.byref(ct_keys),
                                       ct.byref(ct_cnt)
                                       )
            if (res != 0):
                raise Exception("BPF_MAP_DELETE_BATCH has failed: %s"
                                % os.strerror(ct.get_errno()))

        else:
            for _ in self.items_lookup_and_delete_batch():
                return

    def items_update_batch(self, ct_keys, ct_values):
        """Update all the key-value pairs in the map provided.
        The arrays must be the same length, between 1 and the maximum number
        of entries.

        Args:
            ct_keys (ct.Array): keys array to update
            ct_values (ct.Array): values array to update
        Raises:
            Exception: If bpf syscall return value indicates an error.
        """
        ct_cnt = self._sanity_check_keys_values(keys=ct_keys, values=ct_values)
        res = lib.bpf_update_batch(self.map_fd,
                                   ct.byref(ct_keys),
                                   ct.byref(ct_values),
                                   ct.byref(ct_cnt)
                                   )
        if (res != 0):
            raise Exception("BPF_MAP_UPDATE_BATCH has failed: %s"
                            % os.strerror(ct.get_errno()))

    def items_lookup_and_delete_batch(self):
        """Look up and delete all the key-value pairs in the map.

        Args:
            None
        Yields:
            tuple: The tuple of (key,value) for every entries that have
            been looked up and deleted.
        Notes: lookup and delete batch on a keys subset is not supported by
        the kernel.
        """
        for k, v in self._items_lookup_and_optionally_delete_batch(delete=True):
            yield(k, v)
        return

    def _items_lookup_and_optionally_delete_batch(self, delete=True):
        """Look up and optionally delete all the key-value pairs in the map.

        Args:
            delete (bool) : look up and delete the key-value pairs when True,
            else just look up.
        Yields:
            tuple: The tuple of (key,value) for every entries that have
            been looked up and deleted.
        Raises:
            Exception: If bpf syscall return value indicates an error.
        Notes: lookup and delete batch on a keys subset is not supported by
        the kernel.
        """
        if delete is True:
            bpf_batch = lib.bpf_lookup_and_delete_batch
            bpf_cmd = "BPF_MAP_LOOKUP_AND_DELETE_BATCH"
        else:
            bpf_batch = lib.bpf_lookup_batch
            bpf_cmd = "BPF_MAP_LOOKUP_BATCH"

        # alloc keys and values to the max size
        ct_buf_size, ct_keys, ct_values = self._alloc_keys_values(alloc_k=True,
                                                                  alloc_v=True)
        ct_out_batch = ct_cnt = ct.c_uint32(0)
        total = 0
        while True:
            ct_cnt.value = ct_buf_size.value - total
            res = bpf_batch(self.map_fd,
                            ct.byref(ct_out_batch) if total else None,
                            ct.byref(ct_out_batch),
                            ct.byref(ct_keys, ct.sizeof(self.Key) * total),
                            ct.byref(ct_values, ct.sizeof(self.Leaf) * total),
                            ct.byref(ct_cnt)
                            )
            errcode = ct.get_errno()
            total += ct_cnt.value
            if (res != 0 and errcode != errno.ENOENT):
                raise Exception("%s has failed: %s" % (bpf_cmd,
                                                       os.strerror(errcode)))

            if res != 0:
                break  # success

            if total == ct_buf_size.value:  # buffer full, we can't progress
                break

            if ct_cnt.value == 0:
                # no progress, probably because concurrent update
                # puts too many elements in one bucket.
                break

        for i in range(0, total):
            k = ct_keys[i]
            v = ct_values[i]
            if not isinstance(k, ct.Structure):
                k = self.Key(k)
            if not isinstance(v, ct.Structure):
                v = self.Leaf(v)
            yield (k, v)

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

    def decode_c_struct(self, tmp, buckets, bucket_fn, bucket_sort_fn, index_max=log2_index_max):
        f1 = self.Key._fields_[0][0]
        f2 = self.Key._fields_[1][0]
        # The above code assumes that self.Key._fields_[1][0] holds the
        # slot. But a padding member may have been inserted here, which
        # breaks the assumption and leads to chaos.
        # TODO: this is a quick fix. Fixing/working around in the BCC
        # internal library is the right thing to do.
        if f2 == '__pad_1' and len(self.Key._fields_) == 3:
            f2 = self.Key._fields_[2][0]
        for k, v in self.items():
            bucket = getattr(k, f1)
            if bucket_fn:
                bucket = bucket_fn(bucket)
            vals = tmp[bucket] = tmp.get(bucket, [0] * index_max)
            slot = getattr(k, f2)
            vals[slot] = v.value
        buckets_lst = list(tmp.keys())
        if bucket_sort_fn:
            buckets_lst = bucket_sort_fn(buckets_lst)
        for bucket in buckets_lst:
            buckets.append(bucket)

    def print_json_hist(self, val_type="value", section_header="Bucket ptr",
                        section_print_fn=None, bucket_fn=None, bucket_sort_fn=None):
        """print_json_hist(val_type="value", section_header="Bucket ptr",
                                   section_print_fn=None, bucket_fn=None,
                                   bucket_sort_fn=None):

                Prints a table as a json histogram. The table must be stored as
                log2. The val_type argument is optional, and is a column header.
                If the histogram has a secondary key, the dictionary will be split by secondary key
                If section_print_fn is not None, it will be passed the bucket value
                to format into a string as it sees fit. If bucket_fn is not None,
                it will be used to produce a bucket value for the histogram keys.
                If bucket_sort_fn is not None, it will be used to sort the buckets
                before iterating them, and it is useful when there are multiple fields
                in the secondary key.
                The maximum index allowed is log2_index_max (65), which will
                accommodate any 64-bit integer in the histogram.
                """
        if isinstance(self.Key(), ct.Structure):
            tmp = {}
            buckets = []
            self.decode_c_struct(tmp, buckets, bucket_fn, bucket_sort_fn)
            for bucket in buckets:
                vals = tmp[bucket]
                if section_print_fn:
                    section_bucket = (section_header, section_print_fn(bucket))
                else:
                    section_bucket = (section_header, bucket)
                print(_get_json_hist(vals, val_type, section_bucket))

        else:
            vals = [0] * log2_index_max
            for k, v in self.items():
                vals[k.value] = v.value
            print(_get_json_hist(vals, val_type))

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
            buckets = []
            self.decode_c_struct(tmp, buckets, bucket_fn, bucket_sort_fn)
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
            section_print_fn=None, bucket_fn=None, strip_leading_zero=None,
            bucket_sort_fn=None):
        """print_linear_hist(val_type="value", section_header="Bucket ptr",
                           section_print_fn=None, bucket_fn=None,
                           strip_leading_zero=None, bucket_sort_fn=None)

        Prints a table as a linear histogram. This is intended to span integer
        ranges, eg, from 0 to 100. The val_type argument is optional, and is a
        column header.  If the histogram has a secondary key, multiple tables
        will print and section_header can be used as a header description for
        each.  If section_print_fn is not None, it will be passed the bucket
        value to format into a string as it sees fit. If bucket_fn is not None,
        it will be used to produce a bucket value for the histogram keys.
        If the value of strip_leading_zero is not False, prints a histogram
        that is omitted leading zeros from the beginning.
        If bucket_sort_fn is not None, it will be used to sort the buckets
        before iterating them, and it is useful when there are multiple fields
        in the secondary key.
        The maximum index allowed is linear_index_max (1025), which is hoped
        to be sufficient for integer ranges spanned.
        """
        if isinstance(self.Key(), ct.Structure):
            tmp = {}
            buckets = []
            self.decode_c_struct(tmp, buckets, bucket_fn, bucket_sort_fn, linear_index_max)

            for bucket in buckets:
                vals = tmp[bucket]
                if section_print_fn:
                    print("\n%s = %s" % (section_header,
                        section_print_fn(bucket)))
                else:
                    print("\n%s = %r" % (section_header, bucket))
                _print_linear_hist(vals, val_type, strip_leading_zero)
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
            _print_linear_hist(vals, val_type, strip_leading_zero)


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
        self._event_class = None

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

    def event(self, data):
        """event(data)

        When perf buffers are opened to receive custom perf event,
        the underlying event data struct which is defined in C in
        the BPF program can be deduced via this function. This avoids
        redundant definitions in Python.
        """
        if self._event_class == None:
            self._event_class = _get_event_class(self)
        return ct.cast(data, ct.POINTER(self._event_class)).contents

    def open_perf_buffer(self, callback, page_cnt=8, lost_cb=None, wakeup_events=1):
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
            self._open_perf_buffer(i, callback, page_cnt, lost_cb, wakeup_events)

    def _open_perf_buffer(self, cpu, callback, page_cnt, lost_cb, wakeup_events):
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
        opts = bcc_perf_buffer_opts()
        opts.pid = -1
        opts.cpu = cpu
        opts.wakeup_events = wakeup_events
        reader = lib.bpf_open_perf_buffer_opts(fn, lost_fn, None, page_cnt, ct.byref(opts))
        if not reader:
            raise Exception("Could not open perf buffer")
        fd = lib.perf_reader_fd(reader)
        self[self.Key(cpu)] = self.Leaf(fd)
        self.bpf.perf_buffers[(id(self), cpu)] = reader
        # keep a refcnt
        self._cbs[cpu] = (fn, lost_fn)
        # The actual fd is held by the perf reader, add to track opened keys
        self._open_key_fds[cpu] = -1

    def _open_perf_event(self, cpu, typ, config, pid=-1):
        fd = lib.bpf_open_perf_event(typ, config, pid, cpu)
        if fd < 0:
            raise Exception("bpf_open_perf_event failed")
        self[self.Key(cpu)] = self.Leaf(fd)
        self._open_key_fds[cpu] = fd

    def open_perf_event(self, typ, config, pid=-1):
        """open_perf_event(typ, config)

        Configures the table such that calls from the bpf program to
        table.perf_read(CUR_CPU_IDENTIFIER) will return the hardware
        counter denoted by event ev on the local cpu.
        """
        for i in get_online_cpus():
            self._open_perf_event(i, typ, config, pid)


class PerCpuHash(HashTable):
    def __init__(self, *args, **kwargs):
        self.reducer = kwargs.pop("reducer", None)
        super(PerCpuHash, self).__init__(*args, **kwargs)
        self.sLeaf = self.Leaf
        self.total_cpu = len(get_possible_cpus())
        # This needs to be 8 as hard coded into the linux kernel.
        self.alignment = ct.sizeof(self.sLeaf) % 8
        if self.alignment == 0:
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
        if self.alignment == 0:
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
        if self.alignment == 0:
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
        if self.alignment == 0:
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
    BPF_F_STACK_BUILD_ID = (1<<5)
    BPF_STACK_BUILD_ID_EMPTY =  0 #can't get stacktrace
    BPF_STACK_BUILD_ID_VALID = 1 #valid build-id,ip
    BPF_STACK_BUILD_ID_IP = 2 #fallback to ip

    def __init__(self, *args, **kwargs):
        super(StackTrace, self).__init__(*args, **kwargs)

    class StackWalker(object):
        def __init__(self, stack, flags, resolve=None):
            self.stack = stack
            self.n = -1
            self.resolve = resolve
            self.flags = flags

        def __iter__(self):
            return self

        def __next__(self):
            return self.next()

        def next(self):
            self.n += 1
            if self.n == StackTrace.MAX_DEPTH:
                raise StopIteration()

            if self.flags & StackTrace.BPF_F_STACK_BUILD_ID:
              addr = self.stack.trace[self.n]
              if addr.status == StackTrace.BPF_STACK_BUILD_ID_IP or \
                 addr.status == StackTrace.BPF_STACK_BUILD_ID_EMPTY:
                  raise StopIteration()
            else:
              addr = self.stack.ip[self.n]

            # powerpc populates optional, potentially-null second and third entries
            if addr == 0 and (not platform.machine().startswith('ppc') or (self.n != 1 and self.n != 2)) :
                    raise StopIteration()

            return self.resolve(addr) if self.resolve else addr

    def walk(self, stack_id, resolve=None):
        return StackTrace.StackWalker(self[self.Key(stack_id)], self.flags, resolve)

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

class XskMap(ArrayBase):
    def __init__(self, *args, **kwargs):
        super(XskMap, self).__init__(*args, **kwargs)

class MapInMapArray(ArrayBase):
    def __init__(self, *args, **kwargs):
        super(MapInMapArray, self).__init__(*args, **kwargs)

class MapInMapHash(HashTable):
    def __init__(self, *args, **kwargs):
        super(MapInMapHash, self).__init__(*args, **kwargs)

class RingBuf(TableBase):
    def __init__(self, *args, **kwargs):
        super(RingBuf, self).__init__(*args, **kwargs)
        self._ringbuf = None
        self._event_class = None

    def __delitem(self, key):
        pass

    def __del__(self):
        pass

    def __len__(self):
        return 0

    def event(self, data):
        """event(data)

        When ring buffers are opened to receive custom event,
        the underlying event data struct which is defined in C in
        the BPF program can be deduced via this function. This avoids
        redundant definitions in Python.
        """
        if self._event_class == None:
            self._event_class = _get_event_class(self)
        return ct.cast(data, ct.POINTER(self._event_class)).contents

    def open_ring_buffer(self, callback, ctx=None):
        """open_ring_buffer(callback)

        Opens a ring buffer to receive custom event data from the bpf program.
        The callback will be invoked for each event submitted from the kernel,
        up to millions per second.
        """

        def ringbuf_cb_(ctx, data, size):
            try:
                ret = callback(ctx, data, size)
                # Callback for ringbufs should _always_ return an integer.
                # If the function the user registers does not,
                # simply fall back to returning 0.
                try:
                    ret = int(ret)
                except:
                    ret = 0
            except IOError as e:
                if e.errno == errno.EPIPE:
                    exit()
                else:
                    raise e
            return ret

        fn = _RINGBUF_CB_TYPE(ringbuf_cb_)
        self.bpf._open_ring_buffer(self.map_fd, fn, ctx)
        # keep a refcnt
        self._cbs[0] = fn

class QueueStack:
    # Flag for map.push
    BPF_EXIST = 2

    def __init__(self, bpf, map_id, map_fd, leaftype):
        self.bpf = bpf
        self.map_id = map_id
        self.map_fd = map_fd
        self.Leaf = leaftype
        self.ttype = lib.bpf_table_type_id(self.bpf.module, self.map_id)
        self.flags = lib.bpf_table_flags_id(self.bpf.module, self.map_id)
        self.max_entries = int(lib.bpf_table_max_entries_id(self.bpf.module,
                self.map_id))

    def leaf_sprintf(self, leaf):
        buf = ct.create_string_buffer(ct.sizeof(self.Leaf) * 8)
        res = lib.bpf_table_leaf_snprintf(self.bpf.module, self.map_id, buf,
                                          len(buf), ct.byref(leaf))
        if res < 0:
            raise Exception("Could not printf leaf")
        return buf.value

    def leaf_scanf(self, leaf_str):
        leaf = self.Leaf()
        res = lib.bpf_table_leaf_sscanf(self.bpf.module, self.map_id, leaf_str,
                                        ct.byref(leaf))
        if res < 0:
            raise Exception("Could not scanf leaf")
        return leaf

    def push(self, leaf, flags=0):
        res = lib.bpf_update_elem(self.map_fd, None, ct.byref(leaf), flags)
        if res < 0:
            errstr = os.strerror(ct.get_errno())
            raise Exception("Could not push to table: %s" % errstr)

    def pop(self):
        leaf = self.Leaf()
        res = lib.bpf_lookup_and_delete(self.map_fd, None, ct.byref(leaf))
        if res < 0:
            raise KeyError("Could not pop from table")
        return leaf

    def peek(self):
        leaf = self.Leaf()
        res = lib.bpf_lookup_elem(self.map_fd, None, ct.byref(leaf))
        if res < 0:
            raise KeyError("Could not peek table")
        return leaf

    def itervalues(self):
        # to avoid infinite loop, set maximum pops to max_entries
        cnt = self.max_entries
        while cnt:
            try:
                yield(self.pop())
                cnt -= 1
            except KeyError:
                return

    def values(self):
        return [value for value in self.itervalues()]
