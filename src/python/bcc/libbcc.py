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

import ctypes as ct

lib = ct.CDLL("libbcc.so.0", use_errno=True)

# keep in sync with bpf_common.h
lib.bpf_module_create_b.restype = ct.c_void_p
lib.bpf_module_create_b.argtypes = [ct.c_char_p, ct.c_char_p, ct.c_uint]
lib.bpf_module_create_c.restype = ct.c_void_p
lib.bpf_module_create_c.argtypes = [ct.c_char_p, ct.c_uint,
        ct.POINTER(ct.c_char_p), ct.c_int]
lib.bpf_module_create_c_from_string.restype = ct.c_void_p
lib.bpf_module_create_c_from_string.argtypes = [ct.c_char_p, ct.c_uint,
        ct.POINTER(ct.c_char_p), ct.c_int]
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
lib.bpf_table_max_entries_id.restype = ct.c_ulonglong
lib.bpf_table_max_entries_id.argtypes = [ct.c_void_p, ct.c_ulonglong]
lib.bpf_table_flags_id.restype = ct.c_int
lib.bpf_table_flags_id.argtypes = [ct.c_void_p, ct.c_ulonglong]
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
lib.bpf_get_first_key.restype = ct.c_int
lib.bpf_get_first_key.argtypes = [ct.c_int, ct.c_void_p, ct.c_uint]
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
_LOST_CB_TYPE = ct.CFUNCTYPE(None, ct.c_ulonglong)
lib.bpf_attach_kprobe.argtypes = [ct.c_int, ct.c_int, ct.c_char_p, ct.c_char_p, ct.c_int,
        ct.c_int, ct.c_int, _CB_TYPE, ct.py_object]
lib.bpf_detach_kprobe.restype = ct.c_int
lib.bpf_detach_kprobe.argtypes = [ct.c_char_p]
lib.bpf_attach_uprobe.restype = ct.c_void_p
lib.bpf_attach_uprobe.argtypes = [ct.c_int, ct.c_int, ct.c_char_p, ct.c_char_p,
        ct.c_ulonglong, ct.c_int, ct.c_int, ct.c_int, _CB_TYPE, ct.py_object]
lib.bpf_detach_uprobe.restype = ct.c_int
lib.bpf_detach_uprobe.argtypes = [ct.c_char_p]
lib.bpf_attach_tracepoint.restype = ct.c_void_p
lib.bpf_attach_tracepoint.argtypes = [ct.c_int, ct.c_char_p, ct.c_char_p, ct.c_int,
        ct.c_int, ct.c_int, _CB_TYPE, ct.py_object]
lib.bpf_detach_tracepoint.restype = ct.c_int
lib.bpf_detach_tracepoint.argtypes = [ct.c_char_p, ct.c_char_p]
lib.bpf_open_perf_buffer.restype = ct.c_void_p
lib.bpf_open_perf_buffer.argtypes = [_RAW_CB_TYPE, _LOST_CB_TYPE, ct.py_object, ct.c_int, ct.c_int, ct.c_int]
lib.bpf_open_perf_event.restype = ct.c_int
lib.bpf_open_perf_event.argtypes = [ct.c_uint, ct.c_ulonglong, ct.c_int, ct.c_int]
lib.perf_reader_poll.restype = ct.c_int
lib.perf_reader_poll.argtypes = [ct.c_int, ct.POINTER(ct.c_void_p), ct.c_int]
lib.perf_reader_free.restype = None
lib.perf_reader_free.argtypes = [ct.c_void_p]
lib.perf_reader_fd.restype = int
lib.perf_reader_fd.argtypes = [ct.c_void_p]

lib.bpf_attach_xdp.restype = ct.c_int
lib.bpf_attach_xdp.argtypes = [ct.c_char_p, ct.c_int, ct.c_uint]

lib.bpf_attach_perf_event.restype = ct.c_int
lib.bpf_attach_perf_event.argtype = [ct.c_int, ct.c_uint, ct.c_uint, ct.c_ulonglong, ct.c_ulonglong,
        ct.c_int, ct.c_int, ct.c_int]

lib.bpf_close_perf_event_fd.restype = ct.c_int
lib.bpf_close_perf_event_fd.argtype = [ct.c_int]

# bcc symbol helpers
class bcc_symbol(ct.Structure):
    _fields_ = [
            ('name', ct.c_char_p),
            ('demangle_name', ct.c_char_p),
            ('module', ct.POINTER(ct.c_char)),
            ('offset', ct.c_ulonglong),
        ]

class bcc_symbol_option(ct.Structure):
    _fields_ = [
            ('use_debug_file', ct.c_int),
            ('check_debug_file_crc', ct.c_int),
            ('use_symbol_type', ct.c_uint),
        ]

lib.bcc_procutils_which_so.restype = ct.POINTER(ct.c_char)
lib.bcc_procutils_which_so.argtypes = [ct.c_char_p, ct.c_int]
lib.bcc_procutils_free.restype = None
lib.bcc_procutils_free.argtypes = [ct.c_void_p]
lib.bcc_procutils_language.restype = ct.POINTER(ct.c_char)
lib.bcc_procutils_language.argtypes = [ct.c_int]

lib.bcc_resolve_symname.restype = ct.c_int
lib.bcc_resolve_symname.argtypes = [
    ct.c_char_p, ct.c_char_p, ct.c_ulonglong, ct.c_int, ct.POINTER(bcc_symbol_option), ct.POINTER(bcc_symbol)]

_SYM_CB_TYPE = ct.CFUNCTYPE(ct.c_int, ct.c_char_p, ct.c_ulonglong)
lib.bcc_foreach_function_symbol.restype = ct.c_int
lib.bcc_foreach_function_symbol.argtypes = [ct.c_char_p, _SYM_CB_TYPE]

lib.bcc_symcache_new.restype = ct.c_void_p
lib.bcc_symcache_new.argtypes = [ct.c_int, ct.POINTER(bcc_symbol_option)]

lib.bcc_free_symcache.restype = ct.c_void_p
lib.bcc_free_symcache.argtypes = [ct.c_void_p, ct.c_int]

lib.bcc_symbol_free_demangle_name.restype = ct.c_void_p
lib.bcc_symbol_free_demangle_name.argtypes = [ct.POINTER(bcc_symbol)]

lib.bcc_symcache_resolve.restype = ct.c_int
lib.bcc_symcache_resolve.argtypes = [ct.c_void_p, ct.c_ulonglong, ct.POINTER(bcc_symbol)]

lib.bcc_symcache_resolve_no_demangle.restype = ct.c_int
lib.bcc_symcache_resolve_no_demangle.argtypes = [ct.c_void_p, ct.c_ulonglong, ct.POINTER(bcc_symbol)]

lib.bcc_symcache_resolve_name.restype = ct.c_int
lib.bcc_symcache_resolve_name.argtypes = [
    ct.c_void_p, ct.c_char_p, ct.c_char_p, ct.POINTER(ct.c_ulonglong)]

lib.bcc_symcache_refresh.restype = None
lib.bcc_symcache_refresh.argtypes = [ct.c_void_p]

lib.bcc_usdt_new_frompid.restype = ct.c_void_p
lib.bcc_usdt_new_frompid.argtypes = [ct.c_int]

lib.bcc_usdt_new_frompath.restype = ct.c_void_p
lib.bcc_usdt_new_frompath.argtypes = [ct.c_char_p]

lib.bcc_usdt_close.restype = None
lib.bcc_usdt_close.argtypes = [ct.c_void_p]

lib.bcc_usdt_enable_probe.restype = ct.c_int
lib.bcc_usdt_enable_probe.argtypes = [ct.c_void_p, ct.c_char_p, ct.c_char_p]

lib.bcc_usdt_genargs.restype = ct.c_char_p
lib.bcc_usdt_genargs.argtypes = [ct.POINTER(ct.c_void_p), ct.c_int]

lib.bcc_usdt_get_probe_argctype.restype = ct.c_char_p
lib.bcc_usdt_get_probe_argctype.argtypes = [ct.c_void_p, ct.c_char_p, ct.c_int]

class bcc_usdt(ct.Structure):
    _fields_ = [
            ('provider', ct.c_char_p),
            ('name', ct.c_char_p),
            ('bin_path', ct.c_char_p),
            ('semaphore', ct.c_ulonglong),
            ('num_locations', ct.c_int),
            ('num_arguments', ct.c_int),
        ]

class bcc_usdt_location(ct.Structure):
    _fields_ = [
            ('address', ct.c_ulonglong)
        ]

class BCC_USDT_ARGUMENT_FLAGS(object):
    NONE = 0x0
    CONSTANT = 0x1
    DEREF_OFFSET = 0x2
    DEREF_IDENT = 0x4
    BASE_REGISTER_NAME = 0x8
    INDEX_REGISTER_NAME = 0x10
    SCALE = 0x20

class bcc_usdt_argument(ct.Structure):
    _fields_ = [
            ('size', ct.c_int),
            ('valid', ct.c_int),
            ('constant', ct.c_int),
            ('deref_offset', ct.c_int),
            ('deref_ident', ct.c_char_p),
            ('base_register_name', ct.c_char_p),
            ('index_register_name', ct.c_char_p),
            ('scale', ct.c_int)
        ]

_USDT_CB = ct.CFUNCTYPE(None, ct.POINTER(bcc_usdt))

lib.bcc_usdt_foreach.restype = None
lib.bcc_usdt_foreach.argtypes = [ct.c_void_p, _USDT_CB]

lib.bcc_usdt_get_location.restype = ct.c_int
lib.bcc_usdt_get_location.argtypes = [ct.c_void_p, ct.c_char_p, ct.c_int,
                                      ct.POINTER(bcc_usdt_location)]

lib.bcc_usdt_get_argument.restype = ct.c_int
lib.bcc_usdt_get_argument.argtypes = [ct.c_void_p, ct.c_char_p, ct.c_int,
                                      ct.c_int, ct.POINTER(bcc_usdt_argument)]

_USDT_PROBE_CB = ct.CFUNCTYPE(None, ct.c_char_p, ct.c_char_p,
                              ct.c_ulonglong, ct.c_int)

lib.bcc_usdt_foreach_uprobe.restype = None
lib.bcc_usdt_foreach_uprobe.argtypes = [ct.c_void_p, _USDT_PROBE_CB]
