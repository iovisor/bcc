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
import os
from .utils import get_online_cpus

class _sample_period_union(ct.Union):
        _fields_ = [
                ('sample_period', ct.c_ulong),
                ('sample_freq', ct.c_ulong),
        ]

class _wakeup_events_union(ct.Union):
        _fields_ = [
                ('wakeup_events', ct.c_uint),
                ('wakeup_watermark', ct.c_uint),
        ]

class _bp_addr_union(ct.Union):
        _fields_ = [
                ('bp_addr', ct.c_ulong),
                ('kprobe_func', ct.c_ulong),
                ('uprobe_path', ct.c_ulong),
                ('config1', ct.c_ulong),
        ]

class _bp_len_union(ct.Union):
        _fields_ = [
                ('bp_len', ct.c_ulong),
                ('kprobe_addr', ct.c_ulong),
                ('probe_offset', ct.c_ulong),
                ('config2', ct.c_ulong),
        ]

class Perf(object):

        class perf_event_attr(ct.Structure):
                _anonymous_ = [
                        "_sample_period_union",
                        "_wakeup_events_union",
                        "_bp_addr_union",
                        "_bp_len_union"
                ]

                _fields_ = [
                        ('type', ct.c_uint),
                        ('size', ct.c_uint),
                        ('config', ct.c_ulong),
                        ('_sample_period_union', _sample_period_union),  # ct.c_ulong
                        ('sample_type', ct.c_ulong),
                        ('read_format', ct.c_ulong),
                        ('disabled', ct.c_uint, 1),
                        ('inherit', ct.c_uint, 1),
                        ('pinned', ct.c_uint, 1),
                        ('exclusive', ct.c_uint, 1),
                        ('exclude_user', ct.c_uint, 1),
                        ('exclude_kernel', ct.c_uint, 1),
                        ('exclude_hv', ct.c_uint, 1),
                        ('exclude_idle', ct.c_uint, 1),
                        ('mmap', ct.c_uint, 1),
                        ('comm', ct.c_uint, 1),
                        ('freq', ct.c_uint, 1),
                        ('inherit_stat', ct.c_uint, 1),
                        ('enable_on_exec', ct.c_uint, 1),
                        ('task', ct.c_uint, 1),
                        ('watermark', ct.c_uint, 1),
                        ('precise_ip', ct.c_uint, 2),
                        ('mmap_data', ct.c_uint, 1),
                        ('sample_id_all', ct.c_uint, 1),
                        ('exclude_host', ct.c_uint, 1),
                        ('exclude_guest', ct.c_uint, 1),
                        ('exclude_callchain_kernel', ct.c_uint, 1),
                        ('exclude_callchain_user', ct.c_uint, 1),
                        ('mmap2', ct.c_uint, 1),
                        ('comm_exec', ct.c_uint, 1),
                        ('use_clockid', ct.c_uint, 1),
                        ('context_switch', ct.c_uint, 1),
                        ('write_backward', ct.c_uint, 1),
                        ('namespaces', ct.c_uint, 1),
                        ('ksymbol', ct.c_uint, 1),
                        ('bpf_event', ct.c_uint, 1),
                        ('aux_output', ct.c_uint, 1),
                        ('cgroup', ct.c_uint, 1),
                        ('text_poke', ct.c_uint, 1),
                        ('__reserved_1', ct.c_uint, 30),
                        ('_wakeup_events_union', _wakeup_events_union),  # ct.c_uint
                        ('bp_type', ct.c_uint),
                        ('_bp_addr_union', _bp_addr_union),  # ct.c_ulong
                        ('_bp_len_union', _bp_len_union),  # ct.c_ulong
                        ('branch_sample_type', ct.c_ulong),
                        ('sample_regs_user', ct.c_ulong),
                        ('sample_stack_user', ct.c_uint),
                        ('clockid', ct.c_int),
                        ('sample_regs_intr', ct.c_ulong),
                        ('aux_watermark', ct.c_uint),
                        ('sample_max_stack', ct.c_uint16),
                        ('__reserved_2', ct.c_uint16),
                        ('aux_sample_size', ct.c_uint),
                        ('__reserved_3', ct.c_uint),
                ]

                def __init__(self):
                    self.size = 120  # PERF_ATTR_SIZE_VER6
                    self.ctype_fields = [item[0] for item in self._fields_]
                    self.ctype_fields.extend([item[0] for item in _sample_period_union._fields_])
                    self.ctype_fields.extend([item[0] for item in _wakeup_events_union._fields_])
                    self.ctype_fields.extend([item[0] for item in _bp_addr_union._fields_])
                    self.ctype_fields.extend([item[0] for item in _bp_len_union._fields_])

                def __setattr__(self, key, value):
                    if hasattr(self, 'ctype_fields') and key not in self.ctype_fields:
                        print("Warning: Setting field {} on perf_event_attr that isn't part of the ctype - {} won't make it to perf_event_open".format(key, key))
                    super(Perf.perf_event_attr, self).__setattr__(key, value)

        # x86 specific, from arch/x86/include/generated/uapi/asm/unistd_64.h
        NR_PERF_EVENT_OPEN = 298

        #
        # Selected constants from include/uapi/linux/perf_event.h.
        # Values copied during Linux 4.7 series.
        #

        # perf_type_id
        PERF_TYPE_HARDWARE = 0
        PERF_TYPE_SOFTWARE = 1
        PERF_TYPE_TRACEPOINT = 2
        PERF_TYPE_HW_CACHE = 3

        # perf_event_sample_format
        PERF_SAMPLE_RAW = 1024      # it's a u32; could also try zero args

        # perf_event.h
        PERF_FLAG_FD_CLOEXEC = 8
        PERF_EVENT_IOC_SET_FILTER = 1074275334
        PERF_EVENT_IOC_ENABLE = 9216

        # fetch syscall routines
        libc = ct.CDLL('libc.so.6', use_errno=True)
        syscall = libc.syscall          # not declaring vararg types
        ioctl = libc.ioctl              # not declaring vararg types

        @staticmethod
        def _open_for_cpu(cpu, attr, pid=-1):
                pfd = Perf.syscall(Perf.NR_PERF_EVENT_OPEN, ct.byref(attr),
                                   pid, cpu, -1,
                                   Perf.PERF_FLAG_FD_CLOEXEC)
                if pfd < 0:
                        errno_ = ct.get_errno()
                        raise OSError(errno_, os.strerror(errno_))

                if attr.type == Perf.PERF_TYPE_TRACEPOINT:
                    if Perf.ioctl(pfd, Perf.PERF_EVENT_IOC_SET_FILTER,
                                  "common_pid == -17") < 0:
                            errno_ = ct.get_errno()
                            raise OSError(errno_, os.strerror(errno_))

                # we don't setup the perf ring buffers, as we won't read them

                if Perf.ioctl(pfd, Perf.PERF_EVENT_IOC_ENABLE, 0) < 0:
                        errno_ = ct.get_errno()
                        raise OSError(errno_, os.strerror(errno_))

        @staticmethod
        def perf_event_open(tpoint_id, pid=-1, ptype=PERF_TYPE_TRACEPOINT,
                            freq=0):
                attr = Perf.perf_event_attr()
                attr.config = tpoint_id
                attr.type = ptype
                attr.sample_type = Perf.PERF_SAMPLE_RAW
                if freq > 0:
                    # setup sampling
                    attr.freq = 1  # no mmap or comm
                    attr.sample_period = freq
                else:
                    attr.sample_period = 1
                attr.wakeup_events = 9999999                # don't wake up

                for cpu in get_online_cpus():
                        Perf._open_for_cpu(cpu, attr, pid)

        @staticmethod
        def perf_custom_event_open(attr, pid=-1):
                for cpu in get_online_cpus():
                        Perf._open_for_cpu(cpu, attr, pid)
