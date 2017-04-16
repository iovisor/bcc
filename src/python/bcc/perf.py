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

class Perf(object):
        class perf_event_attr(ct.Structure):
                _fields_ = [
                        ('type', ct.c_uint),
                        ('size', ct.c_uint),
                        ('config', ct.c_ulong),
                        ('sample_period', ct.c_ulong),
                        ('sample_type', ct.c_ulong),
                        ('read_format', ct.c_ulong),
                        ('flags', ct.c_ulong),
                        ('wakeup_events', ct.c_uint),
                        ('IGNORE3', ct.c_uint),
                        ('IGNORE4', ct.c_ulong),
                        ('IGNORE5', ct.c_ulong),
                        ('IGNORE6', ct.c_ulong),
                        ('IGNORE7', ct.c_uint),
                        ('IGNORE8', ct.c_int),
                        ('IGNORE9', ct.c_ulong),
                        ('IGNORE10', ct.c_uint),
                        ('IGNORE11', ct.c_uint)
                ]

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

        # perf_event_attr
        PERF_ATTR_FLAG_FREQ = 1024

        # perf_event.h
        PERF_FLAG_FD_CLOEXEC = 8
        PERF_EVENT_IOC_SET_FILTER = 1074275334
        PERF_EVENT_IOC_ENABLE = 9216

        # fetch syscall routines
        libc = ct.CDLL('libc.so.6', use_errno=True)
        syscall = libc.syscall          # not declaring vararg types
        ioctl = libc.ioctl              # not declaring vararg types

        @staticmethod
        def _open_for_cpu(cpu, attr):
                pfd = Perf.syscall(Perf.NR_PERF_EVENT_OPEN, ct.byref(attr),
                                   attr.pid, cpu, -1,
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
                attr.pid = pid
                attr.type = ptype
                attr.sample_type = Perf.PERF_SAMPLE_RAW
                if freq > 0:
                    # setup sampling
                    attr.flags = Perf.PERF_ATTR_FLAG_FREQ   # no mmap or comm
                    attr.sample_period = freq
                else:
                    attr.sample_period = 1
                attr.wakeup_events = 9999999                # don't wake up

                for cpu in get_online_cpus():
                        Perf._open_for_cpu(cpu, attr)
