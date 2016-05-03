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
import multiprocessing
import os
import re

class Perf(object):
        class perf_event_attr(ct.Structure):
                _fields_ = [
                        ('type', ct.c_uint),
                        ('size', ct.c_uint),
                        ('config', ct.c_ulong),
                        ('sample_period', ct.c_ulong),
                        ('sample_type', ct.c_ulong),
                        ('IGNORE1', ct.c_ulong),
                        ('IGNORE2', ct.c_ulong),
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

        NR_PERF_EVENT_OPEN = 298
        PERF_TYPE_TRACEPOINT = 2
        PERF_SAMPLE_RAW = 1024
        PERF_FLAG_FD_CLOEXEC = 8
        PERF_EVENT_IOC_SET_FILTER = 1074275334
        PERF_EVENT_IOC_ENABLE = 9216

        libc = ct.CDLL('libc.so.6', use_errno=True)
        syscall = libc.syscall          # not declaring vararg types
        ioctl = libc.ioctl              # not declaring vararg types

        @staticmethod
        def _open_for_cpu(cpu, attr):
                pfd = Perf.syscall(Perf.NR_PERF_EVENT_OPEN, ct.byref(attr),
                                   -1, cpu, -1, Perf.PERF_FLAG_FD_CLOEXEC)
                if pfd < 0:
                        errno_ = ct.get_errno()
                        raise OSError(errno_, os.strerror(errno_))
                if Perf.ioctl(pfd, Perf.PERF_EVENT_IOC_SET_FILTER,
                              "common_pid == -17") < 0:
                        errno_ = ct.get_errno()
                        raise OSError(errno_, os.strerror(errno_))
                if Perf.ioctl(pfd, Perf.PERF_EVENT_IOC_ENABLE, 0) < 0:
                        errno_ = ct.get_errno()
                        raise OSError(errno_, os.strerror(errno_))

        @staticmethod
        def perf_event_open(tpoint_id):
                attr = Perf.perf_event_attr()
                attr.config = tpoint_id
                attr.type = Perf.PERF_TYPE_TRACEPOINT
                attr.sample_type = Perf.PERF_SAMPLE_RAW
                attr.sample_period = 1
                attr.wakeup_events = 1
                for cpu in range(0, multiprocessing.cpu_count()):
                        Perf._open_for_cpu(cpu, attr)

class Tracepoint(object):
        enabled_tracepoints = []
        trace_root = "/sys/kernel/debug/tracing"
        event_root = os.path.join(trace_root, "events")

        @classmethod
        def _any_tracepoints_enabled(cls):
                return len(cls.enabled_tracepoints) > 0

        @classmethod
        def generate_decl(cls):
                if not cls._any_tracepoints_enabled():
                        return ""
                return "\nBPF_HASH(__trace_di, u64, u64);\n"

        @classmethod
        def generate_entry_probe(cls):
                if not cls._any_tracepoints_enabled():
                        return ""
                return """
int __trace_entry_update(struct pt_regs *ctx)
{
        u64 tid = bpf_get_current_pid_tgid();
        u64 val = PT_REGS_PARM1(ctx);
        __trace_di.update(&tid, &val);
        return 0;
}
"""

        def __init__(self, category, event, tp_id):
                self.category = category
                self.event = event
                self.tp_id = tp_id
                self._retrieve_struct_fields()

        def _retrieve_struct_fields(self):
                self.struct_fields = []
                format_lines = Tracepoint.get_tpoint_format(self.category,
                                                            self.event)
                for line in format_lines:
                        match = re.search(r'field:([^;]*);.*size:(\d+);', line)
                        if match is None:
                                continue
                        parts = match.group(1).split()
                        field_name = parts[-1:][0]
                        field_type = " ".join(parts[:-1])
                        field_size = int(match.group(2))
                        if "__data_loc" in field_type:
                                continue
                        if field_name.startswith("common_"):
                                continue
                        self.struct_fields.append((field_type, field_name))

        def _generate_struct_fields(self):
                text = ""
                for field_type, field_name in self.struct_fields:
                        text += "        %s %s;\n" % (field_type, field_name)
                return text

        def generate_struct(self):
                self.struct_name = self.event + "_trace_entry"
                return """
struct %s {
        u64 __do_not_use__;
%s
};
                """ % (self.struct_name, self._generate_struct_fields())

        def _generate_struct_locals(self):
                text = ""
                for field_type, field_name in self.struct_fields:
                        if field_type == "char" and field_name.endswith(']'):
                                # Special case for 'char whatever[N]', should
                                # be assigned to a 'char *'
                                field_type = "char *"
                                field_name = re.sub(r'\[\d+\]$', '', field_name)
                        text += "        %s %s = tp.%s;\n" % (
                                        field_type, field_name, field_name)
                return text

        def generate_get_struct(self):
                return """
        u64 tid = bpf_get_current_pid_tgid();
        u64 *di = __trace_di.lookup(&tid);
        if (di == 0) { return 0; }
        struct %s tp = {};
        bpf_probe_read(&tp, sizeof(tp), (void *)*di);
%s
                """ % (self.struct_name, self._generate_struct_locals())

        @classmethod
        def enable_tracepoint(cls, category, event):
                tp_id = cls.get_tpoint_id(category, event)
                if tp_id == -1:
                        raise ValueError("no such tracepoint found: %s:%s" %
                                         (category, event))
                Perf.perf_event_open(tp_id)
                new_tp = Tracepoint(category, event, tp_id)
                cls.enabled_tracepoints.append(new_tp)
                return new_tp

        @staticmethod
        def get_tpoint_id(category, event):
                evt_dir = os.path.join(Tracepoint.event_root, category, event)
                try:
                        return int(
                          open(os.path.join(evt_dir, "id")).read().strip())
                except:
                        return -1

        @staticmethod
        def get_tpoint_format(category, event):
                evt_dir = os.path.join(Tracepoint.event_root, category, event)
                try:
                        return open(os.path.join(evt_dir, "format")).readlines()
                except:
                        return ""

        @classmethod
        def attach(cls, bpf):
                if cls._any_tracepoints_enabled():
                        bpf.attach_kprobe(event="tracing_generic_entry_update",
                                          fn_name="__trace_entry_update")

