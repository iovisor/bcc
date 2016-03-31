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

import os
import struct
import re

from . import BPF
from . import ProcStat, ProcUtils

class USDTArgument(object):
        def __init__(self, size, is_signed, location,
                     register=None, constant=None, deref_offset=None,
                     deref_name=None):
                self.size = size
                self.is_signed = is_signed
                self.location = location
                self.register = register
                self.constant = constant
                self.deref_offset = deref_offset
                self.deref_name = deref_name

        def _normalize_register(self):
                normalized = self.register
                if normalized is None:
                        return None
                if normalized.startswith('%'):
                        normalized = normalized[1:]
                if normalized in USDTArgument.translations:
                        normalized = USDTArgument.translations[normalized]
                return normalized

        translations = {
                "rax": "ax", "rbx": "bx", "rcx": "cx", "rdx": "dx",
                "rdi": "di", "rsi": "si", "rbp": "bp", "rsp": "sp",
                "rip": "ip", "eax": "ax", "ebx": "bx", "ecx": "cx",
                "edx": "dx", "edi": "di", "esi": "si", "ebp": "bp",
                "esp": "sp", "eip": "ip", "al": "ax", "bl": "bx",
                "cl": "cx", "dl": "dx"
                        }

        def generate_assign_to_local(self, local_name, pid=None):
                """
                generate_assign_to_local(local_name, pid=None)

                Generates an assignment statement that initializes a local
                variable with the value of this argument. Assumes that the
                struct pt_regs pointer is called 'ctx', and accesses registers
                from that pointer. The local variable must already be declared
                by the caller. Use get_type() to get the proper type for that
                declaration.

                The pid parameter is intended for use when the argument depends
                on an address that is process-specific. This only happens for
                arguments that are offsets from globals -- the load address for
                the global depends on the process. If no pid is specified and
                the argument depends on an address that is process-specific,
                an error is raised.

                Example output:
                        local1 = (u64)ctx->di;
                        {
                                u64 __tmp;
                                bpf_probe_read(&__tmp, sizeof(__tmp),
                                               (void *)(ctx->bp - 8));
                                bpf_probe_read(&local2, sizeof(local2),
                                               (void *)__tmp);
                        }
                """
                normalized_reg = self._normalize_register()
                if self.constant is not None:
                        # Simplest case, it's just a constant
                        return "%s = %d;" % (local_name, self.constant)
                if self.deref_offset is None:
                        # Simple read from the specified register
                        return "%s = (%s)ctx->%s;" % \
                                (local_name, self.get_type(), normalized_reg)
                        # Note that the cast to a smaller type should grab the
                        # relevant part of the register anyway, if we're dealing
                        # with 32/16/8-bit registers like ecx, dx, al, etc.

                if self.deref_offset is not None and self.deref_name is None:
                        # Add deref_offset to register value and bpf_probe_read
                        # from the resulting address
                        return \
"""{
        u64 __temp = ctx->%s + (%d);
        bpf_probe_read(&%s, sizeof(%s), (void *)__temp);
}                       """ % (normalized_reg, self.deref_offset,
                               local_name, local_name)

                # Final case: dereference global, need to find address of global
                # with the provided name and then potentially add deref_offset
                # and bpf_probe_read the result.
                return \
"""{
        u64 __temp = 0x%x + %d;
        bpf_probe_read(&%s, sizeof(%s), (void *)__temp);
}              """ % (self._get_global_address(pid), self.deref_offset,
                      local_name, local_name)

        def _get_global_address(self, pid=None):
                # If this is a library, we need to find its load address in the
                # specified process and then add the global symbol's offset.
                # If this is an executable, the global symbol's address doesn't
                # depend on the pid.
                bin_path = self.location.probe.bin_path
                offset = self._get_global_offset(bin_path)
                if ProcUtils.is_shared_object(self.location.probe.bin_path):
                        if pid is None:
                                raise ValueError("pid is required for " +
                                                 "argument '%s'" % str(self))
                        load_address = ProcUtils.get_load_address(pid, bin_path)
                        return load_address + offset
                else:
                        return offset

        def _get_global_offset(self, bin_path):
                with os.popen("objdump -tT %s | grep '\\s%s$'" %
                        (bin_path, self.deref_name)) as f:
                        lines = f.readlines()
                for line in lines:
                        parts = line.split()
                        if parts[5] != self.deref_name:
                                continue
                        return int(parts[0], 16)
                raise ValueError("can't find global symbol %s" %
                                 self.deref_name)

        def get_type(self):
                result_type = None
                if self.size == 1:
                        result_type = "char"
                elif self.size == 2:
                        result_type = "short"
                elif self.size == 4:
                        result_type = "int"
                elif self.size == 8:
                        result_type = "long"

                if result_type is None:
                        raise ValueError("arguments of size %d are not " +
                                         "currently supported" % self.size)

                if not self.is_signed:
                        result_type = "unsigned " + result_type

                return result_type

        def __str__(self):
                prefix = "%d %s bytes @ " % (self.size,
                        "  signed" if self.is_signed else "unsigned")
                if self.constant is not None:
                        return prefix + "constant %d" % self.constant
                if self.deref_offset is None:
                        return prefix + "register " + self.register
                if self.deref_offset is not None and self.deref_name is None:
                        return prefix + "%d(%s)" % (self.deref_offset,
                                                    self.register)
                return prefix + "%d from %s global" % (self.deref_offset,
                                                       self.deref_name)

class USDTProbeLocation(object):
        def __init__(self, address, args, probe):
                self.address = address
                self.raw_args = args
                self.probe = probe
                self.args = []
                self._parse_args()

        def generate_usdt_assignments(self, prefix="arg", pid=None):
                text = ""
                for i, arg in enumerate(self.args, 1):
                        text += (" "*16) + \
                                arg.generate_assign_to_local(
                                        "%s%d" % (prefix, i), pid) + "\n"
                return text

        def _parse_args(self):
                for arg in self.raw_args.split():
                        self._parse_arg(arg.strip())

        def _parse_arg(self, arg):
                qregs = ["%rax", "%rbx", "%rcx", "%rdx", "%rdi", "%rsi",
                         "%rbp", "%rsp", "%rip", "%r8", "%r9", "%r10", "%r11",
                         "%r12", "%r13", "%r14", "%r15"]
                dregs = ["%eax", "%ebx", "%ecx", "%edx", "%edi", "%esi",
                         "%ebp", "%esp", "%eip"]
                wregs = ["%ax",  "%bx",  "%cx",  "%dx",  "%di",  "%si",
                         "%bp",  "%sp",  "%ip"]
                bregs = ["%al", "%bl", "%cl", "%dl"]

                any_reg = "(" + "|".join(qregs + dregs + wregs + bregs) + ")"

                # -4@$0, 8@$1234
                m = re.match(r'(\-?)(\d+)@\$(\-?)(\d+)', arg)
                if m is not None:
                        sign = -1 if len(m.group(3)) > 0 else 1
                        self.args.append(USDTArgument(
                                int(m.group(2)),
                                m.group(1) == '-',
                                self,
                                constant=sign*int(m.group(4))
                                ))
                        return

                # %rdi, %rax, %rsi
                m = re.match(any_reg, arg)
                if m is not None:
                        if arg in qregs:
                                size = 8
                        elif arg in dregs:
                                size = 4
                        elif arg in wregs:
                                size = 2
                        elif arg in bregs:
                                size = 1
                        self.args.append(USDTArgument(
                                size, False, self, register=arg
                                ))
                        return

                # -8@%rbx, 4@%r12
                m = re.match(r'(\-?)(\d+)@' + any_reg, arg)
                if m is not None:
                        self.args.append(USDTArgument(
                                int(m.group(2)),       # Size (in bytes)
                                m.group(1) == '-',     # Signed
                                self,
                                register=m.group(3)
                                ))
                        return

                # 8@-8(%rbp), 4@(%rax)
                m = re.match(r'(\-?)(\d+)@(\-?)(\d*)\(' + any_reg + r'\)', arg)
                if m is not None:
                        deref_offset = int(m.group(4)) if len(m.group(4)) > 0 \
                                                       else 0
                        if m.group(3) == '-':
                                deref_offset = -deref_offset
                        self.args.append(USDTArgument(
                                int(m.group(2)), m.group(1) == '-', self,
                                register=m.group(5), deref_offset=deref_offset
                                ))
                        return

                # -4@global_max_action(%rip)
                m = re.match(r'(\-?)(\d+)@(\w+)\(%rip\)', arg)
                if m is not None:
                        self.args.append(USDTArgument(
                                int(m.group(2)), m.group(1) == '-', self,
                                register="%rip", deref_name=m.group(3),
                                deref_offset=0
                                ))
                        return

                # 8@24+mp_(@rip)
                m = re.match(r'(\-?)(\d+)@(\-?)(\d+)\+(\w+)\(%rip\)', arg)
                if m is not None:
                        deref_offset = int(m.group(4))
                        if m.group(3) == '-':
                                deref_offset = -deref_offset
                        self.args.append(USDTArgument(
                                int(m.group(2)), m.group(1) == '-', self,
                                register="%rip", deref_offset=deref_offset,
                                deref_name=m.group(5)
                                ))
                        return

                raise ValueError("unrecognized argument format: '%s'" % arg)


class USDTProbe(object):
        def __init__(self, bin_path, provider, name, semaphore):
                self.bin_path = bin_path
                self.provider = provider
                self.name = name
                self.semaphore = semaphore
                self.enabled_procs = {}
                self.proc_semas = {}
                self.locations = []

        def add_location(self, location, arguments):
                self.locations.append(USDTProbeLocation(
                        location, arguments, self))

        def need_enable(self):
                """
                Returns whether this probe needs to be enabled in each
                process that uses it. Probes that must be enabled can't be
                traced without specifying a specific pid.
                """
                return self.semaphore != 0

        def enable(self, pid):
                """Enables this probe in the specified process."""
                self._add_to_semaphore(pid, +1)
                self.enabled_procs[pid] = ProcStat(pid)

        def disable(self, pid):
                """Disables the probe in the specified process."""
                if pid not in self.enabled_procs:
                        raise ValueError("probe wasn't enabled in this process")
                # Because of the possibility of pid wrap, it's extremely
                # important to verify that we are still dealing with the same
                # process. Otherwise, we are overwriting random memory in some
                # other process :-)
                if not self.enabled_procs[pid].is_stale():
                        self._add_to_semaphore(pid, -1)
                del(self.enabled_procs[pid])

        def get_arg_types(self):
                """
                Returns the argument types used by this probe. Different probe
                locations might use different argument types, e.g. signed i32
                vs. unsigned i64. We should take the largest type, and the
                sign really doesn't matter that much.
                """
                arg_types = []
                for i in range(len(self.locations[0].args)):
                        max_size_loc = max(self.locations, key=lambda loc:
                                loc.args[i].size)
                        arg_types.append(max_size_loc.args[i].get_type())
                return arg_types

        def generate_usdt_thunks(self, name_prefix, thunk_names):
                text = ""
                for i in range(len(self.locations)):
                        thunk_name = "%s_thunk_%d" % (name_prefix, i)
                        thunk_names.append(thunk_name)
                        text += """
int %s(struct pt_regs *ctx) {
        return %s(ctx, %d);
}                       """ % (thunk_name, name_prefix, i)
                return text

        def generate_usdt_cases(self, pid=None):
                text = ""
                for i, arg_type in enumerate(self.get_arg_types(), 1):
                        text += "        %s arg%d = 0;\n" % (arg_type, i)
                for i, location in enumerate(self.locations):
                        assignments = location.generate_usdt_assignments(
                                                                pid=pid)
                        text += \
"""
        if (__loc_id == %d) {
%s
        }               \n""" % (i, assignments)
                return text

        def _ensure_proc_sema(self, pid):
                if pid in self.proc_semas:
                        return self.proc_semas[pid]

                if ProcUtils.is_shared_object(self.bin_path):
                        # Semaphores declared in shared objects are relative
                        # to that shared object's load address
                        sema_addr = ProcUtils.get_load_address(
                                        pid, self.bin_path) + self.semaphore
                else:
                        sema_addr = self.semaphore      # executable, absolute
                self.proc_semas[pid] = sema_addr
                return sema_addr

        def _add_to_semaphore(self, pid, val):
                sema_addr = self._ensure_proc_sema(pid)
                with open("/proc/%d/mem" % pid, "r+b") as fd:
                        fd.seek(sema_addr, 0)
                        prev = struct.unpack("H", fd.read(2))[0]
                        fd.seek(sema_addr, 0)
                        fd.write(struct.pack("H", prev + val))

        def __str__(self):
                return "%s %s:%s" % (self.bin_path, self.provider, self.name)

        def display_verbose(self):
                text = str(self) + " [sema 0x%x]\n" % self.semaphore
                for location in self.locations:
                        text += "  location 0x%x raw args: %s\n" % \
                                        (location.address, location.raw_args)
                        for arg in location.args:
                                text += "    %s\n" % str(arg)
                return text

class USDTReader(object):
        def __init__(self, bin_path="", pid=-1):
                """
                __init__(bin_path="", pid=-1)

                Reads all the probes from the specified library, executable,
                or process. If a pid is specified, all the libraries (including
                the executable) are searched for probes. After initialization
                completes, the found probes are in the 'probes' property.
                """
                self.probes = []
                if pid != -1:
                        for mod in ProcUtils.get_modules(pid):
                                self._add_probes(mod)
                elif len(bin_path) != 0:
                        self._add_probes(bin_path)
                else:
                        raise ValueError("pid or bin_path is required")

        def _add_probes(self, bin_path):
                if not os.path.isfile(bin_path):
                        attempt1 = ProcUtils.which(bin_path)
                        if attempt1 is None or not os.path.isfile(attempt1):
                                attempt2 = BPF.find_library(bin_path)
                                if attempt2 is None or \
                                   not os.path.isfile(attempt2):
                                        raise ValueError("can't find %s"
                                                         % bin_path)
                                else:
                                        bin_path = attempt2
                        else:
                                bin_path = attempt1
                bin_path = ProcUtils.traverse_symlink(bin_path)

                with os.popen("readelf -n %s 2>/dev/null" % bin_path) as child:
                        notes = child.read()
                for match in re.finditer(r'stapsdt.*?NT_STAPSDT.*?Provider: ' +
                        r'(\w+).*?Name: (\w+).*?Location: (\w+), Base: ' +
                        r'(\w+), Semaphore: (\w+).*?Arguments: ([^\n]*)',
                        notes, re.DOTALL):
                        self._add_or_merge_probe(
                                bin_path, match.group(1), match.group(2),
                                int(match.group(3), 16),
                                int(match.group(5), 16), match.group(6)
                                )
                # Note that BPF.attach_uprobe takes care of subtracting
                # the load address for that bin, so we can report the actual
                # address that appears in the note

        def _add_or_merge_probe(self, bin_path, provider, name, location,
                                semaphore, arguments):
                matches = filter(lambda p: p.provider == provider and \
                                           p.name == name, self.probes)
                if len(matches) > 0:
                        probe = matches[0]
                else:
                        probe = USDTProbe(bin_path, provider, name, semaphore)
                        self.probes.append(probe)
                probe.add_location(location, arguments)

        def __str__(self):
                return "\n".join(map(USDTProbe.display_verbose, self.probes))

