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

from subprocess import Popen, PIPE, STDOUT

class ProcessSymbols(object):
    def __init__(self, pid):
        """
        Initializes the process symbols store for the specified pid.
        Call refresh_code_ranges() periodically if you anticipate changes
        in the set of loaded libraries or their addresses.
        """
        self.pid = pid
        self.refresh_code_ranges()

    def refresh_code_ranges(self):
        self.code_ranges = self._get_code_ranges()
        self.ranges_cache = {}
        self.exe = self._get_exe()
        self.start_time = self._get_start_time()

    def _get_exe(self):
        return ProcessSymbols._run_command_get_output(
                "readlink -f /proc/%d/exe" % self.pid)

    def _get_start_time(self):
        return ProcessSymbols._run_command_get_output(
                "cut -d' ' -f 22 /proc/%d/stat" % self.pid)

    @staticmethod
    def _is_binary_segment(parts):
        return len(parts) == 6 and parts[5][0] != '[' and 'x' in parts[1]

    def _get_code_ranges(self):
        ranges = {}
        raw_ranges = open("/proc/%d/maps" % self.pid).readlines()
        # A typical line from /proc/PID/maps looks like this:
        # 7f21b6635000-7f21b67eb000 r-xp ... /usr/lib64/libc-2.21.so
        # We are looking for executable segments that have a .so file
        # or the main executable. The first two lines are the range of
        # that memory segment, which we index by binary name.
        for raw_range in raw_ranges:
            parts = raw_range.split()
            if not ProcessSymbols._is_binary_segment(parts):
                continue
            binary = parts[5]
            range_parts = parts[0].split('-')
            addr_range = (int(range_parts[0], 16), int(range_parts[1], 16))
            ranges[binary] = addr_range
        return ranges

    @staticmethod
    def _is_function_symbol(parts):
        return len(parts) == 6 and parts[3] == ".text" and parts[2] == "F"

    @staticmethod
    def _run_command_get_output(command):
        p = Popen(command.split(), stdout=PIPE, stderr=STDOUT)
        return iter(p.stdout.readline, b'')

    def _get_sym_ranges(self, binary):
        if binary in self.ranges_cache:
            return self.ranges_cache[binary]
        sym_ranges = {}
        raw_symbols = ProcessSymbols._run_command_get_output(
                "objdump -t %s" % binary)
        for raw_symbol in raw_symbols:
            # A typical line from objdump -t looks like this:
            # 00000000004007f5 g F .text 000000000000010e main
            # We only care about functions in the .text segment.
            # The first number is the start address, and the second
            # number is the length.
            parts = raw_symbol.split()
            if not ProcessSymbols._is_function_symbol(parts):
                continue
            sym_start = int(parts[0], 16)
            sym_len = int(parts[4], 16)
            sym_name = parts[5]
            sym_ranges[sym_name] = (sym_start, sym_len)
            self.ranges_cache[binary] = sym_ranges
        return sym_ranges

    def _decode_sym(self, binary, offset):
        sym_ranges = self._get_sym_ranges(binary)
        # Find the symbol that contains the specified offset.
        # There might not be one.
        for name, (start, length) in sym_ranges.items():
            if offset >= start and offset <= (start + length):
                return "%s+0x%x" % (name, offset - start)
        return "%x" % offset

    def _check_pid_wrap(self):
        # If the pid wrapped, our exe name and start time must have changed.
        # Detect this and get rid of the cached ranges.
        if self.exe != self._get_exe() or \
           self.start_time != self._get_start_time():
            self.refresh_code_ranges()

    def decode_addr(self, addr):
        """
        Given an address, return the best symbolic representation of it.
        If it doesn't fall in any module, return its hex string. If it
        falls within a module but we don't have a symbol for it, return
        the hex string and the module. If we do have a symbol for it,
        return the symbol and the module, e.g. "readline+0x10 [bash]".
        """
        self._check_pid_wrap()
        # Find the binary that contains the specified address.
        # For .so files, look at the relative address; for the main
        # executable, look at the absolute address.
        for binary, (start, end) in self.code_ranges.items():
            if addr >= start and addr <= end:
                offset = addr - start \
                         if binary.endswith(".so") else addr
                return "%s [%s]" % (self._decode_sym(binary, offset),
                                    binary)
        return "%x" % addr

