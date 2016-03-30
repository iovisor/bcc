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

class ProcStat(object):
        def __init__(self, pid):
                self.pid = pid
                self.exe = self._get_exe()
                self.start_time = self._get_start_time()

        def is_stale(self):
                return self.exe != self._get_exe() or \
                       self.start_time != self._get_start_time()

        def _get_exe(self):
                return os.popen("readlink -f /proc/%d/exe" % self.pid).read()

        def _get_start_time(self):
                return os.popen("cut -d' ' -f 22 /proc/%d/stat" %
                                self.pid).read()

class ProcUtils(object):
        @staticmethod
        def get_load_address(pid, bin_path):
                """
                get_load_address(pid, bin_path)

                Returns the address at which the specified module is loaded
                in the specified process. The module path must match exactly
                the file system path, not a symbolic link.
                """
                with open("/proc/%d/maps" % pid) as m:
                        maps = m.readlines()
                addrs = map(lambda l: l.split('-')[0],
                            filter(lambda l: bin_path in l, maps)
                            )
                if len(addrs) == 0:
                        raise ValueError("lib %s not loaded in pid %d"
                                        % (bin_path, pid))
                return int(addrs[0], 16)

        @staticmethod
        def get_modules(pid):
                """
                get_modules(pid)

                Returns a list of all the modules loaded into the specified
                process. Modules are enumerated by looking at /proc/$PID/maps
                and returning the module name for regions that contain
                executable code.
                """
                with open("/proc/%d/maps" % pid) as f:
                        maps = f.readlines()
                modules = []
                for line in maps:
                        parts = line.strip().split()
                        if len(parts) < 6:
                                continue
                        if parts[5][0] == '[' or not 'x' in parts[1]:
                                continue
                        modules.append(parts[5])
                return modules

        @staticmethod
        def is_shared_object(bin_path):
                """
                is_shared_object(bin_path)

                Returns whether the specified binary is a shared object, rather
                than an executable. If it is neither, an error is raised.
                """
                mime_type = os.popen("file --mime-type -b %s" % bin_path
                                ).read().strip()
                if mime_type == "application/x-sharedlib":
                        return True
                if mime_type == "application/x-executable":
                        return False
                raise ValueError("invalid mime type %s for binary %s" %
                                (mime_type, bin_path))

        @staticmethod
        def traverse_symlink(path):
                """Returns the actual path behind the specified symlink."""
                return os.popen("readlink -f %s" % path).read().strip()

        @staticmethod
        def which(bin_path):
                """
                which(bin_path)

                Traverses the PATH environment variable, looking for the first
                directory that contains an executable file named bin_path, and
                returns the full path to that file, or None if no such file
                can be found. This is meant to replace invocations of the
                "which" shell utility, which doesn't have portable semantics
                for skipping aliases.
                """
                # Source: http://stackoverflow.com/a/377028
                def is_exe(fpath):
                        return os.path.isfile(fpath) and \
                               os.access(fpath, os.X_OK)

                fpath, fname = os.path.split(bin_path)
                if fpath:
                        if is_exe(bin_path):
                                return bin_path
                else:
                        for path in os.environ["PATH"].split(os.pathsep):
                                path = path.strip('"')
                                exe_file = os.path.join(path, bin_path)
                                if is_exe(exe_file):
                                        return exe_file
                return None
