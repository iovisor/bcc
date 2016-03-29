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

