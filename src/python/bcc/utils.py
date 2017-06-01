# Copyright 2016 Catalysts GmbH
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
import sys
import traceback
import warnings

from .libbcc import lib

def _read_cpu_range(path):
    cpus = []
    with open(path, 'r') as f:
        cpus_range_str = f.read()
        for cpu_range in cpus_range_str.split(','):
            rangeop = cpu_range.find('-')
            if rangeop == -1:
                cpus.append(int(cpu_range))
            else:
                start = int(cpu_range[:rangeop])
                end = int(cpu_range[rangeop+1:])
                cpus.extend(range(start, end+1))
    return cpus

def get_online_cpus():
    return _read_cpu_range('/sys/devices/system/cpu/online')

def get_possible_cpus():
    return _read_cpu_range('/sys/devices/system/cpu/possible')

def detect_language(candidates, pid):
    res = lib.bcc_procutils_language(pid)
    language = ct.cast(res, ct.c_char_p).value.decode()
    return language if language in candidates else None

FILESYSTEMENCODING = sys.getfilesystemencoding()

def printb(s, file=sys.stdout):
    """
    printb(s)

    print a bytes object to stdout and flush
    """
    buf = file.buffer if hasattr(file, "buffer") else file

    buf.write(s)
    buf.write(b"\n")
    file.flush()

class ArgString(object):
    """
    ArgString(arg)

    encapsulate a system argument that can be easily coerced to a bytes()
    object, which is better for comparing to kernel or probe data (which should
    never be en/decode()'ed).
    """
    def __init__(self, arg):
        if sys.version_info[0] >= 3:
            self.s = arg
        else:
            self.s = arg.decode(FILESYSTEMENCODING)

    def __bytes__(self):
        return self.s.encode(FILESYSTEMENCODING)

    def __str__(self):
        return self.__bytes__()

def warn_with_traceback(message, category, filename, lineno, file=None, line=None):
    log = file if hasattr(file, "write") else sys.stderr
    traceback.print_stack(f=sys._getframe(2), file=log)
    log.write(warnings.formatwarning(message, category, filename, lineno, line))

# uncomment to get full tracebacks for invalid uses of python3+str in arguments
#warnings.showwarning = warn_with_traceback

_strict_bytes = False
def _assert_is_bytes(arg):
    if arg is None:
        return arg
    if _strict_bytes:
        assert type(arg) is bytes, "not a bytes object: %r" % arg
    elif type(arg) is not bytes:
        #warnings.warn("not a bytes object: %r" % arg, DeprecationWarning, 2)
        return ArgString(arg).__bytes__()
    return arg

