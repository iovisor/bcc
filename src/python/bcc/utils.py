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
import re

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

def printb(s, file=sys.stdout, nl=1):
    """
    printb(s)

    print a bytes object to stdout and flush
    """
    buf = file.buffer if hasattr(file, "buffer") else file

    buf.write(s)
    if nl:
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
        return self.s

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
        warnings.warn("not a bytes object: %r" % arg, DeprecationWarning, 2)
        return ArgString(arg).__bytes__()
    return arg

class StrcmpRewrite(object):
    @staticmethod
    def _generate_streq_function(string, probe_read_func, streq_functions,
                                probeid):
        fname = "streq_%d" % probeid
        streq_functions += """
static inline bool %s(char const *ignored, uintptr_t str) {
        char needle[] = %s;
        char haystack[sizeof(needle)];
        %s(&haystack, sizeof(haystack), (void *)str);
        for (int i = 0; i < sizeof(needle) - 1; ++i) {
                if (needle[i] != haystack[i]) {
                        return false;
                }
        }
        return true;
}
        """ % (fname, string, probe_read_func)
        return fname, streq_functions

    @staticmethod
    def rewrite_expr(expr, bin_cmp, is_user, probe_user_list, streq_functions,
                    probeid):
        if bin_cmp:
            STRCMP_RE = 'STRCMP\\(\"([^"]+)\\",(.+?)\\)'
        else:
            STRCMP_RE = 'STRCMP\\(("[^"]+\\"),(.+?)\\)'
        matches = re.finditer(STRCMP_RE, expr)
        for match in matches:
            string = match.group(1)
            probe_read_func = "bpf_probe_read"
            # if user probe or @user tag is specified, use
            # bpf_probe_read_user for char* read
            if is_user or \
                match.group(2).strip() in probe_user_list:
                    probe_read_func = "bpf_probe_read_user"
            fname, streq_functions = StrcmpRewrite._generate_streq_function(
                                            string, probe_read_func,
                                            streq_functions, probeid)
            probeid += 1
            expr = expr.replace("STRCMP", fname, 1)
        rdict = {
            "expr": expr,
            "streq_functions": streq_functions,
            "probeid": probeid
        }
        return rdict
