#!/usr/bin/env python

from unittest import main, skipUnless, TestCase
import distutils.version
import os
import subprocess
import sys
import tempfile

TOOLS_DIR = "../../tools/"


class cfg:
    cmd_format = ""

    # Amount of memory to leak. Note, that test application allocates memory
    # for its own needs in libc, so this amount should be large enough to be
    # the biggest allocation.
    leaking_amount = 30000


def kernel_version_ge(major, minor):
    # True if running kernel is >= X.Y
    version = distutils.version.LooseVersion(os.uname()[2]).version
    if version[0] > major:
        return True
    if version[0] < major:
        return False
    if minor and version[1] < minor:
        return False
    return True


def setUpModule():
    # Build the memory leaking application.
    c_src = 'test_tools_memleak_leaker_app.c'
    tmp_dir = tempfile.mkdtemp(prefix='bcc-test-memleak-')
    c_src_full = os.path.dirname(sys.argv[0]) + os.path.sep + c_src
    exec_dst = tmp_dir + os.path.sep + 'leaker_app'

    if subprocess.call(['gcc', '-g', '-O0', '-o', exec_dst, c_src_full]) != 0:
        print("can't compile the leaking application")
        raise Exception

    # Taking two snapshot with one second interval. Getting the largest
    # allocation. Since attaching to a program happens with a delay, we wait
    # for the first snapshot, then issue the command to the app. Finally,
    # second snapshot is used to extract the information.
    # Helper utilities "timeout" and "setbuf" are used to limit overall running
    # time, and to disable buffering.
    cfg.cmd_format = (
        'stdbuf -o 0 -i 0 timeout -s KILL 10s ' + TOOLS_DIR +
        'memleak.py -c "{} {{}} {}" -T 1 1 2'.format(exec_dst,
                                                     cfg.leaking_amount))


@skipUnless(kernel_version_ge(4, 6), "requires kernel >= 4.6")
class MemleakToolTests(TestCase):
    def tearDown(self):
        if self.p:
            del(self.p)
    def run_leaker(self, leak_kind):
        # Starting memleak.py, which in turn launches the leaking application.
        self.p = subprocess.Popen(cfg.cmd_format.format(leak_kind),
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  shell=True)

        # Waiting for the first report.
        while True:
            self.p.poll()
            if self.p.returncode is not None:
                break
            line = self.p.stdout.readline()
            if b"with outstanding allocations" in line:
                break

        # At this point, memleak.py have already launched application and set
        # probes. Sending command to the leaking application to make its
        # allocations.
        out = self.p.communicate(input=b"\n")[0]

        # If there were memory leaks, they are in the output. Filter the lines
        # containing "byte" substring. Every interesting line is expected to
        # start with "N bytes from"
        x = [x for x in out.split(b'\n') if b'byte' in x]

        self.assertTrue(len(x) >= 1,
                        msg="At least one line should have 'byte' substring.")

        # Taking last report.
        x = x[-1].split()
        self.assertTrue(len(x) >= 1,
                        msg="There should be at least one word in the line.")

        # First word is the leak amount in bytes.
        return int(x[0])

    def test_malloc(self):
        self.assertEqual(cfg.leaking_amount, self.run_leaker("malloc"))

    def test_calloc(self):
        self.assertEqual(cfg.leaking_amount, self.run_leaker("calloc"))

    def test_realloc(self):
        self.assertEqual(cfg.leaking_amount, self.run_leaker("realloc"))

    def test_posix_memalign(self):
        self.assertEqual(cfg.leaking_amount, self.run_leaker("posix_memalign"))

    def test_valloc(self):
        self.assertEqual(cfg.leaking_amount, self.run_leaker("valloc"))

    def test_memalign(self):
        self.assertEqual(cfg.leaking_amount, self.run_leaker("memalign"))

    def test_pvalloc(self):
        self.assertEqual(cfg.leaking_amount, self.run_leaker("pvalloc"))

    def test_aligned_alloc(self):
        self.assertEqual(cfg.leaking_amount, self.run_leaker("aligned_alloc"))


if __name__ == "__main__":
    main()
