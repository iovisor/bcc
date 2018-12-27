#!/usr/bin/env python
#
# USAGE: test_usdt3.py
#
# Copyright 2018 Facebook, Inc
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF, USDT
from unittest import main, TestCase
from subprocess import Popen, PIPE
import ctypes as ct
import inspect, os, tempfile

class TestUDST(TestCase):
    def setUp(self):
        common_h = b"""
#include "folly/tracing/StaticTracepoint.h"

static inline void record_val(int val)
{
  FOLLY_SDT(test, probe, val);
}

extern void record_a(int val);
extern void record_b(int val);
"""

        a_c = b"""
#include <stdio.h>
#include "common.h"

void record_a(int val)
{
    record_val(val);
}
"""

        b_c = b"""
#include <stdio.h>
#include "common.h"

void record_b(int val)
{
    record_val(val);
}
"""

        m_c = b"""
#include <stdio.h>
#include <unistd.h>
#include "common.h"

int main() {
   while (1) {
     record_a(1);
     record_b(2);
     record_val(3);
     sleep(1);
   }
   return 0;
}
"""
        # BPF program
        self.bpf_text = """
BPF_PERF_OUTPUT(event);
int do_trace(struct pt_regs *ctx) {
    int result = 0;
    bpf_usdt_readarg(1, ctx, &result);
    event.perf_submit(ctx, &result, sizeof(result));
    return 0;
};
"""

        def _create_file(name, text):
            text_file = open(name, "wb")
            text_file.write(text)
            text_file.close()

        # Create source files
        self.tmp_dir = tempfile.mkdtemp()
        print("temp directory: " + self.tmp_dir)
        _create_file(self.tmp_dir + "/common.h", common_h)
        _create_file(self.tmp_dir + "/a.c", a_c)
        _create_file(self.tmp_dir + "/b.c", b_c)
        _create_file(self.tmp_dir + "/m.c", m_c)

        # Compilation
        # the usdt test:probe exists in liba.so, libb.so and a.out
        include_path = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe()))) + "/include"
        a_src = self.tmp_dir + "/a.c"
        a_obj = self.tmp_dir + "/a.o"
        a_lib = self.tmp_dir + "/liba.so"
        b_src = self.tmp_dir + "/b.c"
        b_obj = self.tmp_dir + "/b.o"
        b_lib = self.tmp_dir + "/libb.so"
        m_src = self.tmp_dir + "/m.c"
        m_bin = self.tmp_dir + "/a.out"
        m_linker_opt = " -L" + self.tmp_dir + " -la -lb"
        self.assertEqual(os.system("gcc -I" + include_path + " -fpic -c -o " + a_obj + " " + a_src), 0)
        self.assertEqual(os.system("gcc -I" + include_path + " -fpic -c -o " + b_obj + " " + b_src), 0)
        self.assertEqual(os.system("gcc -shared -o " + a_lib + " " + a_obj), 0)
        self.assertEqual(os.system("gcc -shared -o " + b_lib + " " + b_obj), 0)
        self.assertEqual(os.system("gcc -I" + include_path + " " + m_src + " -o " + m_bin + m_linker_opt), 0)

        # Run the application
        self.app = Popen([m_bin], env=dict(os.environ, LD_LIBRARY_PATH=self.tmp_dir))
        # os.system("tplist.py -vvv -p " + str(self.app.pid))

    def test_attach1(self):
        # enable USDT probe from given PID and verifier generated BPF programs
        u = USDT(pid=int(self.app.pid))
        u.enable_probe(probe="probe", fn_name="do_trace")
        b = BPF(text=self.bpf_text, usdt_contexts=[u])

        # processing events
        self.probe_value_1 = 0
        self.probe_value_2 = 0
        self.probe_value_3 = 0
        self.probe_value_other = 0

        def print_event(cpu, data, size):
            result = ct.cast(data, ct.POINTER(ct.c_int)).contents
            if result.value == 1:
                self.probe_value_1 = 1
            elif result.value == 2:
                self.probe_value_2 = 1
            elif result.value == 3:
                self.probe_value_3 = 1
            else:
                self.probe_value_other = 1

        b["event"].open_perf_buffer(print_event)
        for i in range(100):
            if (self.probe_value_1 == 0 or
                self.probe_value_2 == 0 or
                self.probe_value_3 == 0 or
                self.probe_value_other != 0):
                b.perf_buffer_poll()
            else:
                break;

        self.assertTrue(self.probe_value_1 != 0)
        self.assertTrue(self.probe_value_2 != 0)
        self.assertTrue(self.probe_value_3 != 0)
        self.assertTrue(self.probe_value_other == 0)

    def tearDown(self):
        # kill the subprocess, clean the environment
        self.app.kill()
        self.app.wait()
        os.system("rm -rf " + self.tmp_dir)

if __name__ == "__main__":
    main()
