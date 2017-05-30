#!/usr/bin/python
#
# USAGE: test_usdt.py
#
# Copyright 2017 Facebook, Inc
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF, USDT
from unittest import main, TestCase
from subprocess import Popen, PIPE
from tempfile import NamedTemporaryFile
import os
import signal

class TestUDST(TestCase):
    def setUp(self):
        # Application, minimum, to define three trace points
        app_text = b"""
#include <unistd.h>
#include <folly/tracing/StaticTracepoint.h>

int main() {
  char s[100];
  int i, a = 20, b = 40;
  for (i = 0; i < 100; i++) s[i] = (i & 7) + (i & 6);
  while (1) {
    FOLLY_SDT(test, probe_point_1, s[7], b);
    FOLLY_SDT(test, probe_point_3, a, b);
    sleep(3);
    a++; b++;
    FOLLY_SDT(test, probe_point_1, s[4], a);
    FOLLY_SDT(test, probe_point_2, 5, s[10]);
    FOLLY_SDT(test, probe_point_3, s[4], s[7]);
  }
  return 1;
}
"""
        # BPF program
        self.bpf_text = """
#include <uapi/linux/ptrace.h>
int do_trace(struct pt_regs *ctx) {
    return 0;
};
int do_trace2(struct pt_regs *ctx) {
    return 0;
}
int do_trace3(struct pt_regs *ctx) {
    return 0;
}
"""

        # Compile and run the application
        self.ftemp = NamedTemporaryFile(delete=False)
        self.ftemp.close()
        comp = Popen(["gcc", "-I", "%s/include" % os.getcwd(),
                      "-x", "c", "-o", self.ftemp.name, "-"],
                     stdin=PIPE)
        comp.stdin.write(app_text)
        comp.stdin.close()
        self.assertEqual(comp.wait(), 0)
        self.app = Popen([self.ftemp.name])

    def test_attach1(self):
        # enable USDT probe from given PID and verifier generated BPF programs
        u = USDT(pid=int(self.app.pid))
        u.enable_probe(probe="probe_point_1", fn_name="do_trace")
        u.enable_probe(probe="probe_point_2", fn_name="do_trace2")
        u.enable_probe(probe="probe_point_3", fn_name="do_trace3")
        b = BPF(text=self.bpf_text, usdt_contexts=[u])

    def tearDown(self):
        # kill the subprocess, clean the environment
        self.app.kill()
        self.app.wait()
        os.unlink(self.ftemp.name)

if __name__ == "__main__":
    main()
