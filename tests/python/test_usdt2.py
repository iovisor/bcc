#!/usr/bin/env python
#
# USAGE: test_usdt2.py
#
# Copyright 2017 Facebook, Inc
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF, USDT
from unittest import main, TestCase
from subprocess import Popen, PIPE
from tempfile import NamedTemporaryFile
import ctypes as ct
import inspect
import os
import signal

class TestUDST(TestCase):
    def setUp(self):
        # Application, minimum, to define three trace points
        app_text = b"""
#include <stdlib.h>
#include <unistd.h>
#include "folly/tracing/StaticTracepoint.h"

int main(int argc, char **argv) {
  int t = atoi(argv[1]);
  while (1) {
    FOLLY_SDT(test, probe_point_1, t);
    FOLLY_SDT(test, probe_point_2, t + 1);
    FOLLY_SDT(test, probe_point_3, t + 2);
    sleep(1);
  }
  return 1;
}
"""
        # BPF program
        self.bpf_text = """
#include <uapi/linux/ptrace.h>

BPF_PERF_OUTPUT(event1);
BPF_PERF_OUTPUT(event2);
BPF_PERF_OUTPUT(event3);
BPF_PERF_OUTPUT(event4);
BPF_PERF_OUTPUT(event5);
BPF_PERF_OUTPUT(event6);

int do_trace1(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    int result = 0;
    bpf_usdt_readarg(1, ctx, &result);
    if (FILTER)
      event1.perf_submit(ctx, &result, sizeof(result));
    else
      event4.perf_submit(ctx, &result, sizeof(result));
    return 0;
};
int do_trace2(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    int result = 0;
    bpf_usdt_readarg(1, ctx, &result);
    if (FILTER)
      event2.perf_submit(ctx, &result, sizeof(result));
    else
      event5.perf_submit(ctx, &result, sizeof(result));
    return 0;
}
int do_trace3(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    int result = 0;
    bpf_usdt_readarg(1, ctx, &result);
    if (FILTER)
      event3.perf_submit(ctx, &result, sizeof(result));
    else
      event6.perf_submit(ctx, &result, sizeof(result));
    return 0;
}
"""

        # Compile and run the application
        self.ftemp = NamedTemporaryFile(delete=False)
        self.ftemp.close()
        comp = Popen(["gcc", "-I", "%s/include" % os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe()))),
                      "-x", "c", "-o", self.ftemp.name, "-"],
                     stdin=PIPE)
        comp.stdin.write(app_text)
        comp.stdin.close()
        self.assertEqual(comp.wait(), 0)

        # create 3 applications, 2 applications will have usdt attached and
        # the third one does not, and the third one should not call into
        # bpf program.
        self.app = Popen([self.ftemp.name, "1"])
        self.app2 = Popen([self.ftemp.name, "11"])
        self.app3 = Popen([self.ftemp.name, "21"])

    def test_attach1(self):
        # Enable USDT probe from given PID and verifier generated BPF programs.
        u = USDT(pid=int(self.app.pid))
        u.enable_probe(probe="probe_point_1", fn_name="do_trace1")
        u.enable_probe(probe="probe_point_2", fn_name="do_trace2")
        u2 = USDT(pid=int(self.app2.pid))
        u2.enable_probe(probe="probe_point_2", fn_name="do_trace2")
        u2.enable_probe(probe="probe_point_3", fn_name="do_trace3")
        self.bpf_text = self.bpf_text.replace("FILTER", "pid == %d" % self.app.pid)
        b = BPF(text=self.bpf_text, usdt_contexts=[u, u2])

        # Event states for each event:
        # 0 - probe not caught, 1 - probe caught with correct value,
        # 2 - probe caught with incorrect value
        self.evt_st_1 = 0
        self.evt_st_2 = 0
        self.evt_st_3 = 0
        self.evt_st_4 = 0
        self.evt_st_5 = 0
        self.evt_st_6 = 0

        def check_event_val(data, event_state, expected_val):
            result = ct.cast(data, ct.POINTER(ct.c_int)).contents
            if result.value == expected_val:
                if (event_state == 0 or event_state == 1):
                    return 1
            return 2

        def print_event1(cpu, data, size):
            self.evt_st_1 = check_event_val(data, self.evt_st_1, 1)

        def print_event2(cpu, data, size):
            self.evt_st_2 = check_event_val(data, self.evt_st_2, 2)

        def print_event3(cpu, data, size):
            self.evt_st_3 = check_event_val(data, self.evt_st_3, 3)

        def print_event4(cpu, data, size):
            self.evt_st_4 = check_event_val(data, self.evt_st_4, 11)

        def print_event5(cpu, data, size):
            self.evt_st_5 = check_event_val(data, self.evt_st_5, 12)

        def print_event6(cpu, data, size):
            self.evt_st_6 = check_event_val(data, self.evt_st_6, 13)

        # loop with callback to print_event
        b["event1"].open_perf_buffer(print_event1)
        b["event2"].open_perf_buffer(print_event2)
        b["event3"].open_perf_buffer(print_event3)
        b["event4"].open_perf_buffer(print_event4)
        b["event5"].open_perf_buffer(print_event5)
        b["event6"].open_perf_buffer(print_event6)

        # three iterations to make sure we get some probes and have time to process them
        for i in range(3):
            b.perf_buffer_poll()

        # note that event1 and event4 do not really fire, so their state should be 0
        # use separate asserts so that if test fails we know which one is the culprit
        self.assertTrue(self.evt_st_1 == 1)
        self.assertTrue(self.evt_st_2 == 1)
        self.assertTrue(self.evt_st_3 == 0)
        self.assertTrue(self.evt_st_4 == 0)
        self.assertTrue(self.evt_st_5 == 1)
        self.assertTrue(self.evt_st_6 == 1)

    def tearDown(self):
        # kill the subprocess, clean the environment
        self.app.kill()
        self.app.wait()
        self.app2.kill()
        self.app2.wait()
        self.app3.kill()
        self.app3.wait()
        os.unlink(self.ftemp.name)

if __name__ == "__main__":
    main()
