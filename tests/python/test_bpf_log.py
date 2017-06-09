#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
from simulation import Simulation
import sys
import os
import tempfile
from unittest import main, TestCase


error_msg = "R0 invalid mem access 'map_value_or_null'\n"

text = """
       #include <uapi/linux/ptrace.h>
       #include <bcc/proto.h>
       BPF_HASH(t1, int, int, 10);
       int sim_port(struct __sk_buff *skb) {
           int x = 0, *y;
       """
repeat = """
           y = t1.lookup(&x);
           if (!y) return 0;
           x = *y;
         """
end = """
           y = t1.lookup(&x);
           x = *y;
           return 0;
        }
      """
for i in range(0,300):
    text += repeat
text += end

class TestBPFProgLoad(TestCase):

    def setUp(self):
        self.fp = tempfile.TemporaryFile()
        os.dup2(self.fp.fileno(), sys.stderr.fileno())

    def tearDown(self):
        self.fp.close()


    def test_log_debug(self):
        b = BPF(text=text, debug=2)
        try:
            ingress = b.load_func("sim_port",BPF.SCHED_CLS)
        except Exception:
            self.fp.flush()
            self.fp.seek(0)
            self.assertEqual(error_msg in self.fp.read().decode(), True)


    def test_log_no_debug(self):
        b = BPF(text=text, debug=0)
        try:
            ingress = b.load_func("sim_port",BPF.SCHED_CLS)
        except Exception:
            self.fp.flush()
            self.fp.seek(0)
            self.assertEqual(error_msg in self.fp.read().decode(), True)


if __name__ == "__main__":
    main()


