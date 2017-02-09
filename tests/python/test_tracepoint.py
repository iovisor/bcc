#!/usr/bin/env python
# Copyright (c) Sasha Goldshtein
# Licensed under the Apache License, Version 2.0 (the "License")

import bcc
import unittest
from time import sleep
import distutils.version
import os
import subprocess

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

@unittest.skipUnless(kernel_version_ge(4,7), "requires kernel >= 4.7")
class TestTracepoint(unittest.TestCase):
    def test_tracepoint(self):
        text = """
        BPF_HASH(switches, u32, u64);
        TRACEPOINT_PROBE(sched, sched_switch) {
            u64 val = 0;
            u32 pid = args->next_pid;
            u64 *existing = switches.lookup_or_init(&pid, &val);
            (*existing)++;
            return 0;
        }
        """
        b = bcc.BPF(text=text)
        sleep(1)
        total_switches = 0
        for k, v in b["switches"].items():
            total_switches += v.value
        self.assertNotEqual(0, total_switches)

@unittest.skipUnless(kernel_version_ge(4,7), "requires kernel >= 4.7")
class TestTracepointDataLoc(unittest.TestCase):
    def test_tracepoint_data_loc(self):
        text = """
        struct value_t {
            char filename[64];
        };
        BPF_HASH(execs, u32, struct value_t);
        TRACEPOINT_PROBE(sched, sched_process_exec) {
            struct value_t val = {0};
            char fn[64];
            u32 pid = args->pid;
            struct value_t *existing = execs.lookup_or_init(&pid, &val);
            TP_DATA_LOC_READ_CONST(fn, filename, 64);
            __builtin_memcpy(existing->filename, fn, 64);
            return 0;
        }
        """
        b = bcc.BPF(text=text)
        subprocess.check_output(["/bin/ls"])
        sleep(1)
        self.assertTrue("/bin/ls" in [v.filename.decode()
                                      for v in b["execs"].values()])

if __name__ == "__main__":
    unittest.main()
