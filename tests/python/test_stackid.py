#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

import bcc
import distutils.version
import os
import unittest
from utils import mayFail
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


@unittest.skipUnless(kernel_version_ge(4,6), "requires kernel >= 4.6")
class TestStackid(unittest.TestCase):
    @mayFail("This fails on github actions environment, and needs to be fixed")
    def test_simple(self):
        b = bcc.BPF(text="""
#include <uapi/linux/ptrace.h>
struct bpf_map;
BPF_STACK_TRACE(stack_traces, 10240);
BPF_HASH(stack_entries, int, int);
BPF_HASH(stub);
int kprobe__htab_map_lookup_elem(struct pt_regs *ctx, struct bpf_map *map, u64 *k) {
    int id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
    if (id < 0)
        return 0;
    int key = 1;
    stack_entries.update(&key, &id);
    return 0;
}
""")
        stub = b["stub"]
        stack_traces = b["stack_traces"]
        stack_entries = b["stack_entries"]
        try: x = stub[stub.Key(1)]
        except: pass
        k = stack_entries.Key(1)
        self.assertIn(k, stack_entries)
        stackid = stack_entries[k]
        self.assertIsNotNone(stackid)
        stack = stack_traces[stackid].ip
        self.assertEqual(b.ksym(stack[0]), b"htab_map_lookup_elem")

def Get_libc_path():
  cmd = 'cat /proc/self/maps | grep libc | awk \'{print $6}\' | uniq'
  output = subprocess.check_output(cmd, shell=True)
  if not isinstance(output, str):
    output = output.decode()
  return output.split('\n')[0]

@unittest.skipUnless(kernel_version_ge(4,17), "requires kernel >= 4.17")
class TestStackBuildid(unittest.TestCase):
    def test_simple(self):
        b = bcc.BPF(text="""
#include <uapi/linux/ptrace.h>
struct bpf_map;
BPF_STACK_TRACE_BUILDID(stack_traces, 10240);
BPF_HASH(stack_entries, int, int);
BPF_HASH(stub);
int kprobe__sys_getuid(struct pt_regs *ctx, struct bpf_map *map, u64 *k) {
    int id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
    if (id < 0)
        return 0;
    int key = 1;
    stack_entries.update(&key, &id);
    return 0;
}
""")
        os.getuid()
        stub = b["stub"]
        stack_traces = b["stack_traces"]
        stack_entries = b["stack_entries"]
        b.add_module(Get_libc_path())
        try: x = stub[stub.Key(1)]
        except: pass
        k = stack_entries.Key(1)
        self.assertIn(k, stack_entries)
        stackid = stack_entries[k]
        self.assertIsNotNone(stackid)
        stack = stack_traces[stackid]
        self.assertTrue(b.sym(stack.trace[0], -1).find(b"getuid")!=-1)

if __name__ == "__main__":
    unittest.main()
