#!/usr/bin/python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

import bcc
import unittest

class TestStackid(unittest.TestCase):
    def test_simple(self):
        b = bcc.BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/bpf.h>
BPF_STACK_TRACE(stack_traces, 10240);
BPF_HASH(stack_entries, int, int);
BPF_HASH(stub);
int kprobe__htab_map_delete_elem(struct pt_regs *ctx, struct bpf_map *map, u64 *k) {
    int id = stack_traces.lookup(ctx);
    int key = 1;
    stack_entries.update(&key, &id);
    return 0;
}
""")
        stub = b["stub"]
        stack_traces = b["stack_traces"]
        stack_entries = b["stack_entries"]
        try: del stub[stub.Key(1)]
        except: pass
        k = stack_entries.Key(1)
        self.assertIn(k, stack_entries)
        stackid = stack_entries[k]
        self.assertIsNotNone(stackid)
        stack = stack_traces[stackid].data
        self.assertEqual(b.ksym(stack[0]), "htab_map_delete_elem")


if __name__ == "__main__":
    unittest.main()
