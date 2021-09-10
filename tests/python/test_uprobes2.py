#!/usr/bin/env python
#
# USAGE: test_uprobe2.py
#
# Copyright 2020 Facebook, Inc
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
from unittest import main, TestCase
from subprocess import Popen, PIPE
from tempfile import NamedTemporaryFile


class TestUprobes(TestCase):
    def setUp(self):
        lib_text = b"""
__attribute__((__visibility__("default"))) void fun()
{
}
"""
        self.bpf_text = """
int trace_fun_call(void *ctx) {{
    return 1;
}}
"""
        # Compile and run the application
        self.ftemp = NamedTemporaryFile(delete=False)
        self.ftemp.close()
        comp = Popen([
            "gcc",
            "-x", "c",
            "-shared",
            "-Wl,-Ttext-segment,0x2000000",
            "-o", self.ftemp.name,
            "-"
        ], stdin=PIPE)
        comp.stdin.write(lib_text)
        comp.stdin.close()
        self.assertEqual(comp.wait(), 0)

    def test_attach1(self):
        b = BPF(text=self.bpf_text)
        b.attach_uprobe(name=self.ftemp.name, sym="fun", fn_name="trace_fun_call")


if __name__ == "__main__":
    main()
