#!/usr/bin/env python
# Copyright (c) Jazel Canseco, 2018
# Licensed under the Apache License, Version 2.0 (the "License")

import os
import subprocess

from unittest import main, skipUnless, TestCase
from test_tools_smoke import ToolTestRunner, kernel_version_ge

class RemoteTests(TestCase, ToolTestRunner):

    def setUp(self):
        self.original_env = os.environ.copy()

        os.environ["ARCH"] = "x86"
        os.environ["BCC_REMOTE"] = "shell"

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.original_env)

    def test_biolatency(self):
        self.run_with_duration("biolatency.py 1 1")

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_biosnoop(self):
        self.run_with_int("biosnoop.py")

    def test_biotop(self):
        self.run_with_duration("biotop.py 1 1")

    def test_cachestat(self):
        self.run_with_duration("cachestat.py 1 1")

    def test_filetop(self):
        self.run_with_duration("filetop.py 1 1")

    def test_hardirqs(self):
        self.run_with_duration("hardirqs.py 1 1")

    @skipUnless(kernel_version_ge(4,6), "requires kernel >= 4.6")
    def test_offcputime(self):
        # When running this tool on a remote target, it takes much longer
        # to output results (i.e. not instantaneous). This makes using
        # run_with_duration() unsuitable for this test since it'll erroneously
        # conclude that the tool has hanged when it is just taking some time
        # to finish printing its output.
        self.run_with_int("offcputime.py 1", allow_early=True)

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_opensnoop(self):
        self.run_with_int("opensnoop.py")

    @skipUnless(kernel_version_ge(4,9), "requires kernel >= 4.9")
    def test_profile(self):
        # When running this tool on a remote target, it takes much longer
        # to output results (i.e. not instantaneous). This makes using
        # run_with_duration() unsuitable for this test since it'll erroneously
        # conclude that the tool has hanged when it is just taking some time
        # to finish printing its output.
        self.run_with_int("profile.py 1", allow_early=True)

    @skipUnless(kernel_version_ge(4,9), "requires kernel >= 4.9")
    def test_runqlen(self):
        self.run_with_duration("runqlen.py 1 1")

    @skipUnless(kernel_version_ge(4,6), "requires kernel >= 4.6")
    def test_stackcount(self):
        self.run_with_int("stackcount.py __kmalloc -i 1")

    @skipUnless(kernel_version_ge(4,7), "requires kernel >= 4.7")
    def test_syscount(self):
        self.run_with_int("syscount.py -i 1")

    @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    def test_trace(self):
        self.run_with_int("trace.py SyS_open")

if __name__ == "__main__":
    main()
