#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
import os
import distutils.version
import ctypes as ct
import random
import time
import subprocess
from unittest import main, TestCase, skipUnless

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

class TestQueueStack(TestCase):
    @skipUnless(kernel_version_ge(4,20), "requires kernel >= 4.20")
    def test_stack(self):
        text = """
        BPF_STACK(stack, u64, 10);
        """
        b = BPF(text=text)
        stack = b['stack']

        for i in range(10):
            stack.push(ct.c_uint64(i))

        with self.assertRaises(Exception):
            stack.push(ct.c_uint(10))

        assert stack.peek().value == 9

        for i in reversed(range(10)):
            assert stack.pop().value == i

        with self.assertRaises(KeyError):
            stack.peek()

        with self.assertRaises(KeyError):
            stack.pop()

        b.cleanup()

    @skipUnless(kernel_version_ge(4,20), "requires kernel >= 4.20")
    def test_queue(self):
        text = """
        BPF_QUEUE(queue, u64, 10);
        """
        b = BPF(text=text)
        queue = b['queue']

        for i in range(10):
            queue.push(ct.c_uint64(i))

        with self.assertRaises(Exception):
            queue.push(ct.c_uint(10))

        assert queue.peek().value == 0

        for i in range(10):
            assert queue.pop().value == i

        with self.assertRaises(KeyError):
            queue.peek()

        with self.assertRaises(KeyError):
            queue.pop()

        b.cleanup()

if __name__ == "__main__":
    main()
