#!/usr/bin/env python3
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

import os
import ctypes as ct

from bcc import BPF

from unittest import main, TestCase, skipUnless
from utils import kernel_version_ge

@skipUnless(kernel_version_ge(4,20), "requires kernel >= 4.20")
class TestQueueStack(TestCase):

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

        for i in reversed(range(10)):
            stack.push(ct.c_uint64(i))

        # testing itervalues()
        for i,v in enumerate(stack.values()):
            assert v.value == i

        b.cleanup()

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

        for i in range(10):
            queue.push(ct.c_uint64(i))

        # testing itervalues()
        for i,v in enumerate(queue.values()):
            assert v.value == i

        b.cleanup()


if __name__ == "__main__":
    main()
