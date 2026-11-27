#!/usr/bin/env python3
"""Userspace regression tests for BCC's batch map iterator.

The mocked syscall follows the hash-map batch contract: count is the number of
copied entries, out_batch identifies the next bucket, and ENOSPC leaves the
cursor on an oversized bucket when no entries fit.
"""

import ctypes as ct
import errno
import importlib.util
import os
import sys
import types
import unittest


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
BCC_PYTHON = os.path.join(ROOT, "src", "python", "bcc")

# Load the production table module without loading libbcc or requiring BPF
# privileges. This file is intended to run as a standalone unittest module.
package = types.ModuleType("bcc_batch_test")
package.__path__ = [BCC_PYTHON]
sys.modules[package.__name__] = package

libbcc = types.ModuleType("bcc_batch_test.libbcc")
libbcc.lib = types.SimpleNamespace()
libbcc._RAW_CB_TYPE = ct.CFUNCTYPE(None)
libbcc._LOST_CB_TYPE = ct.CFUNCTYPE(None)
libbcc._RINGBUF_CB_TYPE = ct.CFUNCTYPE(None)
libbcc.bcc_perf_buffer_opts = type("bcc_perf_buffer_opts", (), {})
sys.modules[libbcc.__name__] = libbcc

utils = types.ModuleType("bcc_batch_test.utils")
utils.get_online_cpus = lambda: []
utils.get_possible_cpus = lambda: []
sys.modules[utils.__name__] = utils

spec = importlib.util.spec_from_file_location(
    "bcc_batch_test.table", os.path.join(BCC_PYTHON, "table.py"))
table = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = table
spec.loader.exec_module(table)


U32_PTR = ct.POINTER(ct.c_uint32)


class MockBatchKernel:
    def __init__(self, buckets, delete=False, mutate=False, error=None):
        self.buckets = [list(bucket) for bucket in buckets]
        self.delete = delete
        self.mutate = mutate
        self.error = error
        self.calls = 0
        self.requested_counts = []

    def __call__(self, map_fd, in_batch, out_batch, keys, values, count_ptr):
        self.calls += 1
        count = ct.cast(count_ptr, U32_PTR).contents
        capacity = count.value
        self.requested_counts.append(capacity)
        cursor = 0 if in_batch is None else ct.cast(in_batch, U32_PTR).contents.value
        out_cursor = ct.cast(out_batch, U32_PTR).contents
        key_array = ct.cast(keys, U32_PTR)
        value_array = ct.cast(values, U32_PTR)

        if self.error == errno.EFAULT:
            count.value = 1
            ct.set_errno(errno.EFAULT)
            return -1

        if self.error is not None:
            key_array[0] = 90
            value_array[0] = 900
            count.value = 1
            out_cursor.value = cursor
            ct.set_errno(self.error)
            return -1

        total = 0
        while cursor < len(self.buckets):
            bucket = self.buckets[cursor]
            if len(bucket) > capacity - total:
                if total == 0:
                    out_cursor.value = cursor
                    count.value = 0
                    ct.set_errno(errno.ENOSPC)
                    return -1
                out_cursor.value = cursor
                count.value = total
                ct.set_errno(0)
                return 0

            for key, value in bucket:
                key_array[total] = key
                value_array[total] = value
                total += 1
            if self.delete:
                bucket.clear()
            if self.mutate and cursor == 0:
                # Model an update between bucket reads: a key already returned
                # from the first bucket is deleted and another is inserted into
                # the next bucket. The map stays at its max_entries capacity.
                self.mutate = False
                if not self.delete:
                    bucket.pop()
                self.buckets[1].append((5, 55))
            cursor += 1

        # The libbpf wrapper copies count back after the syscall. Keeping these
        # outputs separate also exposes accidental cursor/count pointer aliasing.
        out_cursor.value = cursor
        count.value = total
        ct.set_errno(errno.ENOENT)
        return -1


class MockTable(table.TableBase):
    def __len__(self):
        return 0


class TestBatchIteratorMock(unittest.TestCase):
    def make_table(self, max_entries, kernel, delete=False):
        table.lib = types.SimpleNamespace(
            bpf_lookup_batch=kernel,
            bpf_lookup_and_delete_batch=kernel,
        )
        obj = object.__new__(MockTable)
        obj.Key = ct.c_uint32
        obj.Leaf = ct.c_uint32
        obj.max_entries = max_entries
        obj.map_fd = 1
        return obj

    def test_concurrent_bucket_change_does_not_exhaust_remaining_capacity(self):
        kernel = MockBatchKernel(
            [[(1, 10), (2, 20), (3, 30)], [(4, 40)]], mutate=True)
        hmap = self.make_table(4, kernel)
        result = list(hmap._items_lookup_and_optionally_delete_batch(delete=False))

        self.assertEqual([(k.value, v.value) for k, v in result],
                         [(1, 10), (2, 20), (3, 30), (4, 40), (5, 55)])
        self.assertEqual(kernel.requested_counts, [4, 4])
        self.assertEqual(kernel.calls, 2)
        self.assertEqual(len(kernel.buckets[0]), 2)
        self.assertEqual(len(kernel.buckets[1]), 2)

    def test_lookup_and_delete_removes_returned_entries(self):
        kernel = MockBatchKernel([[(1, 10), (2, 20)], [(3, 30)]], delete=True)
        hmap = self.make_table(3, kernel)
        result = list(hmap._items_lookup_and_optionally_delete_batch(delete=True))

        self.assertEqual([(k.value, v.value) for k, v in result],
                         [(1, 10), (2, 20), (3, 30)])
        self.assertEqual(kernel.buckets, [[], []])

    def test_lookup_and_delete_handles_partial_batches(self):
        kernel = MockBatchKernel(
            [[(1, 10), (2, 20), (3, 30)], [(4, 40)]],
            delete=True, mutate=True)
        hmap = self.make_table(4, kernel)
        result = list(hmap._items_lookup_and_optionally_delete_batch(delete=True))

        self.assertEqual([(k.value, v.value) for k, v in result],
                         [(1, 10), (2, 20), (3, 30), (4, 40), (5, 55)])
        self.assertEqual(kernel.requested_counts, [4, 4])
        self.assertEqual(kernel.buckets, [[], []])

    def test_lookup_does_not_delete(self):
        kernel = MockBatchKernel([[(1, 10)], [(2, 20)]])
        hmap = self.make_table(2, kernel)
        list(hmap._items_lookup_and_optionally_delete_batch(delete=False))
        self.assertEqual(kernel.buckets, [[(1, 10)], [(2, 20)]])

    def test_empty_map_ends_on_enoent(self):
        kernel = MockBatchKernel([])
        hmap = self.make_table(4, kernel)
        self.assertEqual(list(
            hmap._items_lookup_and_optionally_delete_batch(delete=False)), [])
        self.assertEqual(kernel.calls, 1)

    def test_enospc_without_progress_fails_without_retrying(self):
        kernel = MockBatchKernel([[(i, i) for i in range(5)]])
        hmap = self.make_table(4, kernel)
        with self.assertRaisesRegex(Exception, "No space left on device"):
            list(hmap._items_lookup_and_optionally_delete_batch(delete=False))
        self.assertEqual(kernel.calls, 1)

    def test_partial_results_are_yielded_before_other_errors(self):
        kernel = MockBatchKernel([[(1, 1)]], error=errno.EIO)
        hmap = self.make_table(4, kernel)
        iterator = hmap._items_lookup_and_optionally_delete_batch(delete=False)
        first = next(iterator)
        self.assertEqual((first[0].value, first[1].value), (90, 900))
        with self.assertRaisesRegex(Exception, "Input/output error"):
            next(iterator)

    def test_efault_count_is_not_trusted(self):
        kernel = MockBatchKernel([[(1, 1)]], error=errno.EFAULT)
        hmap = self.make_table(4, kernel)
        with self.assertRaisesRegex(Exception, "Bad address"):
            list(hmap._items_lookup_and_optionally_delete_batch(delete=False))
        self.assertEqual(kernel.calls, 1)


    def test_invalid_count_is_rejected_before_buffer_access(self):
        class InvalidCountKernel:
            calls = 0

            def __call__(self, map_fd, in_batch, out_batch, keys, values,
                         count_ptr):
                self.calls += 1
                ct.cast(count_ptr, U32_PTR).contents.value = 5
                return 0

        kernel = InvalidCountKernel()
        hmap = self.make_table(4, kernel)
        with self.assertRaisesRegex(Exception, "invalid element count: 5"):
            list(hmap._items_lookup_and_optionally_delete_batch(delete=False))
        self.assertEqual(kernel.calls, 1)


if __name__ == "__main__":
    unittest.main()
