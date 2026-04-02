#!/usr/bin/env python3
# Copyright (c) Catalysts GmbH
# Licensed under the Apache License, Version 2.0 (the "License")

import argparse
from bcc.utils import get_online_cpus, detect_language
from bcc.utils import positive_int, positive_nonzero_int, positive_int_list
import multiprocessing
import unittest
import os

class TestUtils(unittest.TestCase):
    def test_get_online_cpus(self):
        online_cpus = get_online_cpus()
        num_cores = multiprocessing.cpu_count()

        self.assertEqual(len(online_cpus), num_cores)

    def test_detect_language(self):
        candidates = ["c", "java", "perl", "php", "node", "ruby", "python"]
        language = detect_language(candidates, os.getpid())
        self.assertEqual(language, "python")

class TestPositiveInt(unittest.TestCase):
    def test_accepts_zero(self):
        self.assertEqual(positive_int("0"), 0)

    def test_accepts_positive(self):
        self.assertEqual(positive_int("42"), 42)

    def test_accepts_large(self):
        self.assertEqual(positive_int("1000000"), 1000000)

    def test_rejects_negative(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            positive_int("-1")

    def test_rejects_non_numeric(self):
        with self.assertRaises(ValueError):
            positive_int("abc")

    def test_rejects_float_string(self):
        with self.assertRaises(ValueError):
            positive_int("1.5")

    def test_rejects_injection(self):
        with self.assertRaises(ValueError):
            positive_int("1; } malicious(); if (0")

    def test_rejects_shell_expansion(self):
        with self.assertRaises(ValueError):
            positive_int("$(whoami)")


class TestPositiveNonzeroInt(unittest.TestCase):
    def test_accepts_one(self):
        self.assertEqual(positive_nonzero_int("1"), 1)

    def test_accepts_large(self):
        self.assertEqual(positive_nonzero_int("999"), 999)

    def test_rejects_zero(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            positive_nonzero_int("0")

    def test_rejects_negative(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            positive_nonzero_int("-1")

    def test_rejects_non_numeric(self):
        with self.assertRaises(ValueError):
            positive_nonzero_int("abc")


class TestPositiveIntList(unittest.TestCase):
    def test_accepts_single(self):
        self.assertEqual(positive_int_list("9"), [9])

    def test_accepts_multiple(self):
        self.assertEqual(positive_int_list("1,2,3"), [1, 2, 3])

    def test_accepts_with_spaces(self):
        self.assertEqual(positive_int_list("9, 15"), [9, 15])

    def test_accepts_zero(self):
        self.assertEqual(positive_int_list("0,1"), [0, 1])

    def test_rejects_non_numeric_in_list(self):
        with self.assertRaises(ValueError):
            positive_int_list("1,malicious,3")

    def test_rejects_injection_in_list(self):
        with self.assertRaises(ValueError):
            positive_int_list("1; } evil()")

    def test_rejects_negative_in_list(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            positive_int_list("1,-1")


if __name__ == "__main__":
    unittest.main()
