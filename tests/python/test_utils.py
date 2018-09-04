#!/usr/bin/env python
# Copyright (c) Catalysts GmbH
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc.utils import get_online_cpus, detect_language
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

if __name__ == "__main__":
    unittest.main()
