#!/usr/bin/python
# Copyright (c) Catalysts GmbH
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc.utils import get_online_cpus
import multiprocessing
import unittest

class TestUtils(unittest.TestCase):
    def test_get_online_cpus(self):
        online_cpus = get_online_cpus()
        num_cores = multiprocessing.cpu_count()

        self.assertEqual(len(online_cpus), num_cores)


if __name__ == "__main__":
    unittest.main()
