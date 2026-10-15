#!/usr/bin/env python3
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

import unittest

from bcc.libbcc import bcc_usdt_argument, BCC_USDT_ARGUMENT_FLAGS
from bcc.usdt import USDTProbeArgument


class TestUSDTProbeArgument(unittest.TestCase):
    def test_rip_relative_deref_ident(self):
        argument = bcc_usdt_argument()
        argument.size = 8
        argument.valid = (
            BCC_USDT_ARGUMENT_FLAGS.DEREF_OFFSET |
            BCC_USDT_ARGUMENT_FLAGS.DEREF_IDENT |
            BCC_USDT_ARGUMENT_FLAGS.BASE_REGISTER_NAME)
        argument.base_register_name = b"ip"
        argument.deref_ident = b"foo"
        argument.deref_offset = 8

        self.assertEqual(USDTProbeArgument(argument)._format(), "*(&foo + 8)")


if __name__ == "__main__":
    unittest.main()
