#!/usr/bin/env python
# Copyright (c) Sasha Goldshtein
# Licensed under the Apache License, Version 2.0 (the "License")

import os
import subprocess
from bcc import SymbolCache
from unittest import main, TestCase

class Harness(TestCase):
    def setUp(self):
        self.build_command()
        subprocess.check_output('objcopy --only-keep-debug dummy dummy.debug'
                                .split())
        self.debug_command()
        subprocess.check_output('strip dummy'.split())
        self.process = subprocess.Popen('./dummy', stdout=subprocess.PIPE)
        # The process prints out the address of some symbol, which we then
        # try to resolve in the test.
        self.addr = int(self.process.stdout.readline().strip(), 16)
        self.syms = SymbolCache(self.process.pid)

    def tearDown(self):
        self.process.kill()
        self.process.wait()

    def resolve_addr(self):
        sym, offset, module = self.syms.resolve(self.addr)
        self.assertEqual(sym, 'some_function')
        self.assertEqual(offset, 0)
        self.assertTrue(module[-5:] == 'dummy')

    def resolve_name(self):
        script_dir = os.path.dirname(os.path.realpath(__file__))
        addr = self.syms.resolve_name(os.path.join(script_dir, 'dummy'),
                                      'some_function')
        self.assertEqual(addr, self.addr)
        pass

class TestDebuglink(Harness):
    def build_command(self):
        subprocess.check_output('gcc -o dummy dummy.c'.split())

    def debug_command(self):
        subprocess.check_output('objcopy --add-gnu-debuglink=dummy.debug dummy'
                                .split())

    def tearDown(self):
        super(TestDebuglink, self).tearDown()
        subprocess.check_output('rm dummy dummy.debug'.split())

    def test_resolve_addr(self):
        self.resolve_addr()

    def test_resolve_name(self):
        self.resolve_name()

class TestBuildid(Harness):
    def build_command(self):
        subprocess.check_output(('gcc -o dummy -Xlinker ' + \
               '--build-id=0x123456789abcdef0123456789abcdef012345678 dummy.c')
               .split())

    def debug_command(self):
        subprocess.check_output('mkdir -p /usr/lib/debug/.build-id/12'.split())
        subprocess.check_output(('mv dummy.debug /usr/lib/debug/.build-id' + \
            '/12/3456789abcdef0123456789abcdef012345678.debug').split())

    def tearDown(self):
        super(TestBuildid, self).tearDown()
        subprocess.check_output('rm dummy'.split())
        subprocess.check_output(('rm /usr/lib/debug/.build-id/12' +
            '/3456789abcdef0123456789abcdef012345678.debug').split())

    def test_resolve_name(self):
        self.resolve_addr()

    def test_resolve_addr(self):
        self.resolve_name()

if __name__ == "__main__":
    main()
