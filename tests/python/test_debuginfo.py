#!/usr/bin/env python
# Copyright (c) Sasha Goldshtein
# Licensed under the Apache License, Version 2.0 (the "License")

import os
import subprocess
from bcc import SymbolCache, BPF
from unittest import main, TestCase

class TestKSyms(TestCase):
    def grab_sym(self):
        address = ""
        aliases = []

        # Grab the first symbol in kallsyms that has type 't' or 'T'.
        # Also, find all aliases of this symbol which are identifiable
        # by the same address.
        with open("/proc/kallsyms", "rb") as f:
            for line in f:

                # Extract the first 3 columns only. The 4th column
                # containing the module name may not exist for all
                # symbols.
                (addr, t, name) = line.strip().split()[:3]
                if t == b"t" or t == b"T":
                    if not address:
                        address = addr
                    if addr == address:
                        aliases.append(name)

        # Return all aliases of the first symbol.
        return (address, aliases)

    def test_ksymname(self):
        sym = BPF.ksymname(b"__kmalloc")
        self.assertIsNotNone(sym)
        self.assertNotEqual(sym, 0)

    def test_ksym(self):
        (addr, aliases) = self.grab_sym()
        sym = BPF.ksym(int(addr, 16))
        found = sym in aliases
        self.assertTrue(found)

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
        self.process.stdout.close()
        self.process = None

    def resolve_addr(self):
        sym, offset, module = self.syms.resolve(self.addr, False)
        self.assertEqual(sym, self.mangled_name)
        self.assertEqual(offset, 0)
        self.assertTrue(module[-5:] == b'dummy')
        sym, offset, module = self.syms.resolve(self.addr, True)
        self.assertEqual(sym, b'some_namespace::some_function(int, int)')
        self.assertEqual(offset, 0)
        self.assertTrue(module[-5:] == b'dummy')


    def resolve_name(self):
        script_dir = os.path.dirname(os.path.realpath(__file__).encode("utf8"))
        addr = self.syms.resolve_name(os.path.join(script_dir, b'dummy'),
                                      self.mangled_name)
        self.assertEqual(addr, self.addr)
        pass

class TestDebuglink(Harness):
    def build_command(self):
        subprocess.check_output('g++ -o dummy dummy.cc'.split())
        lines = subprocess.check_output('nm dummy'.split()).splitlines()
        for line in lines:
            if b"some_function" in line:
                self.mangled_name = line.split(b' ')[2]
                break
        self.assertTrue(self.mangled_name)

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
        subprocess.check_output(('g++ -o dummy -Xlinker ' + \
               '--build-id=0x123456789abcdef0123456789abcdef012345678 dummy.cc')
               .split())
        lines = subprocess.check_output('nm dummy'.split()).splitlines()
        for line in lines:
            if b"some_function" in line:
                self.mangled_name = line.split(b' ')[2]
                break
        self.assertTrue(self.mangled_name)


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
