#!/usr/bin/env python
#
# USAGE: test_map_in_map.py
#
# Copyright 2019 Facebook, Inc
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF
import distutils.version
from unittest import main, skipUnless, TestCase
import ctypes as ct
import os

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

@skipUnless(kernel_version_ge(4,11), "requires kernel >= 4.11")
class TestUDST(TestCase):
    def test_hash_table(self):
        bpf_text = """
      BPF_ARRAY(cntl, int, 1);
      BPF_TABLE("hash", int, int, ex1, 1024);
      BPF_TABLE("hash", int, int, ex2, 1024);
      BPF_HASH_OF_MAPS(maps_hash, "ex1", 10);

      int syscall__getuid(void *ctx) {
         int key = 0, data, *val, cntl_val;
         void *inner_map;

         val = cntl.lookup(&key);
         if (!val || *val == 0)
           return 0;

         cntl_val = *val;
         inner_map = maps_hash.lookup(&cntl_val);
         if (!inner_map)
           return 0;

         val = bpf_map_lookup_elem(inner_map, &key);
         if (!val) {
           data = 1;
           bpf_map_update_elem(inner_map, &key, &data, 0);
         } else {
           data = 1 + *val;
           bpf_map_update_elem(inner_map, &key, &data, 0);
         }

         return 0;
      }
"""
        b = BPF(text=bpf_text)
        cntl_map = b.get_table("cntl")
        ex1_map = b.get_table("ex1")
        ex2_map = b.get_table("ex2")
        hash_maps = b.get_table("maps_hash")

        hash_maps[ct.c_int(1)] = ct.c_int(ex1_map.get_fd())
        hash_maps[ct.c_int(2)] = ct.c_int(ex2_map.get_fd())

        syscall_fnname = b.get_syscall_fnname("getuid")
        b.attach_kprobe(event=syscall_fnname, fn_name="syscall__getuid")

        try:
          ex1_map[ct.c_int(0)]
          raise Exception("Unexpected success for ex1_map[0]")
        except KeyError:
          pass

        cntl_map[0] = ct.c_int(1)
        os.getuid()
        assert(ex1_map[ct.c_int(0)] >= 1)

        try:
          ex2_map[ct.c_int(0)]
          raise Exception("Unexpected success for ex2_map[0]")
        except KeyError:
          pass

        cntl_map[0] = ct.c_int(2)
        os.getuid()
        assert(ex2_map[ct.c_int(0)] >= 1)

        b.detach_kprobe(event=syscall_fnname)
        del hash_maps[ct.c_int(1)]
        del hash_maps[ct.c_int(2)]

    def test_array_table(self):
        bpf_text = """
      BPF_ARRAY(cntl, int, 1);
      BPF_ARRAY(ex1, int, 1024);
      BPF_ARRAY(ex2, int, 1024);
      BPF_ARRAY_OF_MAPS(maps_array, "ex1", 10);

      int syscall__getuid(void *ctx) {
         int key = 0, data, *val, cntl_val;
         void *inner_map;

         val = cntl.lookup(&key);
         if (!val || *val == 0)
           return 0;

         cntl_val = *val;
         inner_map = maps_array.lookup(&cntl_val);
         if (!inner_map)
           return 0;

         val = bpf_map_lookup_elem(inner_map, &key);
         if (val) {
           data = 1 + *val;
           bpf_map_update_elem(inner_map, &key, &data, 0);
         }

         return 0;
      }
"""
        b = BPF(text=bpf_text)
        cntl_map = b.get_table("cntl")
        ex1_map = b.get_table("ex1")
        ex2_map = b.get_table("ex2")
        array_maps = b.get_table("maps_array")

        array_maps[ct.c_int(1)] = ct.c_int(ex1_map.get_fd())
        array_maps[ct.c_int(2)] = ct.c_int(ex2_map.get_fd())

        syscall_fnname = b.get_syscall_fnname("getuid")
        b.attach_kprobe(event=syscall_fnname, fn_name="syscall__getuid")

        cntl_map[0] = ct.c_int(1)
        os.getuid()
        assert(ex1_map[ct.c_int(0)] >= 1)

        cntl_map[0] = ct.c_int(2)
        os.getuid()
        assert(ex2_map[ct.c_int(0)] >= 1)

        b.detach_kprobe(event=syscall_fnname)

if __name__ == "__main__":
    main()
