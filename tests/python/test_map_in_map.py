#!/usr/bin/env python3
#
# USAGE: test_map_in_map.py
#
# Copyright 2019 Facebook, Inc
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF
from unittest import main, skipUnless, TestCase
from utils import kernel_version_ge
import ctypes as ct
import os


class CustomKey(ct.Structure):
  _fields_ = [
    ("value_1", ct.c_int),
    ("value_2", ct.c_int)
  ]

@skipUnless(kernel_version_ge(4,11), "requires kernel >= 4.11")
class TestUDST(TestCase):
    def test_hash_table(self):
        bpf_text = b"""
      BPF_ARRAY(cntl, int, 1);
      BPF_TABLE("hash", int, int, ex1, 1024);
      BPF_TABLE("hash", int, int, ex2, 1024);
      BPF_HASH_OF_MAPS(maps_hash, int, "ex1", 10);

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
        cntl_map = b.get_table(b"cntl")
        ex1_map = b.get_table(b"ex1")
        ex2_map = b.get_table(b"ex2")
        hash_maps = b.get_table(b"maps_hash")

        hash_maps[ct.c_int(1)] = ct.c_int(ex1_map.get_fd())
        hash_maps[ct.c_int(2)] = ct.c_int(ex2_map.get_fd())

        syscall_fnname = b.get_syscall_fnname(b"getuid")
        b.attach_kprobe(event=syscall_fnname, fn_name=b"syscall__getuid")

        try:
          ex1_map[ct.c_int(0)]
          raise Exception("Unexpected success for ex1_map[0]")
        except KeyError:
          pass

        cntl_map[0] = ct.c_int(1)
        os.getuid()
        assert(ex1_map[ct.c_int(0)].value >= 1)

        try:
          ex2_map[ct.c_int(0)]
          raise Exception("Unexpected success for ex2_map[0]")
        except KeyError:
          pass

        cntl_map[0] = ct.c_int(2)
        os.getuid()
        assert(ex2_map[ct.c_int(0)].value >= 1)

        b.detach_kprobe(event=syscall_fnname)
        del hash_maps[ct.c_int(1)]
        del hash_maps[ct.c_int(2)]

    def test_hash_table_custom_key(self):
        bpf_text = b"""
        struct custom_key {
          int value_1;
          int value_2;
        };

        BPF_ARRAY(cntl, int, 1);
        BPF_TABLE("hash", int, int, ex1, 1024);
        BPF_TABLE("hash", int, int, ex2, 1024);
        BPF_HASH_OF_MAPS(maps_hash, struct custom_key, "ex1", 10);

        int syscall__getuid(void *ctx) {
          struct custom_key hash_key = {1, 0};
          int key = 0, data, *val, cntl_val;
          void *inner_map;

          val = cntl.lookup(&key);
          if (!val || *val == 0)
            return 0;

          hash_key.value_2 = *val;
          inner_map = maps_hash.lookup(&hash_key);
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
        cntl_map = b.get_table(b"cntl")
        ex1_map = b.get_table(b"ex1")
        ex2_map = b.get_table(b"ex2")
        hash_maps = b.get_table(b"maps_hash")

        hash_maps[CustomKey(1, 1)] = ct.c_int(ex1_map.get_fd())
        hash_maps[CustomKey(1, 2)] = ct.c_int(ex2_map.get_fd())
        syscall_fnname = b.get_syscall_fnname(b"getuid")
        b.attach_kprobe(event=syscall_fnname, fn_name=b"syscall__getuid")

        try:
          ex1_map[ct.c_int(0)]
          raise Exception("Unexpected success for ex1_map[0]")
        except KeyError:
          pass

        cntl_map[0] = ct.c_int(1)
        os.getuid()
        assert(ex1_map[ct.c_int(0)].value >= 1)

        try:
          ex2_map[ct.c_int(0)]
          raise Exception("Unexpected success for ex2_map[0]")
        except KeyError:
          pass

        cntl_map[0] = ct.c_int(2)
        os.getuid()
        assert(ex2_map[ct.c_int(0)].value >= 1)

        b.detach_kprobe(event=syscall_fnname)
        del hash_maps[CustomKey(1, 1)]
        del hash_maps[CustomKey(1, 2)]

    def test_array_table(self):
        bpf_text = b"""
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
        cntl_map = b.get_table(b"cntl")
        ex1_map = b.get_table(b"ex1")
        ex2_map = b.get_table(b"ex2")
        array_maps = b.get_table(b"maps_array")

        array_maps[ct.c_int(1)] = ct.c_int(ex1_map.get_fd())
        array_maps[ct.c_int(2)] = ct.c_int(ex2_map.get_fd())

        syscall_fnname = b.get_syscall_fnname(b"getuid")
        b.attach_kprobe(event=syscall_fnname, fn_name=b"syscall__getuid")

        cntl_map[0] = ct.c_int(1)
        os.getuid()
        assert(ex1_map[ct.c_int(0)].value >= 1)

        cntl_map[0] = ct.c_int(2)
        os.getuid()
        assert(ex2_map[ct.c_int(0)].value >= 1)

        b.detach_kprobe(event=syscall_fnname)

if __name__ == "__main__":
    main()
