#!/usr/bin/python2

from __future__ import print_function
from bcc import BPF
from ctypes import *

import sys
import socket
import os
import struct


def encode_dns(name):
  size = 32
  if len(name) > 253:
    raise Exception("DNS Name too long.")
  b = bytearray(size)
  i = 0;
  elements = name.split(".")
  for element in elements:
    b[i] = struct.pack("!B", len(element))
    i += 1
    for j in range(0, len(element)):
      b[i] = element[j]
      i += 1


  return (c_ubyte * size).from_buffer(b)



# initialize BPF - load source code from http-parse-simple.c
bpf = BPF(src_file = "dns_matching.c", debug=0)
# print(bpf.dump_func("dns_test"))

#load eBPF program http_filter of type SOCKET_FILTER into the kernel eBPF vm
#more info about eBPF program types
#http://man7.org/linux/man-pages/man2/bpf.2.html
function_dns_matching = bpf.load_func("dns_matching", BPF.SOCKET_FILTER)


#create raw socket, bind it to eth0
#attach bpf program to socket created
BPF.attach_raw_socket(function_dns_matching, "eth1")

# Get the table.
cache = bpf.get_table("cache")

# Create first entry for foo.bar
key = cache.Key()
key.p = encode_dns("foo.bar")

leaf = cache.Leaf()
leaf.p = (c_ubyte * 4).from_buffer(bytearray(4))
cache[key] = leaf

bpf.trace_print()
