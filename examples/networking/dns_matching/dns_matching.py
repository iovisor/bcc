#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
from ctypes import *

import sys
import socket
import os
import struct
import dnslib


def encode_dns(name):
  size = 255
  if len(name) > 255:
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

def add_cache_entry(cache, name):
  key = cache.Key()
  key.p = encode_dns(name)
  leaf = cache.Leaf()
  leaf.p = (c_ubyte * 4).from_buffer(bytearray(4))
  cache[key] = leaf

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

# Add cache entries
add_cache_entry(cache, "foo.bar")
add_cache_entry(cache, "another.sample.domain")

socket_fd = function_dns_matching.sock
sock = socket.fromfd(socket_fd, socket.PF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)
sock.setblocking(True)

while 1:
  #retrieve raw packet from socket
  packet_str = os.read(socket_fd, 2048)
  packet_bytearray = bytearray(packet_str)

  ETH_HLEN = 14
  UDP_HLEN = 8

  #IP HEADER
  #calculate ip header length
  ip_header_length = packet_bytearray[ETH_HLEN]               #load Byte
  ip_header_length = ip_header_length & 0x0F                  #mask bits 0..3
  ip_header_length = ip_header_length << 2                    #shift to obtain length

  #calculate payload offset
  payload_offset = ETH_HLEN + ip_header_length + UDP_HLEN

  payload = packet_bytearray[payload_offset:]
  # pass the payload to dnslib for parsing
  dnsrec = dnslib.DNSRecord.parse(payload)
  print (dnsrec.questions, "\n")
