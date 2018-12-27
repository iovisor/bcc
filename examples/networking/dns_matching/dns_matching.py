#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
from ctypes import *

import os
import sys
import fcntl
import dnslib
import argparse


def encode_dns(name):
  if len(name) + 1 > 255:
    raise Exception("DNS Name too long.")
  b = bytearray()
  for element in name.split('.'):
    sublen = len(element)
    if sublen > 63:
      raise ValueError('DNS label %s is too long' % element)
    b.append(sublen)
    b.extend(element.encode('ascii'))
  b.append(0)  # Add 0-len octet label for the root server
  return b

def add_cache_entry(cache, name):
  key = cache.Key()
  key_len = len(key.p)
  name_buffer = encode_dns(name)
  # Pad the buffer with null bytes if it is too short
  name_buffer.extend((0,) * (key_len - len(name_buffer)))
  key.p = (c_ubyte * key_len).from_buffer(name_buffer)
  leaf = cache.Leaf()
  leaf.p = (c_ubyte * 4).from_buffer(bytearray(4))
  cache[key] = leaf


parser = argparse.ArgumentParser(usage='For detailed information about usage,\
 try with -h option')
req_args = parser.add_argument_group("Required arguments")
req_args.add_argument("-i", "--interface", type=str, default="",
                      help="Interface name, defaults to all if unspecified.")
req_args.add_argument("-d", "--domains", type=str, required=True, nargs="+",
    help='List of domain names separated by space. For example: -d abc.def xyz.mno')
args = parser.parse_args()

# initialize BPF - load source code from http-parse-simple.c
bpf = BPF(src_file = "dns_matching.c", debug=0)
# print(bpf.dump_func("dns_test"))

#load eBPF program http_filter of type SOCKET_FILTER into the kernel eBPF vm
#more info about eBPF program types
#http://man7.org/linux/man-pages/man2/bpf.2.html
function_dns_matching = bpf.load_func("dns_matching", BPF.SOCKET_FILTER)


#create raw socket, bind it to user provided interface
#attach bpf program to socket created
BPF.attach_raw_socket(function_dns_matching, args.interface)

# Get the table.
cache = bpf.get_table("cache")

# Add cache entries
for e in args.domains:
  print(">>>> Adding map entry: ", e)
  add_cache_entry(cache, e)

print("\nTry to lookup some domain names using nslookup from another terminal.")
print("For example:  nslookup foo.bar")
print("\nBPF program will filter-in DNS packets which match with map entries.")
print("Packets received by user space program will be printed here")
print("\nHit Ctrl+C to end...")

socket_fd = function_dns_matching.sock
fl = fcntl.fcntl(socket_fd, fcntl.F_GETFL)
fcntl.fcntl(socket_fd, fcntl.F_SETFL, fl & (~os.O_NONBLOCK))

while 1:
  #retrieve raw packet from socket
  try:
    packet_str = os.read(socket_fd, 2048)
  except KeyboardInterrupt:
    sys.exit(0)
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
