R"********(
/*
 * Copyright (c) 2015 PLUMgrid, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __BCC_PROTO_H
#define __BCC_PROTO_H

#include <uapi/linux/if_ether.h>

#define BPF_PACKET_HEADER __attribute__((packed)) __attribute__((deprecated("packet")))

struct ethernet_t {
  unsigned long long  dst:48;
  unsigned long long  src:48;
  unsigned int        type:16;
} BPF_PACKET_HEADER;

struct dot1q_t {
  unsigned short pri:3;
  unsigned short cfi:1;
  unsigned short vlanid:12;
  unsigned short type;
} BPF_PACKET_HEADER;

struct arp_t {
  unsigned short      htype;
  unsigned short      ptype;
  unsigned char       hlen;
  unsigned char       plen;
  unsigned short      oper;
  unsigned long long  sha:48;
  unsigned long long  spa:32;
  unsigned long long  tha:48;
  unsigned int        tpa;
} BPF_PACKET_HEADER;

struct ip_t {
  unsigned char   ver:4;           // byte 0
  unsigned char   hlen:4;
  unsigned char   tos;
  unsigned short  tlen;
  unsigned short  identification; // byte 4
  unsigned short  ffo_unused:1;
  unsigned short  df:1;
  unsigned short  mf:1;
  unsigned short  foffset:13;
  unsigned char   ttl;             // byte 8
  unsigned char   nextp;
  unsigned short  hchecksum;
  unsigned int    src;            // byte 12
  unsigned int    dst;            // byte 16
} BPF_PACKET_HEADER;

struct icmp_t {
  unsigned char   type;
  unsigned char   code;
  unsigned short  checksum;
} BPF_PACKET_HEADER;

struct ip6_t {
  unsigned int        ver:4;
  unsigned int        priority:8;
  unsigned int        flow_label:20;
  unsigned short      payload_len;
  unsigned char       next_header;
  unsigned char       hop_limit;
  unsigned long long  src_hi;
  unsigned long long  src_lo;
  unsigned long long  dst_hi;
  unsigned long long  dst_lo;
} BPF_PACKET_HEADER;

struct ip6_opt_t {
  unsigned char  next_header;
  unsigned char  ext_len;
  unsigned char  pad[6];
} BPF_PACKET_HEADER;

struct icmp6_t {
  unsigned char   type;
  unsigned char   code;
  unsigned short  checksum;
} BPF_PACKET_HEADER;

struct udp_t {
  unsigned short sport;
  unsigned short dport;
  unsigned short length;
  unsigned short crc;
} BPF_PACKET_HEADER;

struct tcp_t {
  unsigned short  src_port;   // byte 0
  unsigned short  dst_port;
  unsigned int    seq_num;    // byte 4
  unsigned int    ack_num;    // byte 8
  unsigned char   offset:4;    // byte 12
  unsigned char   reserved:4;
  unsigned char   flag_cwr:1;
  unsigned char   flag_ece:1;
  unsigned char   flag_urg:1;
  unsigned char   flag_ack:1;
  unsigned char   flag_psh:1;
  unsigned char   flag_rst:1;
  unsigned char   flag_syn:1;
  unsigned char   flag_fin:1;
  unsigned short  rcv_wnd;
  unsigned short  cksum;      // byte 16
  unsigned short  urg_ptr;
} BPF_PACKET_HEADER;

struct vxlan_t {
  unsigned int rsv1:4;
  unsigned int iflag:1;
  unsigned int rsv2:3;
  unsigned int rsv3:24;
  unsigned int key:24;
  unsigned int rsv4:8;
} BPF_PACKET_HEADER;

struct vxlan_gbp_t {
  unsigned int gflag:1;
  unsigned int rsv1:3;
  unsigned int iflag:1;
  unsigned int rsv2:3;
  unsigned int rsv3:1;
  unsigned int dflag:1;
  unsigned int rsv4:1;
  unsigned int aflag:1;
  unsigned int rsv5:3;
  unsigned int tag:16;
  unsigned int key:24;
  unsigned int rsv6:8;
} BPF_PACKET_HEADER;

#endif
)********"
