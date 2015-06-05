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
#include <linux/types.h>

struct ethernet_t {
  u64 dst:48;
  u64 src:48;
  u32 type:16;
} __attribute__((packed));

struct dot1q_t {
  u16 pri:3;
  u16 cfi:1;
  u16 vlanid:12;
  u16 type;
} __attribute__((packed));

struct arp_t {
  u16 htype;
  u16 ptype;
  u8 hlen;
  u8 plen;
  u16 oper;
  u64 sha:48;
  u64 spa:32;
  u64 tha:48;
  u32 tpa;
} __attribute__((packed));

struct ip_t {
  u8 ver:4;           // byte 0
  u8 hlen:4;
  u8 tos;
  u16 tlen;
  u16 identification; // byte 4
  u16 ffo_unused:1;
  u16 df:1;
  u16 mf:1;
  u16 foffset:13;
  u8 ttl;             // byte 8
  u8 nextp;
  u16 hchecksum;
  u32 src;            // byte 12
  u32 dst;            // byte 16
} __attribute__((packed));

struct udp_t {
  u16 sport;
  u16 dport;
  u16 length;
  u16 crc;
} __attribute__((packed));

struct tcp_t {
  u16 src_port;   // byte 0
  u16 dst_port;
  u32 seq_num;    // byte 4
  u32 ack_num;    // byte 8
  u8 offset:4;    // byte 12
  u8 reserved:4;
  u8 flag_cwr:1;
  u8 flag_ece:1;
  u8 flag_urg:1;
  u8 flag_ack:1;
  u8 flag_psh:1;
  u8 flag_rst:1;
  u8 flag_syn:1;
  u8 flag_fin:1;
  u16 rcv_wnd;
  u16 cksum;      // byte 16
  u16 urg_ptr;
} __attribute__((packed));
