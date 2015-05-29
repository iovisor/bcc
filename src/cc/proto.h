#include <linux/types.h>

struct ethernet_t {
  u64 dst:48;
  u64 src:48;
  u32 type:16;
} __attribute__((packed));

struct dot1q_t {
  u32 pri:3;
  u32 cfi:1;
  u32 vlanid:12;
  u32 type:16;
} __attribute__((packed));

struct ip_t {
  u32 ver:4;              // byte 0
  u32 hlen:4;
  u32 tos:8;
  u32 tlen:16;
  u32 identification:16;  // byte 4
  u32 ffo_unused:1;
  u32 df:1;
  u32 mf:1;
  u32 foffset:13;
  u32 ttl:8;              // byte 8
  u32 nextp:8;
  u32 hchecksum:16;
  u32 src:32;             // byte 12
  u32 dst:32;             // byte 16
} __attribute__((packed));

struct udp_t {
  u32 sport:16;
  u32 dport:16;
  u32 length:16;
  u32 crc:16;
} __attribute__((packed));

struct tcp_t {
  u16 src_port:16;  // byte 0
  u16 dst_port:16;
  u32 seq_num:32;   // byte 4
  u32 ack_num:32;   // byte 8
  u8 offset:4;      // byte 12
  u8 reserved:4;
  u8 flag_cwr:1;
  u8 flag_ece:1;
  u8 flag_urg:1;
  u8 flag_ack:1;
  u8 flag_psh:1;
  u8 flag_rst:1;
  u8 flag_syn:1;
  u8 flag_fin:1;
  u16 rcv_wnd:16;
  u16 cksum:16;     // byte 16
  u16 urg_ptr:16;
} __attribute__((packed));
