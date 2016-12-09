// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")

#packed "true"

struct ethernet {
  u64 dst:48;
  u64 src:48;
  u32 type:16;
};

state ethernet {
  switch $ethernet.type {
    case 0x0800 {
      next proto::ip;
    };
    case 0x8100 {
      next proto::dot1q;
    };
    case * {
      goto EOP;
    };
  }
}


struct dot1q {
  u32 pri:3;
  u32 cfi:1;
  u32 vlanid:12;
  u32 type:16;
};

state dot1q {
  switch $dot1q.type {
    case 0x0800 {
      next proto::ip;
    };
    case * {
      goto EOP;
    };
  }
}


struct ip {
  u32 ver:4;
  u32 hlen:4;
  u32 tos:8;
  u32 tlen:16;
  u32 identification:16;
  u32 ffo_unused:1;
  u32 df:1;
  u32 mf:1;
  u32 foffset:13;
  u32 ttl:8;
  u32 nextp:8;
  u32 hchecksum:16;
  u32 src:32;
  u32 dst:32;
};

state ip {
  switch $ip.nextp {
    case 6 {
      next proto::tcp;
    };
    case 17 {
      next proto::udp;
    };
    case 47 {
      next proto::gre;
    };
    case * {
      goto EOP;
    };
  }
}


struct udp {
  u32 sport:16;
  u32 dport:16;
  u32 length:16;
  u32 crc:16;
};

state udp {
  switch $udp.dport {
    case 8472 {
      next proto::vxlan;
    };
    case * {
      goto EOP;
    };
  }
}

struct tcp {
  u16 src_port:16;
  u16 dst_port:16;
  u32 seq_num:32;
  u32 ack_num:32;
  u8 offset:4;
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
  u16 cksum:16;
  u16 urg_ptr:16;
};

state tcp {
  goto EOP;
}

struct vxlan {
  u32 rsv1:4;
  u32 iflag:1;
  u32 rsv2:3;
  u32 rsv3:24;
  u32 key:24;
  u32 rsv4:8;
};

state vxlan {
  goto EOP;
}


struct gre {
  u32 cflag:1;
  u32 rflag:1;
  u32 kflag:1;
  u32 snflag:1;
  u32 srflag:1;
  u32 recurflag:3;
  u32 reserved:5;
  u32 vflag:3;
  u32 protocol:16;
  u32 key:32;
};

state gre {
  switch $gre.protocol {
    case * {
      goto EOP;
    };
  }
}

