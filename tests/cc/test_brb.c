// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")
#include <bcc/proto.h>

/* compiler workaround */
#define _htonl __builtin_bswap32
#define _htons __builtin_bswap16

// meta data passed between bpf programs
typedef struct bpf_metadata {
    u32 prog_id;
    u32 rx_port_id;
} bpf_metadata_t;

typedef struct bpf_dest {
    u32 prog_id;
    u32 port_id;
} bpf_dest_t;

typedef struct eth_addr {
    u8 addr[6];
} eth_addr_t;

// Program table definitions for tail calls
BPF_TABLE("prog", u32, u32, jump, 16);

// physical endpoint manager (pem) tables which connects to boeht bridge 1 and bridge 2
// <port_id, bpf_dest>
BPF_TABLE("array", u32, bpf_dest_t, pem_dest, 256);
// <port_id, ifindex>
BPF_TABLE("array", u32, u32, pem_port, 256);
// <ifindex, port_id>
BPF_TABLE("hash", u32, u32, pem_ifindex, 256);
// <0, tx2vm_pkts>
BPF_TABLE("array", u32, u32, pem_stats, 1);

// bridge 1 (br1) tables
// <port_id, bpf_dest>
BPF_TABLE("array", u32, bpf_dest_t, br1_dest, 256);
// <eth_addr, port_id>
BPF_TABLE("hash", eth_addr_t, u32, br1_mac, 256);
// <0, rtr_ifindex>
BPF_TABLE("array", u32, u32, br1_rtr, 1);
// <mac, ifindex>
BPF_TABLE("hash", eth_addr_t, u32, br1_mac_ifindex, 1);

// bridge 2 (br2) tables
// <port_id, bpf_dest>
BPF_TABLE("array", u32, bpf_dest_t, br2_dest, 256);
// <eth_addr, port_id>
BPF_TABLE("hash", eth_addr_t, u32, br2_mac, 256);
// <0, rtr_ifindex>
BPF_TABLE("array", u32, u32, br2_rtr, 1);
// <mac, ifindex>
BPF_TABLE("hash", eth_addr_t, u32, br2_mac_ifindex, 1);

BPF_EXPORT(pem)
int pem(struct __sk_buff *skb) {
    bpf_metadata_t meta = {};
    u32 ifindex;
    u32 *tx_port_id_p;
    u32 tx_port_id;
    u32 rx_port;
    u32 *ifindex_p;
    bpf_dest_t *dest_p;

    // pem does not look at packet data
    if (skb->tc_index == 0) {
        skb->tc_index = 1;
        skb->cb[0] = skb->cb[1] = 0;
        meta.prog_id = meta.rx_port_id = 0;
    } else {
        meta.prog_id = skb->cb[0];
        meta.rx_port_id = skb->cb[1];
    }
    if (!meta.prog_id) {
        /* from external */
        ifindex = skb->ingress_ifindex;
        tx_port_id_p = pem_ifindex.lookup(&ifindex);
        if (tx_port_id_p) {
            tx_port_id = *tx_port_id_p;
            dest_p = pem_dest.lookup(&tx_port_id);
            if (dest_p) {
                skb->cb[0] = dest_p->prog_id;
                skb->cb[1] = dest_p->port_id;
                jump.call(skb, dest_p->prog_id);
            }
        }
    } else {
        /* from internal */
        rx_port = meta.rx_port_id;
        ifindex_p = pem_port.lookup(&rx_port);
        if (ifindex_p) {
#if 1
            /* accumulate stats, may hurt performance slightly */
            u32 index = 0;
            u32 *value = pem_stats.lookup(&index);
            if (value)
                lock_xadd(value, 1);
#endif
            bpf_clone_redirect(skb, *ifindex_p, 0);
        }
    }

    return 0;
}

static int br_common(struct __sk_buff *skb, int which_br) __attribute__((always_inline));
static int br_common(struct __sk_buff *skb, int which_br) {
    bpf_metadata_t meta = {};
    u16 proto;
    u16 arpop;
    eth_addr_t dmac;
    u8 *mac_p;
    u32 dip;
    u32 *tx_port_id_p;
    u32 tx_port_id;
    bpf_dest_t *dest_p;
    u32 index, *rtrif_p;

    if (skb->tc_index == 0) {
        skb->tc_index = 1;
        skb->cb[0] = skb->cb[1] = 0;
        meta.prog_id = meta.rx_port_id = 0;
    } else {
        meta.prog_id = skb->cb[0];
        meta.rx_port_id = skb->cb[1];
    }

    BEGIN(ethernet);
    PROTO(ethernet) {
        // ethernet->dst seems not working, so tentatively use the primitive C API.
        *(__u32 *)&dmac.addr[0] = _htonl(load_word(skb, 0));
        *(__u16 *)&dmac.addr[4] = _htons(load_half(skb, 4));
        if (meta.prog_id != 0) {
            /* send to the router */
            if (dmac.addr[0] & dmac.addr[1] & dmac.addr[2] & dmac.addr[3] & dmac.addr[4] & dmac.addr[5] == 0xff) {
                 index = 0;
                 if (which_br == 1)
                     rtrif_p = br1_rtr.lookup(&index);
                 else 
                     rtrif_p = br2_rtr.lookup(&index);
                 if (rtrif_p)
                     bpf_clone_redirect(skb, *rtrif_p, 0);
             } else {
                 /* the dmac address should match the router's */
                 if (which_br == 1)
                     rtrif_p = br1_mac_ifindex.lookup(&dmac);
                 else
                     rtrif_p = br2_mac_ifindex.lookup(&dmac);
                 if (rtrif_p)
                     bpf_clone_redirect(skb, *rtrif_p, 0);
             }
             return 0;
        }

        switch (ethernet->type) {
            case 0x0800: goto ip;
            case 0x0806: goto arp;
            case 0x8100: goto dot1q;
        }
        goto EOP;
    }

    PROTO(dot1q) {
        switch(dot1q->type) {
            case 0x0806: goto arp;
            case 0x0800: goto ip;
        }
        goto EOP;
    }

    PROTO(arp) {
        /* mac learning */
        // arpop = load_half(skb, 20);
        arpop = arp->oper;
        if (arpop == 2) {
            index = 0;
            if (which_br == 1)
                rtrif_p = br1_rtr.lookup(&index);
            else
                rtrif_p = br2_rtr.lookup(&index);
            if (rtrif_p) {
                __u32 ifindex = *rtrif_p;
                eth_addr_t smac;

                *(__u16 *)&smac.addr[0] = _htons(load_half(skb, 6));
                *(__u16 *)&smac.addr[2] = _htons(load_half(skb, 8));
                *(__u16 *)&smac.addr[4] = _htons(load_half(skb, 10));
                if (which_br == 1)
                    br1_mac_ifindex.update(&smac, &ifindex);
                else
                    br2_mac_ifindex.update(&smac, &ifindex);
            }
        }
        goto xmit;
    }

    PROTO(ip) {
        goto xmit;
    }

xmit:
    if (which_br == 1)
        tx_port_id_p = br1_mac.lookup(&dmac);
    else
        tx_port_id_p = br2_mac.lookup(&dmac);
    if (tx_port_id_p) {
        tx_port_id = *tx_port_id_p;
        if (which_br == 1)
            dest_p = br1_dest.lookup(&tx_port_id);
        else
            dest_p = br2_dest.lookup(&tx_port_id);
        if (dest_p) {
            skb->cb[0] = dest_p->prog_id;
            skb->cb[1] = dest_p->port_id;
            jump.call(skb, dest_p->prog_id);
        }
    }

EOP:
    return 0;
}

BPF_EXPORT(br1)
int br1(struct __sk_buff *skb) {
    return br_common(skb, 1);
}

BPF_EXPORT(br2)
int br2(struct __sk_buff *skb) {
    return br_common(skb, 2);
}
