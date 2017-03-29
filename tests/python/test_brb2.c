// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")
#include <bcc/proto.h>

// physical endpoint manager (pem) tables which connects VMs and bridges
// <ifindex_in, ifindex_out>
BPF_HASH(pem_dest, u32, u32, 256);
// <0, tx_pkts>
BPF_ARRAY(pem_stats, u32, 1);

int pem(struct __sk_buff *skb) {
    u32 ifindex_in, *ifindex_p;
    u8 *cursor = 0;
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));

    ifindex_in = skb->ingress_ifindex;
    ifindex_p = pem_dest.lookup(&ifindex_in);
    if (ifindex_p) {
#if 1
        if (ethernet->type == 0x0800 || ethernet->type == 0x0806) {
            /* accumulate stats */
            u32 index = 0;
            u32 *value = pem_stats.lookup(&index);
            if (value)
                lock_xadd(value, 1);
        }
#endif
        bpf_clone_redirect(skb, *ifindex_p, 0);
    }

    return 1;
}
