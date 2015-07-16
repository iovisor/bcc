// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")
#include <bcc/proto.h>

// physical endpoint manager (pem) tables which connects VMs and bridges
// <ifindex_in, ifindex_out>
BPF_TABLE("hash", u32, u32, pem_dest, 256);
// <0, tx_pkts>
BPF_TABLE("array", u32, u32, pem_stats, 1);

int pem(struct __sk_buff *skb) {
    u32 *ifindex_p = pem_dest.lookup(skb->ingress_ifindex);
    if (ifindex_p) {
#if 1
        /* accumulate stats */
        u32 *value = pem_stats.lookup(0);
        if (value)
            lock_xadd(value, 1);
#endif
        bpf_clone_redirect(skb, *ifindex_p, 0);
    }

    return 1;
}
