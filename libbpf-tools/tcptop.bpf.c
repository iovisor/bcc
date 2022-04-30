// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "tcptop.h"


char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile pid_t filter_pid = 0;
const volatile pid_t filter_family = 0;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key,struct ipvx_key_t);
    __type(value, __u64);
} ipv4_recv_bytes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key,struct ipvx_key_t);
    __type(value, u64);
} ipv4_send_bytes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key,struct ipvx_key_t);
    __type(value, u64);
} ipv6_recv_bytes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key,struct ipvx_key_t);
    __type(value, u64);
} ipv6_send_bytes SEC(".maps");

static __always_inline void *
bpf_map_lookup_or_try_init(void *map, const void *key, const void *init)
{
    void *val;
    long err;

    val = bpf_map_lookup_elem(map, key);
    if (val)
        return val;

    err = bpf_map_update_elem(map, key, init, BPF_NOEXIST);
    if (err && err != -EEXIST)
        return 0;

    return bpf_map_lookup_elem(map, key);
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg,
               struct sock *sk,struct msghdr *msg,size_t size)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    static const __u64 zero;
    __u64 *val;
    __u32 family = BPF_CORE_READ(sk, __sk_common.skc_family);

    if(filter_pid && pid != filter_pid)
    {
        return 0;
    }
    if(filter_family && family != filter_family)
    {
        return 0;
    }
    if(family == AF_INET)
    {
        struct ipvx_key_t ipv4_key = {
            .pid = pid
        };
        bpf_get_current_comm(&ipv4_key.name, sizeof(ipv4_key.name));
        BPF_CORE_READ_INTO(&ipv4_key.saddr, sk, __sk_common.skc_rcv_saddr);
        ipv4_key.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        ipv4_key.lport = BPF_CORE_READ(sk, __sk_common.skc_num);
        ipv4_key.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
        val = bpf_map_lookup_or_try_init(&ipv4_send_bytes,&ipv4_key,&zero);
        if (val) {
            __atomic_add_fetch(val, size, __ATOMIC_RELAXED);
            bpf_printk("AF_INET %lld\n",ipv4_key.saddr);
        }
    } else if(family == AF_INET6)
    {
        struct ipvx_key_t ipv6_key = {
            .pid = pid
        };
        bpf_get_current_comm(&ipv6_key.name, sizeof(ipv6_key.name));
        BPF_CORE_READ_INTO(&ipv6_key.saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        BPF_CORE_READ_INTO(&ipv6_key.daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
        BPF_CORE_READ_INTO(&ipv6_key.lport, sk, __sk_common.skc_num);
        BPF_CORE_READ_INTO(&ipv6_key.dport, sk, __sk_common.skc_dport);
        val = bpf_map_lookup_or_try_init(&ipv6_send_bytes,&ipv6_key,&zero);
        if (val) {
            __atomic_add_fetch(val, size, __ATOMIC_RELAXED);
        }
    }
    return 0;
}


SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(tcp_cleanup_rbuf,
               struct sock *sk, int copid)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    static const __u64 zero;
    __u64 *val;
    __u32 family = BPF_CORE_READ(sk, __sk_common.skc_family);

    if(filter_pid && pid != filter_pid)
    {
        return 0;
    }
    if(filter_family && family != filter_family)
    {
        return 0;
    }
    if(copid <= 0)
    {
        return 0;
    }
    if(family == AF_INET)
    {
        struct ipvx_key_t ipv4_key = {
            .pid = pid
        };
        bpf_get_current_comm(&ipv4_key.name, sizeof(ipv4_key.name));
        BPF_CORE_READ_INTO(&ipv4_key.saddr, sk, __sk_common.skc_rcv_saddr);
        ipv4_key.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        ipv4_key.lport = BPF_CORE_READ(sk, __sk_common.skc_num);
        ipv4_key.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
        val = bpf_map_lookup_or_try_init(&ipv4_recv_bytes, &ipv4_key, &zero);
        if (val) {
            __atomic_add_fetch(val, copid, __ATOMIC_RELAXED);
            bpf_printk("AF_INET %lld\n",ipv4_key.saddr);
        }
    } else if(family == AF_INET6)
    {
        struct ipvx_key_t ipv6_key = {
            .pid = pid
        };
        bpf_get_current_comm(&ipv6_key.name, sizeof(ipv6_key.name));
        BPF_CORE_READ_INTO(&ipv6_key.saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        BPF_CORE_READ_INTO(&ipv6_key.daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
        BPF_CORE_READ_INTO(&ipv6_key.lport, sk, __sk_common.skc_num);
        BPF_CORE_READ_INTO(&ipv6_key.dport, sk, __sk_common.skc_dport);
        val = bpf_map_lookup_or_try_init(&ipv6_recv_bytes, &ipv6_key, &zero);
        if (val) {
            __atomic_add_fetch(val, copid, __ATOMIC_RELAXED);
        }
    }
    return 0;
}
