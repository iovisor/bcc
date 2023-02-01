/*author: https://github.com/agentzex
Licensed under the Apache License, Version 2.0 (the "License")

tcp_mon_block.c - uses netlink TC, kernel tracepoints and kprobes to monitor outgoing connections from given PIDs
and block connections to all addresses initiated from them (acting like an in-process firewall), unless they are listed in allow_list
*/

#include <uapi/linux/bpf.h>
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <linux/tcp.h>
#include <uapi/linux/pkt_cls.h>
#include <linux/fs.h>
#include <linux/uaccess.h>


typedef struct
{
    u32 src_ip;
    u16 src_port;
    u32 dst_ip;
    u16 dst_port;
    u32 pid;
    u8 tcp_flags;
    char comm[TASK_COMM_LEN];
} full_packet;


typedef struct
{
    u8 state;
    u32 src_ip;
    u16 src_port;
    u32 dst_ip;
    u16 dst_port;
    u32 pid;
    char comm[TASK_COMM_LEN];
} verbose_event;


typedef struct
{
    u32 src_ip;
    u16 src_port;
    u32 dst_ip;
    u16 dst_port;
} key_hash;


BPF_HASH(monitored_connections, key_hash, full_packet);
BPF_HASH(allow_list, u32, u32);
BPF_HASH(pid_list, u32, u32);
BPF_PERF_OUTPUT(blocked_events);
BPF_PERF_OUTPUT(verbose_events);


#ifndef tcp_flag_byte
#define tcp_flag_byte(th) (((u_int8_t *)th)[13])
#endif


static bool VERBOSE_OUTPUT = false;


static __always_inline int tcp_header_bound_check(struct tcphdr* tcp, void* data_end)
{
    if ((void *)tcp + sizeof(*tcp) > data_end)
    {
        return -1;
    }

    return 0;
}


static void make_verbose_event(verbose_event *v, u32 src_ip, u32 dst_ip, u16 src_port, u16 dst_port, u32 pid, u8 state)
{
    v->src_ip = src_ip;
    v->src_port = src_port;
    v->dst_ip = dst_ip;
    v->dst_port = dst_port;
    v->pid = pid;
    v->state = state;
    bpf_get_current_comm(&v->comm, sizeof(v->comm));
}


int handle_egress(struct __sk_buff *ctx)
{
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(*eth);
    struct tcphdr *tcp;
    key_hash key = {};

    /* length check */
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
    {
        return TC_ACT_OK;
    }

    if (eth->h_proto != htons(ETH_P_IP))
    {
        return TC_ACT_OK;
    }

    if (ip->protocol != IPPROTO_TCP)
    {
        return TC_ACT_OK;
    }

    tcp = (void *)ip + sizeof(*ip);
    if (tcp_header_bound_check(tcp, data_end))
    {
        return TC_ACT_OK;
    }

    u8 tcpflags = ((u_int8_t *)tcp)[13];
    u16 src_port = bpf_ntohs(tcp->source);
    u16 dst_port = bpf_ntohs(tcp->dest);

    key.src_ip = ip->saddr;
    key.src_port = src_port;
    key.dst_ip = ip->daddr;
    key.dst_port = dst_port;

    full_packet *packet_value;
    packet_value = monitored_connections.lookup(&key);
    if (packet_value != 0)
    {
        packet_value->tcp_flags = tcpflags;
        blocked_events.perf_submit(ctx, packet_value, sizeof(full_packet));
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}


// Removing the entry from monitored_connections when the socket closes after failed connection
TRACEPOINT_PROBE(sock, inet_sock_set_state)
{
    if (args->protocol != IPPROTO_TCP)
    {
        return 0;
    }

    if (args->newstate != TCP_CLOSE && args->newstate != TCP_CLOSE_WAIT)
    {
        return 0;
    }

    if (args->family == AF_INET)
    {
        key_hash key = {};
        struct sock *sk = (struct sock *)args->skaddr;

        key.src_port = args->sport;
        key.dst_port = args->dport;
        __builtin_memcpy(&key.src_ip, args->saddr, sizeof(key.src_ip));
        __builtin_memcpy(&key.dst_ip, args->daddr, sizeof(key.dst_ip));

        full_packet *packet_value;
        packet_value = monitored_connections.lookup(&key);
        if (packet_value != 0)
        {
            monitored_connections.delete(&key);
            if (VERBOSE_OUTPUT)
            {
                verbose_event v = {};
                make_verbose_event(&v, packet_value->src_ip, packet_value->dst_ip, packet_value->src_port, packet_value->dst_port, packet_value->pid, 3);
                verbose_events.perf_submit(args, &v, sizeof(v));
            }

        }
    }

    return 0;
}




int trace_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
    key_hash key = {};
    full_packet packet_value = {};
    u8 verbose_state = 0;

    u16 family = sk->__sk_common.skc_family;
    if (family != AF_INET)
    {
        return 0;
    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u16 dst_port = sk->__sk_common.skc_dport;
    dst_port = ntohs(dst_port);
    u16 src_port = sk->__sk_common.skc_num;
    u32 src_ip = sk->__sk_common.skc_rcv_saddr;
    u32 dst_ip = sk->__sk_common.skc_daddr;

    u32 *monitored_pid = pid_list.lookup(&pid);
    if (!monitored_pid)
    {
        return 0;
    }

    u32 *allowed_ip = allow_list.lookup(&dst_ip);
    if (!allowed_ip)
    {
        key.src_ip = src_ip;
        key.src_port = src_port;
        key.dst_ip = dst_ip;
        key.dst_port = dst_port;

        packet_value.src_ip = src_ip;
        packet_value.src_port = src_port;
        packet_value.dst_ip = dst_ip;
        packet_value.dst_port = dst_port;
        packet_value.pid = pid;
        bpf_get_current_comm(&packet_value.comm, sizeof(packet_value.comm));
        verbose_state = 1;
        monitored_connections.update(&key, &packet_value);
    }
    else
    {
        verbose_state = 2;
    }

    if (VERBOSE_OUTPUT)
    {
        verbose_event v = {};
        make_verbose_event(&v, src_ip, dst_ip, src_port, dst_port, pid, verbose_state);
        verbose_events.perf_submit(ctx, &v, sizeof(v));
    }

    return 0;
}