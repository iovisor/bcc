#!/usr/bin/env python3
# coding:utf-8
#
# udpsend    Trace UDP sendmsg()s.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: udpsend [-h] [-T] [-t] [-d] [-P PORT[,PORT ...]]
#
# Traces sendmsg() calls that reach udp_sendmsg() or udpv6_sendmsg(), including
# failed calls.
#
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 14-Jan-2024   Zhixiong Wei   Created this.

import argparse
import os
from socket import inet_ntop, AF_INET, AF_INET6, htons, ntohs
from struct import pack, unpack_from
import sys
from time import monotonic, strftime

DNS_QTYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    41: "OPT",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    50: "NSEC3",
    52: "TLSA",
    64: "SVCB",
    65: "HTTPS",
    255: "ANY",
    257: "CAA",
}

DNS_QCLASSES = (1, 3, 4, 255)  # IN, CH, HS, ANY
DNS_QUERY_AR_TYPES = (24, 41, 250)  # SIG(0), OPT (EDNS0), TSIG
DNS_MAX_QUERY_LEN = 4096
MAX_FILTER_PORTS = 64


def parse_ports(port_arg):
    """Parse a comma-separated list of destination ports (1..65535)."""
    if not port_arg:
        raise ValueError("port list cannot be empty")
    ports = []
    seen = set()
    for raw in port_arg.split(","):
        item = raw.strip()
        if not item:
            raise ValueError("empty port entry in %r" % port_arg)
        try:
            port = int(item, 10)
        except ValueError:
            raise ValueError("invalid port %r" % item)
        if port < 1 or port > 65535:
            raise ValueError("port %d out of range (1-65535)" % port)
        if port not in seen:
            seen.add(port)
            ports.append(port)
    if len(ports) > MAX_FILTER_PORTS:
        raise ValueError("too many ports (max %d)" % MAX_FILTER_PORTS)
    return ports


def _skip_dns_name(payload, pos, valid_name_offsets):
    """Advance past a DNS domain name in payload.

    Returns (new_offset, new_label_offsets) on success, (None, None) if
    truncated at end of payload, or (-1, None) if malformed.
    """
    seen = []
    while pos < len(payload):
        llen = payload[pos]
        if llen == 0:
            seen.append(pos)
            return pos + 1, seen
        if (llen & 0xc0) == 0xc0:
            if pos + 2 > len(payload):
                return None, None
            ptr = ((llen & 0x3f) << 8) | payload[pos + 1]
            # RFC 1035 compression pointers must target a previously validated
            # label start (never mid-label and never inside the current name).
            if ptr not in valid_name_offsets:
                return -1, None
            return pos + 2, seen
        if llen > 63:
            return -1, None
        seen.append(pos)
        pos += 1 + llen
        if pos > len(payload):
            return None, None
    return None, None


def parse_dns_query(payload, msg_len=None):
    """Parse a standard UDP DNS query (QR=0, QDCOUNT=1) into 'query <QNAME> <QTYPE>'.

    Returns None if payload does not strictly match a DNS query.
    """
    if len(payload) < 17:
        return None
    if msg_len is None:
        msg_len = len(payload)
    if msg_len < len(payload) or msg_len < 17 or msg_len > DNS_MAX_QUERY_LEN:
        return None

    _, flags, qdcount, ancount, nscount, arcount = unpack_from("!HHHHHH", payload, 0)
    # Require standard query: QR=0, OPCODE=0, AA=0, TC=0, RA=0, Z=0, RCODE=0.
    # Allow RD (0x0100), AD (0x0020), and CD (0x0010).
    if (flags & 0xfecf) != 0:
        return None
    if qdcount != 1 or ancount != 0 or nscount != 0 or arcount > 2:
        return None

    # Parse RFC 1035 QNAME labels (no compression pointers in the first question).
    pos = 12
    labels = []
    valid_name_offsets = set()
    qname_wire_len = 0
    while True:
        if pos >= len(payload):
            return None
        valid_name_offsets.add(pos)
        llen = payload[pos]
        pos += 1
        qname_wire_len += 1
        if llen == 0:
            break
        if llen > 63:
            return None
        if pos + llen > len(payload):
            return None
        qname_wire_len += llen
        if qname_wire_len > 255:
            return None
        raw = payload[pos:pos + llen]
        pos += llen
        # Reject control characters, whitespace, and non-ASCII bytes to prevent
        # false positives on binary protocols and keep column formatting intact.
        for b in raw:
            if b < 0x21 or b > 0x7e:
                return None
        label = raw.decode("ascii").replace("\\", "\\\\").replace(".", "\\.")
        labels.append(label)

    if pos + 4 > len(payload):
        return None
    qtype, qclass = unpack_from("!HH", payload, pos)
    pos += 4

    # Mask mDNS unicast-response bit (0x8000) when validating QCLASS.
    if qtype == 0 or (qclass & 0x7fff) not in DNS_QCLASSES:
        return None

    # Validate trailing additional records to suppress false positives on
    # non-DNS UDP packets.
    if arcount == 0:
        if msg_len != pos:
            return None
    else:
        ar_pos = pos
        truncated = False
        seen_opt = False
        for ar_idx in range(arcount):
            min_rem = (arcount - ar_idx) * 11
            if msg_len < ar_pos + min_rem:
                return None
            if ar_pos >= len(payload):
                truncated = True
                break
            rr_hdr_pos, new_offsets = _skip_dns_name(
                payload, ar_pos, valid_name_offsets
            )
            if rr_hdr_pos == -1:
                return None
            if rr_hdr_pos is None:
                # If the captured prefix ended mid-name, allow truncation only
                # when the full datagram is longer than the captured prefix.
                if len(payload) < msg_len:
                    truncated = True
                    break
                return None
            valid_name_offsets.update(new_offsets)
            if rr_hdr_pos + 10 > len(payload):
                if len(payload) < msg_len and msg_len >= rr_hdr_pos + 10 + (arcount - ar_idx - 1) * 11:
                    truncated = True
                    break
                return None
            rr_type, _, _, rr_rdlen = unpack_from("!HHIH", payload, rr_hdr_pos)
            if rr_type not in DNS_QUERY_AR_TYPES:
                return None
            if rr_type == 41:
                if seen_opt or payload[ar_pos] != 0:
                    return None
                seen_opt = True
            elif rr_type == 250 and ar_idx != arcount - 1:
                return None
            ar_pos = rr_hdr_pos + 10 + rr_rdlen
            if ar_pos > msg_len:
                return None
        if not truncated and ar_pos != msg_len:
            return None

    qname = ".".join(labels) if labels else "."
    qtype_str = DNS_QTYPES.get(qtype, "TYPE%d" % qtype)
    return "query %s %s" % (qname, qtype_str)


# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/socket.h>
#include <linux/udp.h>
#include <uapi/linux/in.h>

#ifdef ENABLE_DNS
#include <linux/uio.h>
#include <linux/version.h>
#define DNS_HDR_LEN 12
#define DNS_MAX_LEN 256
#define DNS_MAX_QUERY_LEN 4096

// When vmlinux BTF is unavailable (kernel_struct_has_field() returns -1),
// fall back to kernel version checks matching upstream iov_iter transitions.
#ifndef IOV_ITER_BTF_AVAILABLE
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
#define IOV_ITER_HAS_ITER_TYPE 1
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
#define IOV_ITER_HAS_UBUF 1
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
#define IOV_ITER_IOV_FIELD __iov
#else
#define IOV_ITER_IOV_FIELD iov
#endif
#endif
#endif

struct ipv4_data_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u64 ip;
    u16 sport;
    u16 dport;
    char task[TASK_COMM_LEN];
#ifdef ENABLE_DNS
    u16 dns_len;
    u16 dns_msg_len;
    u8 dns_payload[DNS_MAX_LEN];
#endif
};
BPF_PERF_OUTPUT(ipv4_events);

#ifdef ENABLE_DNS
BPF_PERCPU_ARRAY(v4_scratch, struct ipv4_data_t, 1);

static __always_inline void capture_dns_query(struct msghdr *msg, size_t len,
                                              int pending, u16 *out_len,
                                              u16 *out_msg_len, u8 *out_buf) {
    if (pending != 0 || len < 17 || len > DNS_MAX_QUERY_LEN)
        return;

    unsigned int msg_flags = 0;
    bpf_probe_read_kernel(&msg_flags, sizeof(msg_flags), &msg->msg_flags);
    if (msg_flags & MSG_MORE)
        return;

    size_t count = 0;
    bpf_probe_read_kernel(&count, sizeof(count), &msg->msg_iter.count);
    if (count < 17)
        return;

    size_t iov_offset = 0;
    bpf_probe_read_kernel(&iov_offset, sizeof(iov_offset),
        &msg->msg_iter.iov_offset);

    const void *src = NULL;
    size_t seg_len = 0;
    bool is_user = true;

#ifdef IOV_ITER_HAS_ITER_TYPE
    u8 itype = 0;
    bpf_probe_read_kernel(&itype, sizeof(itype), &msg->msg_iter.iter_type);
#else
    unsigned int itype = 0;
    bpf_probe_read_kernel(&itype, sizeof(itype), &msg->msg_iter.type);
    itype &= ~1U;
#endif

#ifdef IOV_ITER_HAS_UBUF
    if (itype == ITER_UBUF) {
        void *ubuf = NULL;
        bpf_probe_read_kernel(&ubuf, sizeof(ubuf), &msg->msg_iter.ubuf);
        if (!ubuf)
            return;
        src = (const char *)ubuf + iov_offset;
        seg_len = count;
    } else
#endif
    if (itype == ITER_IOVEC) {
        const struct iovec *iovp = NULL;
        bpf_probe_read_kernel(&iovp, sizeof(iovp),
            &msg->msg_iter.IOV_ITER_IOV_FIELD);
        if (!iovp)
            return;
        struct iovec iov = {};
        bpf_probe_read_kernel(&iov, sizeof(iov), iovp);
        if (!iov.iov_base || iov_offset >= iov.iov_len)
            return;
        src = (const char *)iov.iov_base + iov_offset;
        seg_len = iov.iov_len - iov_offset;
        if (seg_len > count)
            seg_len = count;
    } else if (itype == ITER_KVEC) {
        const struct kvec *kvp = NULL;
        bpf_probe_read_kernel(&kvp, sizeof(kvp), &msg->msg_iter.kvec);
        if (!kvp)
            return;
        struct kvec kv = {};
        bpf_probe_read_kernel(&kv, sizeof(kv), kvp);
        if (!kv.iov_base || iov_offset >= kv.iov_len)
            return;
        src = (const char *)kv.iov_base + iov_offset;
        seg_len = kv.iov_len - iov_offset;
        if (seg_len > count)
            seg_len = count;
        is_user = false;
    } else {
        return;
    }

    if (seg_len > len)
        seg_len = len;
    if (seg_len < 17)
        return;

    // Fast 12-byte DNS query header prefilter before copying full payload.
    u8 hdr[DNS_HDR_LEN];
    int rc = is_user
        ? bpf_probe_read_user(hdr, sizeof(hdr), src)
        : bpf_probe_read_kernel(hdr, sizeof(hdr), src);
    if (rc != 0)
        return;

    u16 flags = ((u16)hdr[2] << 8) | hdr[3];
    u16 qdcount = ((u16)hdr[4] << 8) | hdr[5];
    u16 ancount = ((u16)hdr[6] << 8) | hdr[7];
    u16 nscount = ((u16)hdr[8] << 8) | hdr[9];
    u16 arcount = ((u16)hdr[10] << 8) | hdr[11];
    if ((flags & 0xfecf) != 0)
        return;
    if (qdcount != 1 || ancount != 0 || nscount != 0 || arcount > 2)
        return;

    u32 copy_len = DNS_MAX_LEN;
    if (seg_len < DNS_MAX_LEN)
        copy_len = (u32)seg_len;
    if (copy_len < DNS_HDR_LEN || copy_len > DNS_MAX_LEN)
        return;

    rc = is_user
        ? bpf_probe_read_user(out_buf, copy_len, src)
        : bpf_probe_read_kernel(out_buf, copy_len, src);
    if (rc != 0)
        return;

    *out_len = (u16)copy_len;
    *out_msg_len = (u16)len;
}
#endif

#if IS_ENABLED(CONFIG_IPV6)
#include <uapi/linux/in6.h>

struct ipv6_data_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 ip;
    u16 sport;
    u16 dport;
    char task[TASK_COMM_LEN];
#ifdef ENABLE_DNS
    u16 dns_len;
    u16 dns_msg_len;
    u8 dns_payload[DNS_MAX_LEN];
#endif
};
BPF_PERF_OUTPUT(ipv6_events);

struct ipv6_call_t {
    struct ipv6_data_t event;
    u64 sock_addr;
    u64 msg_addr;
};

struct ipv6_stats_t {
    u64 store_failures;
    u64 unreturned;
    u64 evicted;
};

// Keep one pending call per thread until return or forwarding to udp_sendmsg().
// Use an LRU hash (Linux >= 4.10) so orphaned entries from missed kretprobes
// are automatically evicted by the kernel without needing a global thread-exit
// probe or userspace table scans.
BPF_TABLE("lru_hash", u64, struct ipv6_call_t, v6_pending, 10240);
BPF_ARRAY(v6_stats, struct ipv6_stats_t, 1);
#ifdef ENABLE_DNS
BPF_PERCPU_ARRAY(v6_scratch, struct ipv6_call_t, 1);
BPF_PERCPU_ARRAY(v6_ret_scratch, struct ipv6_data_t, 1);
#endif

static __always_inline void discard_unreturned_ipv6(u64 pid_tgid) {
    if (v6_pending.delete(&pid_tgid) != 0)
        return;

    u32 zero = 0;
    struct ipv6_stats_t *stats = v6_stats.lookup(&zero);
    if (stats)
        __sync_fetch_and_add(&stats->unreturned, 1);
}
#endif

// IPv4 path. udp_sendmsg() is also the function udpv6_sendmsg() forwards to for
// v4 / v4-mapped / IPv4-corked sends on dual-stack sockets, so this is where
// those get reported.
//
// Note: For normal userspace sends, inet_sendmsg() runs inet_autobind() before
// calling udp_sendmsg(), so SPORT (skc_num) is already assigned even on a
// socket's first send. For unbound, unconnected sockets, SADDR (skc_rcv_saddr)
// remains 0.0.0.0 on every send because the kernel does not write the
// route-selected source address back into the socket.
int kprobe__udp_sendmsg(struct pt_regs *ctx, struct sock *sk,
                        struct msghdr *msg, size_t len) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
#if IS_ENABLED(CONFIG_IPV6)
    // udpv6_sendmsg() forwards with the same socket and msghdr, even when it
    // changes msg_name. An unrelated send on this thread must keep the event.
    struct ipv6_call_t *call = v6_pending.lookup(&pid_tgid);
    if (call && call->sock_addr == (u64)sk && call->msg_addr == (u64)msg)
        v6_pending.delete(&pid_tgid);
#endif
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid();

#ifdef ENABLE_DNS
    u32 zero = 0;
    struct ipv4_data_t *data4 = v4_scratch.lookup(&zero);
    if (!data4)
        return 0;
    if (data4->dns_len != 0)
        __builtin_memset(data4->dns_payload, 0, sizeof(data4->dns_payload));
    data4->dns_len = 0;
    data4->dns_msg_len = 0;
#else
    struct ipv4_data_t data4_stack;
    __builtin_memset(&data4_stack, 0, sizeof(data4_stack));
    struct ipv4_data_t *data4 = &data4_stack;
#endif
    data4->pid = pid;
    data4->uid = uid;
    data4->ip = 4;
    data4->ts_us = bpf_ktime_get_ns() / 1000;
    bpf_probe_read_kernel(&data4->saddr, sizeof(data4->saddr),
        &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&data4->sport, sizeof(data4->sport),
        &sk->__sk_common.skc_num);

    struct udp_sock *up = (struct udp_sock *)sk;
    int pending = 0;
    bpf_probe_read_kernel(&pending, sizeof(pending), &up->pending);

    if (pending == AF_INET) {
        // Corked send (UDP_CORK / MSG_MORE): destination is saved in cork.fl.
        bpf_probe_read_kernel(&data4->daddr, sizeof(data4->daddr),
            &up->inet.cork.fl.u.ip4.daddr);
        bpf_probe_read_kernel(&data4->dport, sizeof(data4->dport),
            &up->inet.cork.fl.u.ip4.uli.ports.dport);
    } else {
        // A sendto() destination overrides the connected peer (UDP allows
        // sendto() on an already-connected socket), so msg->msg_name takes
        // priority. Validate msg_namelen and sa_family (udp_sendmsg() permits
        // AF_INET and AF_UNSPEC).
        void *msg_name = NULL;
        int msg_namelen = 0;
        bpf_probe_read_kernel(&msg_name, sizeof(msg_name), &msg->msg_name);
        bpf_probe_read_kernel(&msg_namelen, sizeof(msg_namelen), &msg->msg_namelen);

        u16 sa_family = 0xffff;
        if (msg_name != NULL && msg_namelen >= (int)sizeof(struct sockaddr_in))
            bpf_probe_read_kernel(&sa_family, sizeof(sa_family), msg_name);

        if (sa_family == AF_INET || sa_family == AF_UNSPEC) {
            struct sockaddr_in sin = {};
            bpf_probe_read_kernel(&sin, sizeof(sin), msg_name);
            data4->daddr = sin.sin_addr.s_addr;
            data4->dport = sin.sin_port;
        } else {
            // no (decodable) explicit destination: fall back to the connected peer
            bpf_probe_read_kernel(&data4->daddr, sizeof(data4->daddr),
                &sk->__sk_common.skc_daddr);
            bpf_probe_read_kernel(&data4->dport, sizeof(data4->dport),
                &sk->__sk_common.skc_dport);
        }
    }

    FILTER_DPORT_V4

#ifdef ENABLE_DNS
    capture_dns_query(msg, len, pending, &data4->dns_len, &data4->dns_msg_len,
        data4->dns_payload);
#endif
    bpf_get_current_comm(&data4->task, sizeof(data4->task));
    ipv4_events.perf_submit(ctx, data4, sizeof(*data4));
    return 0;
}

#if IS_ENABLED(CONFIG_IPV6)
// IPv6 path. Attached manually to udpv6_sendmsg() entry + return (see Python side).
int trace_udpv6_sendmsg(struct pt_regs *ctx, struct sock *sk,
                        struct msghdr *msg, size_t len) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    // A leftover record belongs to a call whose return probe did not run.
    discard_unreturned_ipv6(pid_tgid);

#ifdef ENABLE_DNS
    u32 zero = 0;
    struct ipv6_call_t *call = v6_scratch.lookup(&zero);
    if (!call)
        return 0;
    if (call->event.dns_len != 0)
        __builtin_memset(call->event.dns_payload, 0,
            sizeof(call->event.dns_payload));
    call->event.dns_len = 0;
    call->event.dns_msg_len = 0;
    call->event.daddr = 0;
    call->event.dport = 0;
#else
    struct ipv6_call_t call_stack;
    __builtin_memset(&call_stack, 0, sizeof(call_stack));
    struct ipv6_call_t *call = &call_stack;
#endif
    call->sock_addr = (u64)sk;
    call->msg_addr = (u64)msg;
    struct ipv6_data_t *data6 = &call->event;
    data6->pid = pid_tgid >> 32;
    data6->uid = bpf_get_current_uid_gid();
    data6->ip = 6;
    data6->ts_us = bpf_ktime_get_ns() / 1000;
    bpf_probe_read_kernel(&data6->saddr, sizeof(data6->saddr),
        &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    bpf_probe_read_kernel(&data6->sport, sizeof(data6->sport),
        &sk->__sk_common.skc_num);

    struct udp_sock *up = (struct udp_sock *)sk;
    int pending = 0;
    bpf_probe_read_kernel(&pending, sizeof(pending), &up->pending);

    void *msg_name = NULL;
    int msg_namelen = 0;
    bpf_probe_read_kernel(&msg_name, sizeof(msg_name), &msg->msg_name);
    bpf_probe_read_kernel(&msg_namelen, sizeof(msg_namelen), &msg->msg_namelen);

    bool use_cork_or_peer = false;
    if (msg_name != NULL) {
        if (msg_namelen >= (int)sizeof(u16)) {
            u16 sa_family = 0xffff;
            bpf_probe_read_kernel(&sa_family, sizeof(sa_family), msg_name);
            if (sa_family == AF_INET6 &&
                msg_namelen >=
                    (int)offsetof(struct sockaddr_in6, sin6_scope_id)) {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)msg_name;
                u32 daddr[4] = {};
                bpf_probe_read_kernel(&daddr, sizeof(daddr), &sin6->sin6_addr);
                if (pending == AF_INET6 &&
                    !(daddr[0] == 0 && daddr[1] == 0 &&
                      daddr[2] == bpf_htonl(0x0000ffff))) {
                    // Kernel appends native IPv6 sends to the existing corked
                    // IPv6 flow rather than switching to the new destination.
                    use_cork_or_peer = true;
                } else {
                    __builtin_memcpy(&data6->daddr, daddr, sizeof(data6->daddr));
                    bpf_probe_read_kernel(&data6->dport, sizeof(data6->dport),
                        &sin6->sin6_port);
                }
            } else if (sa_family == AF_INET &&
                       msg_namelen >= (int)sizeof(struct sockaddr_in)) {
                // Only emitted if udp_sendmsg() is NOT invoked (e.g. IPV6_V6ONLY).
                struct sockaddr_in sin = {};
                bpf_probe_read_kernel(&sin, sizeof(sin), msg_name);
                u32 mapped[4] = {0, 0, bpf_htonl(0x0000ffff), sin.sin_addr.s_addr};
                __builtin_memcpy(&data6->daddr, mapped, sizeof(data6->daddr));
                data6->dport = sin.sin_port;
            } else if (sa_family == AF_UNSPEC) {
                use_cork_or_peer = true;
            }
        }
    } else {
        use_cork_or_peer = true;
    }

    if (use_cork_or_peer) {
        if (pending == AF_INET6) {
            bpf_probe_read_kernel(&data6->daddr, sizeof(data6->daddr),
                &up->inet.cork.fl.u.ip6.daddr.in6_u.u6_addr32);
            bpf_probe_read_kernel(&data6->dport, sizeof(data6->dport),
                &up->inet.cork.fl.u.ip6.uli.ports.dport);
        } else {
            bpf_probe_read_kernel(&data6->daddr, sizeof(data6->daddr),
                &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
            bpf_probe_read_kernel(&data6->dport, sizeof(data6->dport),
                &sk->__sk_common.skc_dport);
        }
    }

    FILTER_DPORT_V6

#ifdef ENABLE_DNS
    capture_dns_query(msg, len, pending, &data6->dns_len, &data6->dns_msg_len,
        data6->dns_payload);
#endif
    bpf_get_current_comm(&data6->task, sizeof(data6->task));
    if (v6_pending.update(&pid_tgid, call) != 0) {
        u32 stats_key = 0;
        struct ipv6_stats_t *stats = v6_stats.lookup(&stats_key);
        if (stats)
            __sync_fetch_and_add(&stats->store_failures, 1);
    }
    return 0;
}

int trace_udpv6_sendmsg_ret(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ipv6_call_t *call = v6_pending.lookup(&pid_tgid);
    if (!call)
        return 0;

    // Copy out of the LRU node, then confirm the key was still present via
    // delete() before submitting. LRU eviction unlinks the key before reusing
    // node storage, so a successful delete() guarantees the copied event was
    // not overwritten by another thread.
#ifdef ENABLE_DNS
    u32 zero = 0;
    struct ipv6_data_t *data6 = v6_ret_scratch.lookup(&zero);
    if (!data6)
        return 0;
    __builtin_memcpy(data6, &call->event, sizeof(*data6));
#else
    struct ipv6_data_t data6_stack;
    __builtin_memcpy(&data6_stack, &call->event, sizeof(data6_stack));
    struct ipv6_data_t *data6 = &data6_stack;
#endif
    if (v6_pending.delete(&pid_tgid) != 0) {
        u32 stats_key = 0;
        struct ipv6_stats_t *stats = v6_stats.lookup(&stats_key);
        if (stats)
            __sync_fetch_and_add(&stats->evicted, 1);
        return 0;
    }
    ipv6_events.perf_submit(ctx, data6, sizeof(*data6));
    return 0;
}
#endif
"""


def root_monotonic_us():
    # Align userspace CLOCK_MONOTONIC with bpf_ktime_get_ns() (root time
    # namespace) by removing any time-namespace monotonic offset.
    ts_us = int(monotonic() * 1000000)
    try:
        with open("/proc/self/timens_offsets") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3 and parts[0] == "monotonic":
                    ts_us -= int(parts[1]) * 1000000 + int(parts[2]) // 1000
                    break
    except OSError:
        pass
    return ts_us


def report_ipv6_stats(table, previous):
    current = table[0]
    store_failures = current.store_failures - previous.store_failures
    unreturned = current.unreturned - previous.unreturned
    evicted = current.evicted - previous.evicted
    if store_failures:
        print("WARNING: could not store %d pending IPv6 calls" % store_failures,
              file=sys.stderr)
    if unreturned:
        print("WARNING: discarded %d pending IPv6 calls without an observed return"
              % unreturned, file=sys.stderr)
    if evicted:
        print("WARNING: lost %d pending IPv6 calls due to LRU eviction"
              % evicted, file=sys.stderr)
    return current


def build_dns_defines(bpf_cls):
    defs = ["#define ENABLE_DNS 1"]
    has_iter_type = bpf_cls.kernel_struct_has_field(b"iov_iter", b"iter_type")
    has_ubuf = bpf_cls.kernel_struct_has_field(b"iov_iter", b"ubuf")
    has_dunder_iov = bpf_cls.kernel_struct_has_field(b"iov_iter", b"__iov")
    if has_iter_type >= 0 and has_ubuf >= 0 and has_dunder_iov >= 0:
        defs.append("#define IOV_ITER_BTF_AVAILABLE 1")
        if has_iter_type == 1:
            defs.append("#define IOV_ITER_HAS_ITER_TYPE 1")
        if has_ubuf == 1:
            defs.append("#define IOV_ITER_HAS_UBUF 1")
        if has_dunder_iov == 1:
            defs.append("#define IOV_ITER_IOV_FIELD __iov")
        else:
            defs.append("#define IOV_ITER_IOV_FIELD iov")
    return "\n".join(defs) + "\n"


def build_dport_filter(ports, expr):
    if not ports:
        return ""
    cond = " && ".join("%s != %d" % (expr, htons(p)) for p in ports)
    return "if (%s) { return 0; }" % cond


def main():
    examples = """examples:
    ./udpsend           # trace all UDP sendmsg()s
    ./udpsend -t        # include seconds since trace start
    ./udpsend -T        # include wall-clock time (HH:MM:SS)
    ./udpsend -P 53     # only trace destination port 53
    ./udpsend -P 53,5353 --dns  # decode DNS queries on destination ports 53 and 5353
"""
    parser = argparse.ArgumentParser(
        description="Trace UDP sends",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
    parser.add_argument("-T", "--time", action="store_true",
        help="include wall-clock time column when event is read (HH:MM:SS)")
    parser.add_argument("-t", "--timestamp", action="store_true",
        help="include seconds since trace start")
    parser.add_argument("-d", "--dns", action="store_true",
        help="decode DNS queries in UDP payloads")
    parser.add_argument("-P", "--port",
        help="comma-separated list of destination ports to trace")
    args = parser.parse_args()

    filter_ports = []
    if args.port is not None:
        try:
            filter_ports = parse_ports(args.port)
        except ValueError as err:
            parser.error("invalid -P/--port value: %s" % err)

    from bcc import BPF
    from bcc.utils import printb

    prog_text = bpf_text
    prog_text = prog_text.replace(
        "FILTER_DPORT_V4", build_dport_filter(filter_ports, "data4->dport"))
    prog_text = prog_text.replace(
        "FILTER_DPORT_V6", build_dport_filter(filter_ports, "data6->dport"))
    if args.dns:
        prog_text = build_dns_defines(BPF) + prog_text

    # Record trace start time before attaching probes so -t offsets are relative
    # to trace start and never negative across CPUs or perf buffers.
    start_ts = root_monotonic_us()

    def print_event(event, saddr, daddr):
        if args.time:
            printb(b"%-9s" % strftime("%H:%M:%S").encode("ascii"), nl="")
        if args.timestamp:
            delta_s = max(0.0, (float(event.ts_us) - start_ts) / 1000000)
            printb(b"%-9.3f" % delta_s, nl="")
        if args.dns:
            dns_text = None
            if event.dns_len > 0:
                payload = bytes(event.dns_payload[:event.dns_len])
                dns_text = parse_dns_query(payload, event.dns_msg_len)
            dns_bytes = dns_text.encode("ascii") if dns_text else b"-"
            printb(b"%-7d %-7d %-12.12s %-2d %-16s %-5d %-16s %-5d %s" % (
                event.pid, event.uid, event.task, event.ip, saddr, event.sport,
                daddr, ntohs(event.dport), dns_bytes))
        else:
            printb(b"%-7d %-7d %-12.12s %-2d %-16s %-5d %-16s %-5d" % (
                event.pid, event.uid, event.task, event.ip, saddr, event.sport,
                daddr, ntohs(event.dport)))

    def print_ipv4_event(cpu, data, size):
        event = b["ipv4_events"].event(data)
        print_event(event,
            inet_ntop(AF_INET, pack("I", event.saddr)).encode(),
            inet_ntop(AF_INET, pack("I", event.daddr)).encode())

    def print_ipv6_event(cpu, data, size):
        event = b["ipv6_events"].event(data)
        print_event(event,
            inet_ntop(AF_INET6, event.saddr).encode(),
            inet_ntop(AF_INET6, event.daddr).encode())

    # initialize BPF
    # kprobe__udp_sendmsg is auto-attached to udp_sendmsg (IPv4 path). The IPv6
    # path (udpv6_sendmsg) is optional. Install the return probe before the
    # entry probe so every stored call has an active return hook.
    b = BPF(text=prog_text)
    has_ipv6 = False
    kretprobe_attached = False
    maxactive = max(128, (os.cpu_count() or 1) * 4)
    try:
        try:
            b.attach_kretprobe(event="udpv6_sendmsg",
                               fn_name="trace_udpv6_sendmsg_ret",
                               maxactive=maxactive)
        except Exception:
            b.attach_kretprobe(event="udpv6_sendmsg",
                               fn_name="trace_udpv6_sendmsg_ret")
        kretprobe_attached = True
        b.attach_kprobe(event="udpv6_sendmsg", fn_name="trace_udpv6_sendmsg")
        has_ipv6 = True
    except Exception as error:
        if kretprobe_attached:
            try:
                b.detach_kretprobe("udpv6_sendmsg")
            except Exception:
                pass
        print("WARNING: could not attach IPv6 probes; tracing IPv4 only (%s)"
              % error, file=sys.stderr)

    # Open perf buffers before printing the header so callers waiting on the
    # header know event capture is fully ready.
    b["ipv4_events"].open_perf_buffer(print_ipv4_event)
    if has_ipv6:
        b["ipv6_events"].open_perf_buffer(print_ipv6_event)
        ipv6_stats = b["v6_stats"]
        previous_ipv6_stats = ipv6_stats.Leaf()
        next_ipv6_report = monotonic() + 5.0

    print("Tracing UDP sendmsg ... Hit Ctrl-C to end")

    if args.time:
        print("%-9s" % ("TIME"), end="")
    if args.timestamp:
        print("%-9s" % ("TIME(s)"), end="")
    # header
    if args.dns:
        print("%-7s %-7s %-12s %-2s %-16s %-5s %-16s %-5s %s" % ("PID", "UID",
            "COMM", "IP", "SADDR", "SPORT", "DADDR", "DPORT", "DNS"),
            flush=True)
    else:
        print("%-7s %-7s %-12s %-2s %-16s %-5s %-16s %-5s" % ("PID", "UID",
            "COMM", "IP", "SADDR", "SPORT", "DADDR", "DPORT"), flush=True)

    # read events
    try:
        while True:
            b.perf_buffer_poll(timeout=1000 if has_ipv6 else -1)
            if has_ipv6:
                now = monotonic()
                if now >= next_ipv6_report:
                    previous_ipv6_stats = report_ipv6_stats(
                        ipv6_stats, previous_ipv6_stats)
                    next_ipv6_report = now + 5.0
    except KeyboardInterrupt:
        if has_ipv6:
            report_ipv6_stats(ipv6_stats, previous_ipv6_stats)


if __name__ == "__main__":
    main()
