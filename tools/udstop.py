#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# udstop    Summarize UDS send/recv throughput by host.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: udstop [-h] [-S] [-s] [-D] [-C] [-T] [-p PID] [interval [count]]
#
# Copyright (c) Ping Gan.
# 29-Jan-2023   Ping Gan   Created this.

from __future__ import print_function
from bcc import BPF
from bcc.containers import filter_by_containers
import argparse
from struct import pack
from time import sleep, strftime
from subprocess import call
from collections import namedtuple, defaultdict

# arguments
def range_check(string):
    value = int(string)
    if value < 1:
        msg = "value must be stricly positive, got %d" % (value,)
        raise argparse.ArgumentTypeError(msg)
    return value

examples = """examples:
    ./udstop               # trace UDS send/recv by host
    ./udstop -C            # don't clear the screen
    ./udstop -S            # only trace stream uds socket
    ./udstop -s            # only trace sequence uds socket
    ./udstop -D            # only trace dgram uds socket
    ./udstop -p 181        # only trace PID 181
    ./udstop -T 1          # trace and add timestamp
"""
parser = argparse.ArgumentParser(
    description="Summarize UDS send/recv throughput by host",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-C", "--noclear", action="store_true",
    help="don't clear the screen")
parser.add_argument("-S", "--streamonly", action="store_true",
    help="only trace stream uds socket")
parser.add_argument("-s", "--sequenceonly", action="store_true",
    help="only trace sequence uds socket")
parser.add_argument("-D", "--dgramonly", action="store_true",
    help="only trace dgram uds socket")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("interval", nargs="?", default=1, type=range_check,
    help="output interval, in seconds (default 1)")
parser.add_argument("count", nargs="?", default=-1, type=range_check,
    help="number of outputs")
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
countdown = int(args.count)
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/un.h>
#include <linux/fs.h>
#include <linux/pid.h>
#include <linux/net.h>
#include <net/sock.h>
#include <net/af_unix.h>
#include <bcc/proto.h>

#define bpf_prog_offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

#define bpf_prog_container_of(ptr, type, member) ({			\
        const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
        (type *)( (char *)__mptr - bpf_prog_offsetof(type,member) );})

enum {
    RX_DIR = 0,
    TX_DIR,
};

typedef struct uds_key_s {
    u32  pid;
    char name[TASK_COMM_LEN];
    u64  local_sock_ino;
    u64  peer_sock_ino;
    char sun_path[UNIX_PATH_MAX];
}uds_key_t;

typedef struct uds_val_s {
    u64  tx_bytes;
    u64  rx_bytes;
}uds_val_t;

typedef struct uds_params {
    struct socket *skt;
    u64 local_sock_ino;
}uds_params_t;

typedef struct sock_params {
    struct socket skt;
    struct unix_sock usock;
    struct sock peer_sk;
    struct unix_address uaddr;
    struct sockaddr_un sunaddr;
}sock_params_t;

BPF_HASH(uds_xmit_bytes, uds_key_t, uds_val_t);
BPF_HASH(params_store, u64, uds_params_t);
BPF_PERCPU_ARRAY(sock_param, sock_params_t, 1);

static int uds_stat(int size, int direct)
{
    u64 key = bpf_get_current_pid_tgid();
    u32 pid = key >> 32;
    u32 sockp_key = 0;
    int len = 0;
    struct inode *inode;
    struct socket *sk_socket;
    uds_key_t uds_key = {0};
    uds_val_t *uvalp, uval = {0};

    FILTER_PID
    uds_params_t *uds_param = params_store.lookup(&key);
    if (uds_param == 0) {
        return 0; //miss the entry
    }

    sock_params_t *sk_params = sock_param.lookup(&sockp_key);
    if (!sk_params) {
        return 0; //miss the entry
    }

    bpf_probe_read_kernel(&(sk_params->skt), sizeof(struct socket),
        uds_param->skt);
    bpf_probe_read_kernel(&(sk_params->usock), sizeof(struct unix_sock),
        sk_params->skt.sk);
    bpf_probe_read_kernel(&(sk_params->peer_sk), sizeof(struct sock),
        sk_params->usock.peer);
    if (sk_params->usock.addr) {
        bpf_probe_read_kernel(&(sk_params->uaddr),
            sizeof(struct unix_address), sk_params->usock.addr);
        len = sk_params->uaddr.len - sizeof(short);
        if (len > 0 ) {
            bpf_probe_read_kernel(&(sk_params->sunaddr),
                sizeof(struct sockaddr_un),
                (struct sockaddr_un *)&(sk_params->usock.addr[1]));
            bpf_probe_read_kernel(uds_key.sun_path, sizeof(uds_key.sun_path),
                sk_params->sunaddr.sun_path);
        }
    }
    sk_socket = sk_params->peer_sk.sk_socket;
    inode = &bpf_prog_container_of(sk_socket,
                struct socket_alloc, socket)->vfs_inode;
    bpf_probe_read_kernel(&uds_key.peer_sock_ino,
        sizeof(uds_key.peer_sock_ino), &inode->i_ino);
    uds_key.pid = pid;
    bpf_get_current_comm(&uds_key.name, sizeof(uds_key.name));
    uds_key.local_sock_ino = uds_param->local_sock_ino;

    uvalp = uds_xmit_bytes.lookup(&uds_key);
    if (uvalp == 0) {
        if (direct == RX_DIR) {
            uval.rx_bytes = size;
        } else {
            uval.tx_bytes = size;
        }
        uds_xmit_bytes.update(&uds_key, &uval);
    } else {
        if (direct == RX_DIR) {
            uvalp->rx_bytes += size;
        } else {
            uvalp->tx_bytes += size;
        }
    }
    params_store.delete(&key);
    return 0;
}

static int uds_entry(struct socket *socket)
{
    u64 key = bpf_get_current_pid_tgid();
    u32 pid = key >> 32;
    uds_params_t udsparam = {0};
    struct inode *inode;

    FILTER_PID
    udsparam.skt = socket;
    inode = &bpf_prog_container_of(socket,
        struct socket_alloc, socket)->vfs_inode;
    bpf_probe_read_kernel(&(udsparam.local_sock_ino),
        sizeof(udsparam.local_sock_ino), &inode->i_ino);
    params_store.update(&key, &udsparam);
    return 0;
}
"""

bpf_stream_text = """
int kprobe__unix_stream_sendmsg(struct pt_regs *ctx, struct socket *sock,
    struct msghdr *msg, size_t size)
{
    return uds_entry(sock);
}

int kretprobe__unix_stream_sendmsg(struct pt_regs *ctx)
{
    int size = PT_REGS_RC(ctx);

    if (size > 0)
        return uds_stat(size, TX_DIR);
    else
        return 0;
}

int kprobe__unix_stream_sendpage(struct pt_regs *ctx, struct socket *socket,
    struct page *page, int offset, size_t size)
{
    return uds_entry(socket);
}

int kretprobe__unix_stream_sendpage(struct pt_regs *ctx)
{
    int size = PT_REGS_RC(ctx);

    if (size > 0)
        return uds_stat(size, TX_DIR);
    else
        return 0;
}

int kprobe__unix_stream_recvmsg(struct pt_regs *ctx, struct socket *sock,
    struct msghdr *msg, size_t size)
{
    return uds_entry(sock);
}

int kretprobe__unix_stream_recvmsg(struct pt_regs *ctx)
{
    int size = PT_REGS_RC(ctx);

    if (size > 0)
        return uds_stat(size, RX_DIR);
    else
        return 0;
}
"""

bpf_dgram_text = """
int kprobe__unix_dgram_sendmsg(struct pt_regs *ctx, struct socket *sock,
    struct msghdr *msg, size_t len)
{
    return uds_entry(sock);
}

int kretprobe__unix_dgram_sendmsg(struct pt_regs *ctx)
{
    int size = PT_REGS_RC(ctx);

    if (size > 0)
        return uds_stat(size, TX_DIR);
    else
        return 0;
}

int kprobe__unix_dgram_recvmsg(struct pt_regs *ctx, struct socket *sock,
    struct msghdr *msg, size_t size)
{
    return uds_entry(sock);
}

int kretprobe__unix_dgram_recvmsg(struct pt_regs *ctx)
{
    int size = PT_REGS_RC(ctx);

    if (size > 0)
        return uds_stat(size, RX_DIR);
    else
        return 0;
}
"""

bpf_seq_text = """
int kprobe__unix_seqpacket_sendmsg(struct pt_regs *ctx, struct socket *sock,
    struct msghdr *msg, size_t len)
{
    return uds_entry(sock);
}

int kretprobe__unix_seqpacket_sendmsg(struct pt_regs *ctx)
{
    int size = PT_REGS_RC(ctx);

    if (size > 0)
        return uds_stat(size, TX_DIR);
    else
        return 0;
}

int kprobe__unix_seqpacket_recvmsg(struct pt_regs *ctx, struct socket *sock,
    struct msghdr *msg, size_t size)
{
    return uds_entry(sock);
}

int kretprobe__unix_seqpacket_recvmsg(struct pt_regs *ctx)
{
    int size = PT_REGS_RC(ctx);

    if (size > 0)
        return uds_stat(size, RX_DIR);
    else
        return 0;
}
"""

# code substitutions
if args.streamonly or args.dgramonly or args.sequenceonly:
    if args.streamonly:
        bpf_text += bpf_stream_text
    if args.dgramonly:
        bpf_text += bpf_dgram_text
    if args.sequenceonly:
        bpf_text += bpf_seq_text
else:
    bpf_text += bpf_stream_text
    bpf_text += bpf_dgram_text
    bpf_text += bpf_seq_text

if args.pid:
    bpf_text = bpf_text.replace('FILTER_PID',
        'if (pid != %s) { return 0; }' % (args.pid))
else:
    bpf_text = bpf_text.replace('FILTER_PID', '')

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF
b = BPF(text=bpf_text)
uds_xmit_bytes = b["uds_xmit_bytes"]
print('Tracing... Output every %s secs. Hit Ctrl-C to end' % args.interval)

# output
exiting = 0 if args.interval else 1

while (1):
    try:
        sleep(int(args.interval))
    except KeyboardInterrupt:
        exiting = 1
    # header
    if args.noclear:
        print()
    else:
        call("clear")
    if args.timestamp:
        print("%-8s\n" % strftime("%H:%M:%S"), end="")

    print("%-7s %-16s %-12s %-12s %-7s %-7s %s"
          % ("PID", "COMM", "INO", "PEERINO", "RX_KB", "TX_KB", "SUN_PATH"))
    for k, v in sorted(uds_xmit_bytes.items(),
      key=lambda uds_xmit_bytes: uds_xmit_bytes[1].rx_bytes, reverse=True):
        print("%-7d %-16s %-12d %-12d %-7d %-7d %s"
              % (k.pid, k.name.decode('utf-8', 'replace'), k.local_sock_ino,
                 k.peer_sock_ino, v.rx_bytes / 1024, v.tx_bytes / 1024,
                 k.sun_path.decode('utf-8', 'replace')))
    countdown -= 1
    if exiting or countdown == 0:
        exit()
    uds_xmit_bytes.clear()
