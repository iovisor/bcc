#!/usr/bin/env python
#
# mptcpify Make the applications to use MPTCP.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: mptcpify -t
#
# Copyright 2025 Kylin Software, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 05-Apr-2025   Gang Yan   Created this.

import ctypes as ct
import argparse
import signal
import time

from bcc import BPF

#arguments
parser = argparse.ArgumentParser(
         description="mptcpify try to force applications to use MPTCP instead of TCP")
parser.add_argument("-t", "--targets", required=True, type=str,
                    help="use ',' for multi targets, eg: 'iperf3,rsync'")

args_str = parser.parse_args()
args_list = [t.strip() for t in args_str.targets.split(',')]

if (not BPF.support_fmod_ret()):
    print("Your kernel version is too old,"
          " fmod_ret method is only support kernel v5.7 and later.")
    exit()

TASK_COMM_LEN = 18

class app_name(ct.Structure):
    _fields_ = [("str", ct.c_char * TASK_COMM_LEN)]

# define BPF program
prog = """
#include <linux/net.h>
#include <uapi/linux/in.h>
#include <linux/string.h>

struct app_name {
    char name[TASK_COMM_LEN];
};

BPF_HASH(support_apps, struct app_name);

KMOD_RET(update_socket_protocol, int family, int type, int protocol, int ret)
{
    struct app_name target = {};
    bpf_get_current_comm(&target.name, TASK_COMM_LEN);

    if ((family == AF_INET || family == AF_INET6) &&
        type == SOCK_STREAM &&
        (!protocol || protocol == IPPROTO_TCP) &&
        support_apps.lookup(&target))
        return IPPROTO_MPTCP;

    return protocol;

}

"""

b = BPF(text=prog)
b.attach_fmod_ret("update_socket_protocol")

support_apps = b.get_table("support_apps")
for i in args_list:
    app = i.encode()
    name = app_name()
    name.str = app[:TASK_COMM_LEN-1].ljust(TASK_COMM_LEN, b'\0')
    support_apps[name] = ct.c_uint32(1)

print("MPTCP is been forced for ", args_list);
signal.pause()
