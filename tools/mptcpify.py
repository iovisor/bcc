#!/usr/bin/env python
#
# mptcpify Make the applications to use MPTCP.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: ./mptcpify
#        ./mptcpify -t curl,iperf3
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
parser.add_argument("-t", "--targets", type=str,
                    help="use ',' for multi targets, eg: 'iperf3,rsync'. "
                         "Without '-t', it can works on all applications by default.")

args_str = parser.parse_args()
if args_str.targets != None:
    mode = 1
    args_list = [t.strip() for t in args_str.targets.split(',')]
else:
    mode = 0

if (not BPF.support_fmod_ret()):
    print("Your kernel version is too old,"
          " fmod_ret method is only support kernel v5.7 and later.")
    exit()

TASK_COMM_LEN = 16

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

BPF_ARRAY(work_mode, int, 1);
BPF_HASH(support_apps, struct app_name);

KMOD_RET(update_socket_protocol, int family, int type, int protocol, int ret)
{
    struct app_name target = {};
    int index = 0;
    int *mode = work_mode.lookup(&index);
    bpf_get_current_comm(&target.name, TASK_COMM_LEN);

    if ((family == AF_INET || family == AF_INET6) &&
        type == SOCK_STREAM &&
        (!protocol || protocol == IPPROTO_TCP) &&
        (mode && *mode == 0 || support_apps.lookup(&target)))
        return IPPROTO_MPTCP;

    return protocol;

}

"""

b = BPF(text=prog)
b.attach_fmod_ret("update_socket_protocol")

work_mode = b["work_mode"]
support_apps = b.get_table("support_apps")
if mode:
    for i in args_list:
        app = i.encode()
        name = app_name()
        name.str = app[:TASK_COMM_LEN-1].ljust(TASK_COMM_LEN, b'\0')
        support_apps[name] = ct.c_uint32(1)

work_mode[ct.c_int(0)] = ct.c_int(mode)

print("MPTCP is been forced for ", args_list if mode == 1 else "all applications");
signal.pause()
