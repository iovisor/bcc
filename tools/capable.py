#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# capable   Trace security capabilitiy checks (cap_capable()).
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: capable [-h] [-v] [-p PID] [-K] [-U]
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 13-Sep-2016   Brendan Gregg   Created this.

from __future__ import print_function
from os import getpid
from functools import partial
from bcc import BPF
from bcc.containers import filter_by_containers
import errno
import argparse
from time import strftime

# arguments
examples = """examples:
    ./capable             # trace capability checks
    ./capable -v          # verbose: include non-audit checks
    ./capable -p 181      # only trace PID 181
    ./capable -K          # add kernel stacks to trace
    ./capable -U          # add user-space stacks to trace
    ./capable -x          # extra fields: show TID and INSETID columns
    ./capable --unique    # don't repeat stacks for the same pid or cgroup
    ./capable --cgroupmap mappath  # only trace cgroups in this BPF map
    ./capable --mntnsmap mappath   # only trace mount namespaces in the map
"""
parser = argparse.ArgumentParser(
    description="Trace security capability checks",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-v", "--verbose", action="store_true",
    help="include non-audit checks")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("-K", "--kernel-stack", action="store_true",
    help="output kernel stack trace")
parser.add_argument("-U", "--user-stack", action="store_true",
    help="output user stack trace")
parser.add_argument("-x", "--extra", action="store_true",
    help="show extra fields in TID and INSETID columns")
parser.add_argument("--cgroupmap",
    help="trace cgroups in this BPF map only")
parser.add_argument("--mntnsmap",
    help="trace mount namespaces in this BPF map only")
parser.add_argument("--unique", action="store_true",
    help="don't repeat stacks for the same pid or cgroup")
args = parser.parse_args()
debug = 0

# capabilities to names, generated from (and will need updating):
# awk '/^#define.CAP_.*[0-9]$/ { print "    " $3 ": \"" $2 "\"," }' \
#     include/uapi/linux/capability.h
capabilities = {
    0: "CAP_CHOWN",
    1: "CAP_DAC_OVERRIDE",
    2: "CAP_DAC_READ_SEARCH",
    3: "CAP_FOWNER",
    4: "CAP_FSETID",
    5: "CAP_KILL",
    6: "CAP_SETGID",
    7: "CAP_SETUID",
    8: "CAP_SETPCAP",
    9: "CAP_LINUX_IMMUTABLE",
    10: "CAP_NET_BIND_SERVICE",
    11: "CAP_NET_BROADCAST",
    12: "CAP_NET_ADMIN",
    13: "CAP_NET_RAW",
    14: "CAP_IPC_LOCK",
    15: "CAP_IPC_OWNER",
    16: "CAP_SYS_MODULE",
    17: "CAP_SYS_RAWIO",
    18: "CAP_SYS_CHROOT",
    19: "CAP_SYS_PTRACE",
    20: "CAP_SYS_PACCT",
    21: "CAP_SYS_ADMIN",
    22: "CAP_SYS_BOOT",
    23: "CAP_SYS_NICE",
    24: "CAP_SYS_RESOURCE",
    25: "CAP_SYS_TIME",
    26: "CAP_SYS_TTY_CONFIG",
    27: "CAP_MKNOD",
    28: "CAP_LEASE",
    29: "CAP_AUDIT_WRITE",
    30: "CAP_AUDIT_CONTROL",
    31: "CAP_SETFCAP",
    32: "CAP_MAC_OVERRIDE",
    33: "CAP_MAC_ADMIN",
    34: "CAP_SYSLOG",
    35: "CAP_WAKE_ALARM",
    36: "CAP_BLOCK_SUSPEND",
    37: "CAP_AUDIT_READ",
    38: "CAP_PERFMON",
    39: "CAP_BPF",
    40: "CAP_CHECKPOINT_RESTORE",
}

class Enum(set):
    def __getattr__(self, name):
        if name in self:
            return name
        raise AttributeError

# Stack trace types
StackType = Enum(("Kernel", "User",))

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/security.h>

struct data_t {
   u32 tgid;
   u32 pid;
   u32 uid;
   int cap;
   int audit;
   int insetid;
   char comm[TASK_COMM_LEN];
#ifdef KERNEL_STACKS
   int kernel_stack_id;
#endif
#ifdef USER_STACKS
   int user_stack_id;
#endif
};

BPF_PERF_OUTPUT(events);

#if UNIQUESET
struct repeat_t {
   int cap;
   u32 tgid;
#if CGROUPSET
   u64 cgroupid;
#endif
#ifdef KERNEL_STACKS
   int kernel_stack_id;
#endif
#ifdef USER_STACKS
   int user_stack_id;
#endif
};
BPF_HASH(seen, struct repeat_t, u64);
#endif

#if defined(USER_STACKS) || defined(KERNEL_STACKS)
BPF_STACK_TRACE(stacks, 2048);
#endif

int kprobe__cap_capable(struct pt_regs *ctx, const struct cred *cred,
    struct user_namespace *targ_ns, int cap, int cap_opt)
{
    u64 __pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = __pid_tgid >> 32;
    u32 pid = __pid_tgid;
    int audit;
    int insetid;

  #ifdef CAP_OPT_NONE
    audit = (cap_opt & 0b10) == 0;
    insetid = (cap_opt & 0b100) != 0;
  #else
    audit = cap_opt;
    insetid = -1;
  #endif

    FILTER1
    FILTER2
    FILTER3

    if (container_should_be_filtered()) {
        return 0;
    }

    u32 uid = bpf_get_current_uid_gid();
    struct data_t data = {.tgid = tgid, .pid = pid, .uid = uid, .cap = cap, .audit = audit, .insetid = insetid};
#ifdef KERNEL_STACKS
    data.kernel_stack_id = stacks.get_stackid(ctx, 0);
#endif
#ifdef USER_STACKS
    data.user_stack_id = stacks.get_stackid(ctx, BPF_F_USER_STACK);
#endif

#if UNIQUESET
    struct repeat_t repeat = {0,};
    repeat.cap = cap;
#if CGROUP_ID_SET
    repeat.cgroupid = bpf_get_current_cgroup_id();
#else
    repeat.tgid = tgid;
#endif
#ifdef KERNEL_STACKS
    repeat.kernel_stack_id = data.kernel_stack_id;
#endif
#ifdef USER_STACKS
    repeat.user_stack_id = data.user_stack_id;
#endif
    if (seen.lookup(&repeat) != NULL) {
        return 0;
    }
    u64 zero = 0;
    seen.update(&repeat, &zero);
#endif

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
};
"""
if args.pid:
    bpf_text = bpf_text.replace('FILTER1',
        'if (pid != %s) { return 0; }' % args.pid)
if not args.verbose:
    bpf_text = bpf_text.replace('FILTER2', 'if (audit == 0) { return 0; }')
if args.kernel_stack:
    bpf_text = "#define KERNEL_STACKS\n" + bpf_text
if args.user_stack:
    bpf_text = "#define USER_STACKS\n" + bpf_text
bpf_text = bpf_text.replace('FILTER1', '')
bpf_text = bpf_text.replace('FILTER2', '')
bpf_text = bpf_text.replace('FILTER3',
    'if (pid == %s) { return 0; }' % getpid())
bpf_text = filter_by_containers(args) + bpf_text
if args.unique:
    bpf_text = bpf_text.replace('UNIQUESET', '1')
else:
    bpf_text = bpf_text.replace('UNIQUESET', '0')
if debug:
    print(bpf_text)

# initialize BPF
b = BPF(text=bpf_text)

# header
if args.extra:
    print("%-9s %-6s %-6s %-6s %-16s %-4s %-20s %-6s %s" % (
        "TIME", "UID", "PID", "TID", "COMM", "CAP", "NAME", "AUDIT", "INSETID"))
else:
    print("%-9s %-6s %-6s %-16s %-4s %-20s %-6s" % (
        "TIME", "UID", "PID", "COMM", "CAP", "NAME", "AUDIT"))

def stack_id_err(stack_id):
    # -EFAULT in get_stackid normally means the stack-trace is not available,
    # Such as getting kernel stack trace in userspace code
    return (stack_id < 0) and (stack_id != -errno.EFAULT)

def print_stack(bpf, stack_id, stack_type, tgid):
    if stack_id_err(stack_id):
        print("    [Missed %s Stack]" % stack_type)
        return
    stack = list(bpf.get_table("stacks").walk(stack_id))
    for addr in stack:
        print("        ", end="")
        print("%s" % (bpf.sym(addr, tgid, show_module=True, show_offset=True)))

# process event
def print_event(bpf, cpu, data, size):
    event = b["events"].event(data)

    if event.cap in capabilities:
        name = capabilities[event.cap]
    else:
        name = "?"
    if args.extra:
        print("%-9s %-6d %-6d %-6d %-16s %-4d %-20s %-6d %s" % (strftime("%H:%M:%S"),
            event.uid, event.pid, event.tgid, event.comm.decode('utf-8', 'replace'),
            event.cap, name, event.audit, str(event.insetid) if event.insetid != -1 else "N/A"))
    else:
        print("%-9s %-6d %-6d %-16s %-4d %-20s %-6d" % (strftime("%H:%M:%S"),
            event.uid, event.pid, event.comm.decode('utf-8', 'replace'),
            event.cap, name, event.audit))
    if args.kernel_stack:
        print_stack(bpf, event.kernel_stack_id, StackType.Kernel, -1)
    if args.user_stack:
        print_stack(bpf, event.user_stack_id, StackType.User, event.tgid)

# loop with callback to print_event
callback = partial(print_event, b)
b["events"].open_perf_buffer(callback)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
