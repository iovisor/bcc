#!/usr/bin/env python
#
# kvmexit.py
#
# Display the exit_reason and its statistics of each vm exit
# for all vcpus of all virtual machines. For example:
# $./kvmexit.py
#  PID      TID      KVM_EXIT_REASON                     COUNT
#  1273551  1273568  EXIT_REASON_MSR_WRITE               6
#  1274253  1274261  EXIT_REASON_EXTERNAL_INTERRUPT      1
#  1274253  1274261  EXIT_REASON_HLT                     12
#  ...
#
# Besides, we also allow users to specify one pid, tid(s), or one
# pid and its vcpu. See kvmexit_example.txt for more examples.
#
# @PID: each vitual machine's pid in the user space.
# @TID: the user space's thread of each vcpu of that virtual machine.
# @KVM_EXIT_REASON: the reason why the vm exits.
# @COUNT: the counts of the @KVM_EXIT_REASONS.
#
# REQUIRES: Linux 4.7+ (BPF_PROG_TYPE_TRACEPOINT support)
#
# Copyright (c) 2021 ByteDance Inc. All rights reserved.
#
# 31-Aug-2021  Fei Li <lifei.shirley@bytedance.com>  Initial implementation.
# 28-Jul-2025  Matt Pelland <mpelland@akamai.com>    Implement support for AMD.
# 28-Jul-2025  Matt Pelland <mpelland@akamai.com>    Parallelize postprocessing.
# 28-Jul-2025  Matt Pelland <mpelland@akamai.com>    Silence compiler warnings.

from __future__ import print_function
from time import sleep
from bcc import BPF
import argparse
import multiprocessing
import os
import subprocess

#
# Process Arguments
#
def valid_args_list(args):
    args_list = args.split(",")
    for arg in args_list:
        try:
            int(arg)
        except:
            raise argparse.ArgumentTypeError("must be valid integer")
    return args_list

# arguments
examples = """examples:
    ./kvmexit                              # Display kvm_exit_reason and its statistics in real-time until Ctrl-C
    ./kvmexit 5                            # Display in real-time after sleeping 5s
    ./kvmexit -p 3195281                   # Collpase all tids for pid 3195281 with exit reasons sorted in descending order
    ./kvmexit -p 3195281 20                # Collpase all tids for pid 3195281 with exit reasons sorted in descending order, and display after sleeping 20s
    ./kvmexit -p 3195281 -v 0              # Display only vcpu0 for pid 3195281, descending sort by default
    ./kvmexit -p 3195281 -a                # Display all tids for pid 3195281
    ./kvmexit -p 3195281 -a -m 2           # Display all tids for pid 3195281, limit post processing to two threads
    ./kvmexit -t 395490                    # Display only for tid 395490 with exit reasons sorted in descending order
    ./kvmexit -t 395490 20                 # Display only for tid 395490 with exit reasons sorted in descending order after sleeping 20s
    ./kvmexit -T '395490,395491'           # Display for a union like {395490, 395491}
"""
parser = argparse.ArgumentParser(
    description="Display kvm_exit_reason and its statistics at a timed interval",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("duration", nargs="?", default=99999999, type=int, help="show delta for next several seconds")
parser.add_argument("-p", "--pid", type=int, help="trace this PID only")
exgroup = parser.add_mutually_exclusive_group()
exgroup.add_argument("-t", "--tid", type=int, help="trace this TID only")
exgroup.add_argument("-T", "--tids", type=valid_args_list, help="trace a comma separated series of tids with no space in between")
exgroup.add_argument("-v", "--vcpu", type=int, help="trace this vcpu only")
exgroup.add_argument("-a", "--alltids", action="store_true", help="trace all tids for this pid")
parser.add_argument("-m", "--max-parallelism", type=int, help="limit post processing parallelism to the given thread count", default=64)
parser.add_argument("-d", "--debug", action="store_true", help="enable debug facilities")
args = parser.parse_args()
duration = int(args.duration)

#
# Setup BPF
#

# load BPF program
bpf_text = """
#include <linux/delay.h>

#define TGID_NUM 1024

struct exit_count {
    u64 exit_ct[REASON_NUM];
};
BPF_PERCPU_ARRAY(init_value, struct exit_count, 1);
BPF_TABLE("percpu_hash", u64, struct exit_count, pcpu_kvm_stat, TGID_NUM);

struct cache_info {
    u64 cache_pid_tgid;
    struct exit_count cache_exit_ct;
};
BPF_PERCPU_ARRAY(pcpu_cache, struct cache_info, 1);

TRACEPOINT_PROBE(kvm, kvm_exit) {
    int cache_miss = 0;
    int zero = 0;
    u32 er = args->exit_reason;
    if (er >= REASON_NUM) {
        return 0;
    }

    u64 cur_pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = cur_pid_tgid >> 32;
    u32 pid = cur_pid_tgid;

    if (THREAD_FILTER)
        return 0;

    struct exit_count *tmp_info = NULL, *initial = NULL;
    struct cache_info *cache_p;
    cache_p = pcpu_cache.lookup(&zero);
    if (cache_p == NULL) {
        return 0;
    }

    if (cache_p->cache_pid_tgid == cur_pid_tgid) {
        //a. If the cur_pid_tgid hit this physical cpu consecutively, save it to pcpu_cache
        tmp_info = &cache_p->cache_exit_ct;
    } else {
        //b. If another pid_tgid matches this pcpu for the last hit, OR it is the first time to hit this physical cpu.
        cache_miss = 1;

        // b.a Try to load the last cache struct if exists.
        tmp_info = pcpu_kvm_stat.lookup(&cur_pid_tgid);

        // b.b If it is the first time for the cur_pid_tgid to hit this pcpu, employ a
        // per_cpu array to initialize pcpu_kvm_stat's exit_count with each exit reason's count is zero
        if (tmp_info == NULL) {
            initial = init_value.lookup(&zero);
            if (initial == NULL) {
                return 0;
            }

            pcpu_kvm_stat.update(&cur_pid_tgid, initial);
            tmp_info = pcpu_kvm_stat.lookup(&cur_pid_tgid);
            // To pass the verifier
            if (tmp_info == NULL) {
                return 0;
            }
        }
    }

    if (er < REASON_NUM) {
        tmp_info->exit_ct[er]++;
        if (cache_miss == 1) {
            if (cache_p->cache_pid_tgid != 0) {
                // b.*.a Let's save the last hit cache_info into kvm_stat.
                pcpu_kvm_stat.update(&cache_p->cache_pid_tgid, &cache_p->cache_exit_ct);
            }
            // b.* As the cur_pid_tgid meets current pcpu_cache_array for the first time, save it.
            cache_p->cache_pid_tgid = cur_pid_tgid;
            bpf_probe_read(&cache_p->cache_exit_ct, sizeof(*tmp_info), tmp_info);
        }
        return 0;
    }

    return 0;
}
"""

# Defines Intel (VMX) VM exit reason codes. Keep this in sync with
# arch/x86/include/uapi/asm/vmx.h.
VMX_EXIT_REASONS = {
    0: "EXCEPTION_NMI",
    1: "EXTERNAL_INTERRUPT",
    2: "TRIPLE_FAULT",
    3: "INIT_SIGNAL",
    4: "SIPI_SIGNAL",
    6: "OTHER_SMI",
    7: "INTERRUPT_WINDOW",
    8: "NMI_WINDOW",
    9: "TASK_SWITCH",
    10: "CPUID",
    12: "HLT",
    13: "INVD",
    14: "INVLPG",
    15: "RDPMC",
    16: "RDTSC",
    18: "VMCALL",
    19: "VMCLEAR",
    20: "VMLAUNCH",
    21: "VMPTRLD",
    22: "VMPTRST",
    23: "VMREAD",
    24: "VMRESUME",
    25: "VMWRITE",
    26: "VMOFF",
    27: "VMON",
    28: "CR_ACCESS",
    29: "DR_ACCESS",
    30: "IO_INSTRUCTION",
    31: "MSR_READ",
    32: "MSR_WRITE",
    33: "INVALID_STATE",
    34: "MSR_LOAD_FAIL",
    36: "MWAIT_INSTRUCTION",
    37: "MONITOR_TRAP_FLAG",
    39: "MONITOR_INSTRUCTION",
    40: "PAUSE_INSTRUCTION",
    41: "MCE_DURING_VMENTRY",
    43: "TPR_BELOW_THRESHOLD",
    44: "APIC_ACCESS",
    45: "EOI_INDUCED",
    46: "GDTR_IDTR",
    47: "LDTR_TR",
    48: "EPT_VIOLATION",
    49: "EPT_MISCONFIG",
    50: "INVEPT",
    51: "RDTSCP",
    52: "PREEMPTION_TIMER",
    53: "INVVPID",
    54: "WBINVD",
    55: "XSETBV",
    56: "APIC_WRITE",
    57: "RDRAND",
    58: "INVPCID",
    59: "VMFUNC",
    60: "ENCLS",
    61: "RDSEED",
    62: "PML_FULL",
    63: "XSAVES",
    64: "XRSTORS",
    67: "UMWAIT",
    68: "TPAUSE",
    74: "BUS_LOCK",
    75: "NOTIFY",
    76: "TDCALL"
}

# Defines AMD (SVM) VM exit reason codes. Keep this in sync with
# arch/x86/include/uapi/asm/svm.h.
SVM_EXIT_REASONS = {
    0x0: "READ_CR0",
    0x2: "READ_CR2",
    0x3: "READ_CR3",
    0x4: "READ_CR4",
    0x8: "READ_CR8",
    0x10: "WRITE_CR0",
    0x12: "WRITE_CR2",
    0x13: "WRITE_CR3",
    0x14: "WRITE_CR4",
    0x18: "WRITE_CR8",
    0x20: "READ_DR0",
    0x21: "READ_DR1",
    0x22: "READ_DR2",
    0x23: "READ_DR3",
    0x24: "READ_DR4",
    0x25: "READ_DR5",
    0x26: "READ_DR6",
    0x27: "READ_DR7",
    0x30: "WRITE_DR0",
    0x31: "WRITE_DR1",
    0x32: "WRITE_DR2",
    0x33: "WRITE_DR3",
    0x34: "WRITE_DR4",
    0x35: "WRITE_DR5",
    0x36: "WRITE_DR6",
    0x37: "WRITE_DR7",
    0x40: "EXCP_BASE",
    0x5f: "LAST_EXCP",
    0x60: "INTR",
    0x61: "NMI",
    0x62: "SMI",
    0x63: "INIT",
    0x64: "VINTR",
    0x65: "CR0_SEL_WRITE",
    0x66: "IDTR_READ",
    0x67: "GDTR_READ",
    0x68: "LDTR_READ",
    0x69: "TR_READ",
    0x6a: "IDTR_WRITE",
    0x6b: "GDTR_WRITE",
    0x6c: "LDTR_WRITE",
    0x6d: "TR_WRITE",
    0x6e: "RDTSC",
    0x6f: "RDPMC",
    0x70: "PUSHF",
    0x71: "POPF",
    0x72: "CPUID",
    0x73: "RSM",
    0x74: "IRET",
    0x75: "SWINT",
    0x76: "INVD",
    0x77: "PAUSE",
    0x78: "HLT",
    0x79: "INVLPG",
    0x7a: "INVLPGA",
    0x7b: "IOIO",
    0x7c: "MSR",
    0x7d: "TASK_SWITCH",
    0x7e: "FERR_FREEZE",
    0x7f: "SHUTDOWN",
    0x80: "VMRUN",
    0x81: "VMMCALL",
    0x82: "VMLOAD",
    0x83: "VMSAVE",
    0x84: "STGI",
    0x85: "CLGI",
    0x86: "SKINIT",
    0x87: "RDTSCP",
    0x88: "ICEBP",
    0x89: "WBINVD",
    0x8a: "MONITOR",
    0x8b: "MWAIT",
    0x8c: "MWAIT_COND",
    0x8d: "XSETBV",
    0x8e: "RDPRU",
    0x8f: "EFER_WRITE_TRAP",
    0x90: "CR0_WRITE_TRAP",
    0x91: "CR1_WRITE_TRAP",
    0x92: "CR2_WRITE_TRAP",
    0x93: "CR3_WRITE_TRAP",
    0x94: "CR4_WRITE_TRAP",
    0x95: "CR5_WRITE_TRAP",
    0x96: "CR6_WRITE_TRAP",
    0x97: "CR7_WRITE_TRAP",
    0x98: "CR8_WRITE_TRAP",
    0x99: "CR9_WRITE_TRAP",
    0x9a: "CR10_WRITE_TRAP",
    0x9b: "CR11_WRITE_TRAP",
    0x9c: "CR12_WRITE_TRAP",
    0x9d: "CR13_WRITE_TRAP",
    0x9e: "CR14_WRITE_TRAP",
    0x9f: "CR15_WRITE_TRAP",
    0xa2: "INVPCID",
    0xa5: "BUS_LOCK",
    0xa6: "IDLE_HLT",
    0x400: "NPF",
    0x401: "AVIC_INCOMPLETE_IPI",
    0x402: "AVIC_UNACCELERATED_ACCESS",
    0x403: "VMGEXIT"
}

KVM_EXIT_REASONS_BY_VENDOR = {
    "GenuineIntel": VMX_EXIT_REASONS,
    "AuthenticAMD": SVM_EXIT_REASONS
}


# Do some checks
#
try:
    with open("/proc/cpuinfo", "r") as cpuinfo:
        for line in cpuinfo:
            if line.startswith("vendor_id"):
                cpu_vendor = line.split(":")[1].strip()
                break
    if cpu_vendor not in KVM_EXIT_REASONS_BY_VENDOR:
        raise Exception("CPU vendor not supported: %s" % cpu_vendor)

    # Check if kvm module is loaded
    if os.access("/dev/kvm", os.R_OK | os.W_OK):
        pass
    else:
        raise Exception("Please insmod kvm module to use kvmexit tool.")
except Exception as e:
    raise Exception("Failed to do precondition check, due to: %s." % e)

exit_reasons = KVM_EXIT_REASONS_BY_VENDOR[cpu_vendor]

def find_tid(tgt_dir, tgt_vcpu):
    for tid in os.listdir(tgt_dir):
        path = tgt_dir + "/" + tid + "/comm"
        fp = open(path, "r")
        comm = fp.read()
        if (comm.find(tgt_vcpu) != -1):
            return tid
    return -1

# set process/thread filter
thread_context = ""
header_format = ""
need_collapse = not args.alltids
if args.tid is not None:
    thread_context = "TID %s" % args.tid
    thread_filter = 'pid != %s' % args.tid
elif args.tids is not None:
    thread_context = "TIDS %s" % args.tids
    thread_filter = "pid != " + " && pid != ".join(args.tids)
    header_format = "TIDS     "
elif args.pid is not None:
    thread_context = "PID %s" % args.pid
    thread_filter = 'tgid != %s' % args.pid
    if args.vcpu is not None:
        thread_context = "PID %s VCPU %s" % (args.pid, args.vcpu)
        # transfer vcpu to tid
        tgt_dir = '/proc/' + str(args.pid) + '/task'
        tgt_vcpu = "CPU " + str(args.vcpu)
        args.tid = find_tid(tgt_dir, tgt_vcpu)
        if args.tid == -1:
            raise Exception("There's no v%s for PID %d." % (tgt_vcpu, args.pid))
        thread_filter = 'pid != %s' % args.tid
    elif args.alltids:
        thread_context = "PID %s and its all threads" % args.pid
        header_format = "TID      "
else:
    thread_context = "all threads"
    thread_filter = '0'
    header_format = "PID      TID      "
bpf_text = bpf_text.replace('THREAD_FILTER', thread_filter)
bpf_text = bpf_text.replace('REASON_NUM', str(max(exit_reasons.keys()) + 1))
cflags = []

if not args.debug:
    cflags.append("-w")

b = BPF(text=bpf_text, cflags=cflags)


# header
print("Display kvm exit reasons and statistics for %s" % thread_context, end="")
if duration < 99999999:
    print(" after sleeping %d secs." % duration)
else:
    print("... Hit Ctrl-C to end.")

try:
    sleep(duration)
except KeyboardInterrupt:
    print()


# Currently, sort multiple tids in descending order is not supported.
if (args.pid or args.tid):
    ct_reason = []
    if args.pid:
        tgid_exit = {k: 0 for k in exit_reasons}

# output
print("%s%-35s %s" % (header_format, "KVM_EXIT_REASON", "COUNT"))

pcpu_kvm_stat = b["pcpu_kvm_stat"]
pcpu_cache = b["pcpu_cache"]

def extract_pcpu_kvm_exit_reason_count(args):
    pid_tgid, exit_reason, cpu_num = args
    inner_cpu_cache = pcpu_cache[0][cpu_num]
    cachePIDTGID = inner_cpu_cache.cache_pid_tgid
    # Take priority to check if it is in cache

    if cachePIDTGID == pid_tgid.value:
        return inner_cpu_cache.cache_exit_ct.exit_ct[exit_reason]

    # If not in cache, find from kvm_stat
    return pcpu_kvm_stat[pid_tgid][cpu_num].exit_ct[exit_reason]

cpu_count = multiprocessing.cpu_count()
parallelism = min(max(1, int(cpu_count / 2)), args.max_parallelism)
pool = multiprocessing.Pool(parallelism)

for k, v in pcpu_kvm_stat.items():
    tgid = k.value >> 32
    pid = k.value & 0xffffffff
    for i in exit_reasons.keys():
        sum1 = sum(pool.map(
            extract_pcpu_kvm_exit_reason_count,
            [(k, i, c) for c in range(cpu_count)]
        ))

        if sum1 == 0:
            continue

        if (args.pid and args.pid == tgid and need_collapse):
            tgid_exit[i] += sum1
        elif (args.tid and args.tid == pid):
            ct_reason.append((sum1, i))
        elif not need_collapse or args.tids:
            print("%-8u %-35s %-8u" % (pid, exit_reasons[i], sum1))
        else:
            print("%-8u %-8u %-35s %-8u" % (tgid, pid, exit_reasons[i], sum1))

    # Display only for the target tid in descending sort
    if (args.tid and args.tid == pid):
        ct_reason.sort(reverse=True)
        for i in range(0, len(ct_reason)):
            if ct_reason[i][0] == 0:
                continue
            print("%-35s %-8u" % (exit_reasons[ct_reason[i][1]], ct_reason[i][0]))
        break


# Aggregate all tids' counts for this args.pid in descending sort
if args.pid and need_collapse:
    for k, v in tgid_exit.items():
        ct_reason.append((v, k))
    ct_reason.sort(reverse=True)
    for i in range(0, len(ct_reason)):
        if ct_reason[i][0] == 0:
            continue
        print("%-35s %-8u" % (exit_reasons[ct_reason[i][1]], ct_reason[i][0]))
