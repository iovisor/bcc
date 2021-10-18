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
# Author(s):
#   Fei Li <lifei.shirley@bytedance.com>


from __future__ import print_function
from time import sleep
from bcc import BPF
import argparse
import multiprocessing
import os
import subprocess
import re

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
args = parser.parse_args()
duration = int(args.duration)

#
# Setup BPF
#

# load BPF program
bpf_text = """
#include <linux/delay.h>

REASON_NUM_L
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

FUNC_ENTRY {
    int cache_miss = 0;
    int zero = 0;
    u32 er = GET_ER;
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

# format setting, hard code in case of no header files
exit_reasons_Intel = (
    "EXCEPTION_NMI 0",
    "EXTERNAL_INTERRUPT 1",
    "TRIPLE_FAULT 2",
    "INIT_SIGNAL 3",
    "INTERRUPT_WINDOW 7",
    "NMI_WINDOW 8",
    "TASK_SWITCH 9",
    "CPUID 10",
    "HLT 12",
    "INVD 13",
    "INVLPG 14",
    "RDPMC 15",
    "RDTSC 16",
    "VMCALL 18",
    "VMCLEAR 19",
    "VMLAUNCH 20",
    "VMPTRLD 21",
    "VMPTRST 22",
    "VMREAD 23",
    "VMRESUME 24",
    "VMWRITE 25",
    "VMOFF 26",
    "VMON 27",
    "CR_ACCESS 28",
    "DR_ACCESS 29",
    "IO_INSTRUCTION 30",
    "MSR_READ 31",
    "MSR_WRITE 32",
    "INVALID_STATE 33",
    "MSR_LOAD_FAIL 34",
    "MWAIT_INSTRUCTION 36",
    "MONITOR_TRAP_FLAG 37",
    "MONITOR_INSTRUCTION 39",
    "PAUSE_INSTRUCTION 40",
    "MCE_DURING_VMENTRY 41",
    "TPR_BELOW_THRESHOLD 43",
    "APIC_ACCESS 44",
    "EOI_INDUCED 45",
    "GDTR_IDTR 46",
    "LDTR_TR 47",
    "EPT_VIOLATION 48",
    "EPT_MISCONFIG 49",
    "INVEPT 50",
    "RDTSCP 51",
    "PREEMPTION_TIMER 52",
    "INVVPID 53",
    "WBINVD 54",
    "XSETBV 55",
    "APIC_WRITE 56",
    "RDRAND 57",
    "INVPCID 58",
    "VMFUNC 59",
    "ENCLS 60",
    "RDSEED 61",
    "PML_FULL 62",
    "XSAVES 63",
    "XRSTORS 64",
    "UMWAIT 67",
    "TPAUSE 68"
)

exit_reasons_AMD = (
    "READ_CR0 0",
    "READ_CR2 2",
    "READ_CR3 3",
    "READ_CR4 4",
    "READ_CR8 8",
    "WRITE_CR0 16",
    "WRITE_CR2 18",
    "WRITE_CR3 19",
    "WRITE_CR4 20",
    "WRITE_CR8 24",
    "READ_DR0 32",
    "READ_DR1 33",
    "READ_DR2 34",
    "READ_DR3 35",
    "READ_DR4 36",
    "READ_DR5 37",
    "READ_DR6 38",
    "READ_DR7 39",
    "WRITE_DR0 48",
    "WRITE_DR1 49",
    "WRITE_DR2 50",
    "WRITE_DR3 51",
    "WRITE_DR4 52",
    "WRITE_DR5 53",
    "WRITE_DR6 54",
    "WRITE_DR7 55",
    "EXCP_BASE_DE 64",
    "EXCP_BASE_DB 65",
    "EXCP_BASE_BP 67",
    "EXCP_BASE_OF 68",
    "EXCP_BASE_BR 69",
    "EXCP_BASE_UD 70",
    "EXCP_BASE_NM 71",
    "EXCP_BASE_DF 72",
    "EXCP_BASE_TS 74",
    "EXCP_BASE_NP 75",
    "EXCP_BASE_SS 76",
    "EXCP_BASE_GP 77",
    "EXCP_BASE_PF 78",
    "EXCP_BASE_MF 80",
    "EXCP_BASE_AC 81",
    "EXCP_BASE_MC 82",
    "EXCP_BASE_XM 83",
    "INTR 96",
    "NMI 97",
    "SMI 98",
    "INIT 99",
    "VINTR 100",
    "CR0_SEL_WRITE 101",
    "IDTR_READ 102",
    "GDTR_READ 103",
    "LDTR_READ 104",
    "TR_READ 105",
    "IDTR_WRITE 106",
    "GDTR_WRITE 107",
    "LDTR_WRITE 108",
    "TR_WRITE 109",
    "RDTSC 110",
    "RDPMC 111",
    "PUSHF 112",
    "POPF 113",
    "CPUID 114",
    "RSM 115",
    "IRET 116",
    "SWINT 117",
    "INVD 118",
    "PAUSE 119",
    "HLT 120",
    "INVLPG 121",
    "INVLPGA 122",
    "IOIO 123",
    "MSR 124",
    "TASK_SWITCH 125",
    "FERR_FREEZE 126",
    "SHUTDOWN 127",
    "VMRUN 128",
    "VMMCALL 129",
    "VMLOAD 130",
    "VMSAVE 131",
    "STGI 132",
    "CLGI 133",
    "SKINIT 134",
    "RDTSCP 135",
    "ICEBP 136",
    "WBINVD 137",
    "MONITOR 138",
    "MWAIT 139",
    "MWAIT_COND 140",
    "XSETBV 141",
    "RDPRU 142",
    "NPF 1024",
    "AVIC_INCOMPLETE_IPI 1025",
    "AVIC_UNACCELERATED_ACCESS 1026",
)

#
# Do some checks
#
is_INTEL = False
is_AMD = False
try:
    # Currently, only adapte on Intel/AMD architecture
    cmd = "cat /proc/cpuinfo | grep vendor_id | head -n 1"
    arch_info = subprocess.check_output(cmd, shell=True).strip()
    if b"Intel" in arch_info:
        is_INTEL = True
        pass
    elif b"AMD" in arch_info:
        is_AMD = True
        pass
    else:
        raise Exception("Currently we only support Intel & AMD architecture, please do expansion if needs more.")

    # Check if kvm module is loaded
    if os.access("/dev/kvm", os.R_OK | os.W_OK):
        pass
    else:
        raise Exception("Please insmod kvm module to use kvmexit tool.")
except Exception as e:
    raise Exception("Failed to do precondition check, due to: %s." % e)

try:
    if BPF.support_raw_tracepoint_in_module():
        # Let's firstly try raw_tracepoint_in_module
        func_entry = "RAW_TRACEPOINT_PROBE(kvm_exit)"
        get_er = "ctx->args[0]"
    else:
        # If raw_tp_in_module is not supported, fall back to regular tp
        func_entry = "TRACEPOINT_PROBE(kvm, kvm_exit)"
        get_er = "args->exit_reason"
except Exception as e:
    raise Exception("Failed to catch kvm exit reasons due to: %s" % e)

# format output
if is_INTEL:
    exit_reason_header = exit_reasons_Intel
else:
    exit_reason_header = exit_reasons_AMD
exit_reasons = dict()

max_reason_num = 0
for reason in exit_reason_header:
    value, key = re.split(r"\s+", reason)
    key = int(key, 10)
    exit_reasons[key] = value
    if key > max_reason_num:
        max_reason_num = key

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

# For kernel >= 5.0, use RAW_TRACEPOINT_MODULE for performance consideration
bpf_text = bpf_text.replace('FUNC_ENTRY', func_entry)
bpf_text = bpf_text.replace('GET_ER', get_er)

reasons_size= "#define REASON_NUM " + str(max_reason_num + 1)
bpf_text = bpf_text.replace('REASON_NUM_L', reasons_size)
b = BPF(text=bpf_text)


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
        tgid_exit = [0 for i in range(max_reason_num + 1)]

# output
print("%s%-35s %s" % (header_format, "KVM_EXIT_REASON", "COUNT"))

pcpu_kvm_stat = b["pcpu_kvm_stat"]
pcpu_cache = b["pcpu_cache"]
for k, v in pcpu_kvm_stat.items():
    tgid = k.value >> 32
    pid = k.value & 0xffffffff
    for i in exit_reasons.keys():
        sum1 = 0
        for inner_cpu in range(0, multiprocessing.cpu_count()):
            cachePIDTGID = pcpu_cache[0][inner_cpu].cache_pid_tgid
            # Take priority to check if it is in cache
            if cachePIDTGID == k.value:
                sum1 += pcpu_cache[0][inner_cpu].cache_exit_ct.exit_ct[i]
            # If not in cache, find from kvm_stat
            else:
                sum1 += v[inner_cpu].exit_ct[i]
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
    for i in exit_reasons.keys():
        ct_reason.append((tgid_exit[i], i))
    ct_reason.sort(reverse=True)
    for i in range(0, len(ct_reason)):
        if ct_reason[i][0] == 0:
            continue
        print("%-35s %-8u" % (exit_reasons[ct_reason[i][1]], ct_reason[i][0]))
