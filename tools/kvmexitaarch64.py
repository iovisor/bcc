#!/usr/bin/python3
#
# kvmexitaarch64.py
#
# Display the exit_reason and its statistics of each vm exit
# for all vcpus of all virtual machines on aarch64. For example:
# $./kvmexit.py 5
# TGID     TID      COMM             KVM_EXIT_REASON  COUNT    AVG_TIME    
# 24919    24938    b'CPU 1/KVM'     EC_WFx           143      34780751.4 
# 24919    24938    b'CPU 1/KVM'     EC_SYS64         8        8545.0     
# 24919    24938    b'CPU 1/KVM'     EC_DABT_LOW      2        10650.0    
# 24919    24937    b'CPU 0/KVM'     EC_WFx           21       192253853.0
# 24919    24937    b'CPU 0/KVM'     EC_SYS64         3        6173.3     
#  ...
#
# @TID: the user space's thread of each vcpu of that virtual machine.
# @TGID: thread group id, means qmeu's pid in user space.
# @COMM: the name of vcpu thread.
# @KVM_EXIT_REASON: the reason why the vm exits on aarch64.
# @COUNT: the counts of the @KVM_EXIT_REASONS.
# @AVG_TIME: the average of all time interval from kvm_exit to the next kvm_entry. unit:ns
#
# REQUIRES: Linux 4.7+ (BPF_PROG_TYPE_TRACEPOINT support)
#
# Copyright (c) 2023 kylinos Inc. All rights reserved.
#
# Author(s):
#   Longjun Tang <tanglongjun@kylinos.cn>


from time import sleep
from ctypes import *
import argparse
import subprocess
import os
from bpfcc import BPF


# arguments
examples = """examples:
    ./kvmexitaarch64.py                              # Display kvm_exit_reason and its statistics in real-time until Ctrl-C
    ./kvmexitaarch64.py 5                            # Display in real-time after sleeping 5s
"""

parser = argparse.ArgumentParser(
    description="Display kvm_exit_reason and its statistics at a timed interval on aarch64",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("duration", nargs="?", default=99999999, type=int, help="show delta for next several seconds")
args = parser.parse_args()
duration = int(args.duration)

# Do some checks
try:
    # Currently, only adapte on aarch64 architecture
    cmd = "uname -m"
    arch_info = subprocess.check_output(cmd, shell=True).strip()
    if b"aarch64" in arch_info:
        pass
    else:
        raise Exception("Currently we only support aarch64 architecture, please do expansion if needs more.")

    # Check if kvm module is loaded
    if os.access("/dev/kvm", os.R_OK | os.W_OK):
        pass
    else:
        raise Exception("Please insmod kvm module to use kvmexitaarch64 tool.")
except Exception as e:
    raise Exception("Failed to do precondition check, due to: %s." % e)


# define BPF program
prog = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// define kvm_exit structure in C
typedef struct kvm_exit{
    u64 exit_count;
    u64 exit_ts;    //timestamp of kvm_exit
    u64 entry_ts;   //timestamp of kvm_entry after kvm_exit for the same vcpu thread.
    u64 sum_hd;
    u64 max_hd;
    u64 min_hd;
}kvm_exit_t;

#define MAX_ESR_EC 64
struct kvm_exit_stat_t{
    u64 tgid_pid;
    char comm[TASK_COMM_LEN];
    u32 last_exit_rs;
    kvm_exit_t kvm_exit[MAX_ESR_EC];
};

BPF_HASH(kvm_exit_stat, u64, struct kvm_exit_stat_t);
BPF_ARRAY(init_value, struct kvm_exit_stat_t, 1);

TRACEPOINT_PROBE(kvm, kvm_entry)
{
    kvm_exit_t *tmp_kvm_exit = NULL;
    u64 time_hd = 0;
    u64 cur_tgid_pid = bpf_get_current_pid_tgid();
    struct kvm_exit_stat_t *tmp_kvm_exit_stat = NULL;

    // it will return if vcpu thread never occur kvm entry 
    tmp_kvm_exit_stat = kvm_exit_stat.lookup(&cur_tgid_pid);
    if (tmp_kvm_exit_stat == NULL) {
        return 0;
    }

    if (tmp_kvm_exit_stat->last_exit_rs >= MAX_ESR_EC) {
        return 0;
    }
    tmp_kvm_exit = &tmp_kvm_exit_stat->kvm_exit[tmp_kvm_exit_stat->last_exit_rs];

    tmp_kvm_exit->entry_ts = bpf_ktime_get_ns();

    // time_hd is time interval from kvm_exit to next kvm entry
    time_hd = tmp_kvm_exit->entry_ts - tmp_kvm_exit->exit_ts;
    tmp_kvm_exit->sum_hd += time_hd;

    // for maximum of all time_hd
    if (tmp_kvm_exit->max_hd == 0) {
        tmp_kvm_exit->max_hd = time_hd;
    } else {
        if (time_hd > tmp_kvm_exit->max_hd) {
            tmp_kvm_exit->max_hd = time_hd;
        }
    }

    // for minimum of all time_hd
    if (tmp_kvm_exit->min_hd == 0) {
        tmp_kvm_exit->min_hd = time_hd;
    } else {
        if (time_hd < tmp_kvm_exit->min_hd) {
            tmp_kvm_exit->min_hd = time_hd;
        }
    }
 
    return 0;
}

TRACEPOINT_PROBE(kvm, kvm_exit)
{
    int zero = 0;
    u32 esr_ec = args->esr_ec;
    u64 cur_tgid_pid = bpf_get_current_pid_tgid();
    struct kvm_exit_stat_t *tmp_kvm_exit_stat = NULL, *init = NULL;

    if (esr_ec >= MAX_ESR_EC) {
        return 0;
    }

    tmp_kvm_exit_stat = kvm_exit_stat.lookup(&cur_tgid_pid);
    // kvm_exit_stat hash initialized when vcpu thread first time occur kvm exit
    if (tmp_kvm_exit_stat == NULL) {
        init = init_value.lookup(&zero);
        if (init == NULL) {
            return 0;
        }
        kvm_exit_stat.update(&cur_tgid_pid, init);
        tmp_kvm_exit_stat = kvm_exit_stat.lookup(&cur_tgid_pid);
        if (tmp_kvm_exit_stat == NULL) {
            return 0;
        }
        tmp_kvm_exit_stat->tgid_pid = cur_tgid_pid;
        bpf_get_current_comm(&tmp_kvm_exit_stat->comm[0], sizeof(tmp_kvm_exit_stat->comm));
    }

    // record exit reason and count
    tmp_kvm_exit_stat->last_exit_rs = esr_ec;
    tmp_kvm_exit_stat->kvm_exit[esr_ec].exit_count += 1;
    tmp_kvm_exit_stat->kvm_exit[esr_ec].exit_ts = bpf_ktime_get_ns();

    return 0;
}
"""


"""
From linux kernel version 4.19
static exit_handle_fn arm_exit_handlers[] = {
	[0 ... ESR_ELx_EC_MAX]	= kvm_handle_unknown_ec,
	[ESR_ELx_EC_WFx]	= kvm_handle_wfx,
	[ESR_ELx_EC_CP15_32]	= kvm_handle_cp15_32,
	[ESR_ELx_EC_CP15_64]	= kvm_handle_cp15_64,
	[ESR_ELx_EC_CP14_MR]	= kvm_handle_cp14_32,
	[ESR_ELx_EC_CP14_LS]	= kvm_handle_cp14_load_store,
	[ESR_ELx_EC_CP14_64]	= kvm_handle_cp14_64,
	[ESR_ELx_EC_HVC32]	= handle_hvc,
	[ESR_ELx_EC_SMC32]	= handle_smc,
	[ESR_ELx_EC_HVC64]	= handle_hvc,
	[ESR_ELx_EC_SMC64]	= handle_smc,
	[ESR_ELx_EC_SYS64]	= kvm_handle_sys_reg,
	[ESR_ELx_EC_SVE]	= handle_sve,
	[ESR_ELx_EC_IABT_LOW]	= kvm_handle_guest_abort,
	[ESR_ELx_EC_DABT_LOW]	= kvm_handle_guest_abort,
	[ESR_ELx_EC_SOFTSTP_LOW]= kvm_handle_guest_debug,
	[ESR_ELx_EC_WATCHPT_LOW]= kvm_handle_guest_debug,
	[ESR_ELx_EC_BREAKPT_LOW]= kvm_handle_guest_debug,
	[ESR_ELx_EC_BKPT32]	= kvm_handle_guest_debug,
	[ESR_ELx_EC_BRK64]	= kvm_handle_guest_debug,
	[ESR_ELx_EC_FP_ASIMD]	= handle_no_fpsimd,
};
"""
aarch64_exit_reasons = (
    "UNKNOWN_EC",
    "EC_WFx",
    "N/A",
    "EC_CP15_32",
    "EC_CP15_64",
    "EC_CP14_MR",
    "EC_CP14_LS",
    "EC_FP_ASIMD",
    "N/A",
    "N/A",
    "N/A",
    "N/A",
    "EC_CP14_64",
    "N/A",
    "N/A",
    "N/A",
    "N/A",
    "N/A",
    "EC_HVC32",
    "EC_SMC32",
    "N/A",
    "N/A",
    "EC_HVC64",
    "EC_SMC64",
    "EC_SYS64",
    "EC_SVE",
    "N/A",
    "N/A",
    "N/A",
    "N/A",
    "N/A",
    "N/A",
    "EC_IABT_LOW",
    "N/A",
    "N/A",
    "N/A",
    "EC_DABT_LOW",
    "N/A",
    "N/A",
    "N/A",
    "N/A",
    "N/A",
    "N/A",
    "N/A",
    "N/A",
    "N/A",
    "N/A",
    "N/A",
    "EC_BREAKPT_LOW",
    "N/A",
    "EC_SOFTSTP_LOW",
    "N/A",
    "EC_WATCHPT_LOW",
    "N/A",
    "N/A",
    "N/A",
    "EC_BKPT32",
    "N/A",
    "N/A",
    "N/A",
    "EC_BRK64",
    "N/A",
    "N/A",
    "N/A"
)

# load BPF program
b = BPF(text=prog)

try:
    sleep(duration)
except KeyboardInterrupt:
    pass

# header
print("\n%-8s %-8s %-16s %-16s %-8s %-12s" % ("TGID", "TID", "COMM", "KVM_EXIT_REASON", "COUNT", "AVG_TIME"))

kvm_exit_stat = b["kvm_exit_stat"]
for k, v in kvm_exit_stat.items():
    tgid = k.value >> 32
    pid = k.value & 0xffffffff
    for i in range(0, len(aarch64_exit_reasons)):
        if (v.kvm_exit[i].exit_count == 0):
            continue
        print("%-8u %-8u %-16s %-16s %-8u %-11.1f" % (tgid, pid, v.comm, aarch64_exit_reasons[i], \
            v.kvm_exit[i].exit_count, v.kvm_exit[i].sum_hd/v.kvm_exit[i].exit_count))