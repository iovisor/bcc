#!/usr/bin/python
#
# lbr.py
#
# Trace conditional branches executed by syscalls using the Last Branch Record
# Buffer (LBR)
#
# REQUIRES:
#   Linux 5.16+ (bpf_get_branch_snapshot support)
#
# Copyright (c) 2023 Bytedance Inc.
#
# Author(s):
#   Lorenzo Carrozzo <lorenzocarrozzo@bytedance.com>

from __future__ import absolute_import, print_function, unicode_literals
from bcc import BPF
from bcc import PerfType, PerfHWConfig, PerfEventSampleFormat, Perf
import argparse
from sys import exit
from pathlib import Path
from subprocess import Popen, PIPE

# Number of LBR entries and output tags
lbr_cnt = 32
num_entries_tag = 'lbr_total_entries:'
entry_tag = 'lbr_entry:'

# BPF program text
bpf_text = """
#include <uapi/linux/perf_event.h>
#include <uapi/linux/ptrace.h>

// Define arguments passed to tracepoint
struct params {
        short common_type;
        unsigned char common_flags;
        unsigned char common_preempt_count;
        int common_pid;
        int __syscall_nr;
        long ret;
};

struct perf_branch_entry_buf {
    struct perf_branch_entry entries[ENTRY_CNT];
};

BPF_PERCPU_ARRAY(branch_entry, struct perf_branch_entry_buf, 1);

// Function to use with tracepoint
int disp_snapshot_tp(struct params *p) {
    unsigned buf_size = sizeof(struct perf_branch_entry_buf), idx = 0;
    struct perf_branch_entry_buf *buf;

    buf = branch_entry.lookup(&idx);
    if (!buf)
        return 0;

    int total_entries = bpf_get_branch_snapshot(buf, buf_size, 0);
    total_entries /= sizeof(struct perf_branch_entry);

    if (true T_R_COND P_COND) {
        bpf_trace_printk("NUM_ENTRIES%d", total_entries);

        for (int i = 0; i < ENTRY_CNT; i++) {
            bpf_trace_printk("ENTRY%pS --> %pS", buf->entries[i].from,
                             buf->entries[i].to);
        }
    }

    return 0;
}

// Function to use with kretprobe
int disp_snapshot_krp(struct pt_regs *p) {
    unsigned buf_size = sizeof(struct perf_branch_entry_buf), idx = 0;
    struct perf_branch_entry_buf *buf;

    buf = branch_entry.lookup(&idx);
    if (!buf)
        return 0;

    int total_entries = bpf_get_branch_snapshot(buf, buf_size, 0);
    total_entries /= sizeof(struct perf_branch_entry);

    if (true K_R_COND P_COND) {
        bpf_trace_printk("NUM_ENTRIES%d", total_entries);

        for (int i = 0; i < ENTRY_CNT; i++) {
            bpf_trace_printk("ENTRY%pS --> %pS", buf->entries[i].from,
                             buf->entries[i].to);
        }
    }

    return 0;
}
"""

# Parse arguments
examples = """
examples:
    ./lbr -t <syscall>       # the syscall to attach the exit tracepoint to
    ./lbr -k <syscall>       # the syscall to attach a kretprobe to
    ./lbr -r <value>         # filter by syscall's return value
    ./lbr -p <pid>           # filter by program pid
    ./lbr -b <path/to/bin>   # kernel to search addresses in using addr2line
    ./lbr -d                 # show debug strings
"""
parser = argparse.ArgumentParser(
    description="Trace conditional branches using LBR.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-t", "--tracepoint", type=str, metavar="SYSCALL",
                    help="the syscall to attach the exit tracepoint to")
parser.add_argument("-k", "--kretprobe", type=str, metavar="SYSCALL",
                    help="the syscall to attach a kretprobe to", )
parser.add_argument("-r", "--ret_value", type=int, metavar="VALUE",
                    help="filter by syscall's return value")
parser.add_argument("-p", "--pid", type=int,
                    help="filter by pid")
parser.add_argument("-e", "--extend", action="store_true",
                    help="extend output width so entry addresses are on on \
                    one line")
parser.add_argument("-b", "--bin", type=str,
                    help="the binary to search address in")
parser.add_argument("-d", "--debug", action="store_true",
                    help="print out bpf program text")
args = parser.parse_args()

# Check that tracepoint or kretprobe is given
if args.tracepoint is None and args.kretprobe is None:
    print('Error tracepoint or kretprobe is required')
    parser.print_help()
    exit(1)
elif args.tracepoint == args.kretprobe:
    print('Warning it is not recommend to attach to a syscall`s tracepoint \n \
          and kretprobe at the same time!!!')

# Check binary is valid if provided
if args.bin is not None and not Path(args.bin).is_file():
    print('Error binary path is invalid')
    parser.print_help()
    exit(1)

# Replace conditions based on arguments
if args.ret_value is not None:
    bpf_text = bpf_text.replace('T_R_COND', f'&& p->ret == {args.ret_value}')
    bpf_text = bpf_text.replace('K_R_COND',
                                f'&& PT_REGS_RC(p) == {args.ret_value}')

if args.pid is not None:
    bpf_text = bpf_text.replace('P_COND',
                                f'&& (bpf_get_current_pid_tgid() >> 32) == \
                                {args.pid}')

# Remove any unused tags not used
bpf_text = bpf_text.replace('T_R_COND', '')
bpf_text = bpf_text.replace('K_R_COND', '')
bpf_text = bpf_text.replace('P_COND', '')

# Replace other globals
bpf_text = bpf_text.replace('ENTRY_CNT', str(lbr_cnt))
bpf_text = bpf_text.replace('NUM_ENTRIES', num_entries_tag)
bpf_text = bpf_text.replace('ENTRY', entry_tag)

# Print out completed bpf program text
if args.debug:
    print(bpf_text)

# Load bpf program
bpf_prog = BPF(text=bpf_text)

# Open perf event
# Filters are defined in perf_event.h
# PERF_SAMPLE_BRANCH_KERNEL | PERF_SAMPLE_BRANCH_USER | PERF_SAMPLE_BRANCH_COND
attr = Perf.perf_event_attr()
attr.config = PerfHWConfig.CPU_CYCLES
attr.type = PerfType.HARDWARE
attr.sample_type = PerfEventSampleFormat.BRANCH_STACK
attr.branch_sample_type = 2 | 1 | 1024
Perf.perf_custom_event_open(attr)

# Attach to tracepoint
if args.tracepoint is not None:
    tracepoint = f'syscalls:sys_exit_{args.tracepoint}'
    bpf_prog.attach_tracepoint(tp=tracepoint, fn_name='disp_snapshot_tp')

# Attach to kretprobe
if args.kretprobe is not None:
    kretprobe = bpf_prog.get_syscall_fnname(args.kretprobe)
    bpf_prog.attach_kretprobe(event=kretprobe, fn_name='disp_snapshot_krp')

def print_line(max_len, dir, info, i=' '):
    line = i + ' ' * (3 - len(i)) + '| ' + dir + ' | '
    line += info + ' ' * (max_len - len(info)) + ' |'
    print(line)
    return len(line)

def print_ex_line(max_fr, max_to, fr, to, i=' '):
    # Construct line and print it
    line = i + ' ' * (3 - len(i)) + '| '
    line += fr + ' ' * (max_fr - len(fr)) + ' --> '
    line += to + ' ' * (max_to - len(to)) + ' |'
    print(line)
    return len(line)

def addr2line(addr):
    # Get addr2line's output for the address
    comm = Popen(f'addr2line -e {args.bin} {addr}', stdout=PIPE, shell=True)
    stdout, _ = comm.communicate()
    stdout = stdout.decode().replace('\n', '').split(' ')
    return stdout[0]

def print_snapshot():
    # Get number of entries
    at_start = False
    while not at_start:
        (_, _, _, _, _, msg) = bpf_prog.trace_fields()
        msg = msg.decode()
        if msg.startswith(num_entries_tag):
            total_entries = int(msg.replace(num_entries_tag, ''))
            at_start = True

    # Get addresses
    fr_addrs, to_addrs, fr_paths, to_paths = [], [], [], []
    entries_read = 0
    while entries_read < total_entries:
        (_, _, _, _, _, msg) = bpf_prog.trace_fields()
        msg = msg.decode()
        if msg.startswith(entry_tag):
            addrs = msg.replace(entry_tag, '')
            addrs = addrs.split(' --> ')
            fr_addrs.append(addrs[0])
            to_addrs.append(addrs[1])
            entries_read += 1

    # Get address line number
    if args.bin is not None:
        fr_paths = list(map(lambda a: addr2line(a), fr_addrs))
        to_paths = list(map(lambda a: addr2line(a), to_addrs))

    # Get longest string for addresses/ paths
    max_fr = max(list(map(lambda a: len(a), fr_addrs + fr_paths + ['from'])))
    max_to = max(list(map(lambda a: len(a), to_addrs + to_paths + ['to'])))

    # Print info to user
    if args.extend:
        line_len = print_ex_line(max_fr, max_to, 'From', 'To', 'i')
        under_line = '-' * (line_len - 1) + '|'
        print(under_line)
        for i in range(total_entries):
            print_ex_line(max_fr, max_to, fr_addrs[i], to_addrs[i], str(i))
            if args.bin is not None:
                print_ex_line(max_fr, max_to, fr_paths[i], to_paths[i])
            print(under_line)
    else:
        hdr = 'Addresses' + (' / Paths' if args.bin is not None else '')
        max_len = max(max_fr, max_to, len(hdr))
        line_len = print_line(max_len, 'T/F ', hdr, 'i')
        under_line = '-' * (line_len - 5) + '|'
        print('----' + under_line)
        for i in range(total_entries):
            print_line(max_len, 'From', fr_addrs[i], str(i))
            if args.bin is not None:
                print_line(max_len, '    ', fr_paths[i])
            print('   |' + under_line)
            print_line(max_len, 'To  ', to_addrs[i])
            if args.bin is not None:
                print_line(max_len, '    ', to_paths[i])
            print('----' + under_line)
    print("\n\n")


# Main program loops

print('\nTracing logical branches... Hit Ctrl-C to end.\n')
while True:
    try:
        print_snapshot()
    except KeyboardInterrupt:
        exit(0)
