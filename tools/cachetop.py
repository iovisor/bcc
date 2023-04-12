#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# cachetop      Count cache kernel function calls per processes
#               For Linux, uses BCC, eBPF.
#
# USAGE: cachetop
# Taken from cachestat by Brendan Gregg
#
# Copyright (c) 2016-present, Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 13-Jul-2016   Emmanuel Bretelle first version
# 17-Mar-2022   Rocky Xing        Added PID filter support.
# 15-Feb-2023   Rong Tao          Add writeback_dirty_{folio,page} tracepoints

from __future__ import absolute_import
from __future__ import division
# Do not import unicode_literals until #623 is fixed
# from __future__ import unicode_literals
from __future__ import print_function

from bcc import BPF
from collections import defaultdict
from time import strftime

import argparse
import curses
import pwd
import re
import signal
from time import sleep

FIELDS = (
    "PID",
    "UID",
    "CMD",
    "HITS",
    "MISSES",
    "DIRTIES",
    "READ_HIT%",
    "WRITE_HIT%"
)
DEFAULT_FIELD = "HITS"
DEFAULT_SORT_FIELD = FIELDS.index(DEFAULT_FIELD)

# signal handler
def signal_ignore(signal, frame):
    print()


# Function to gather data from /proc/meminfo
# return dictionary for quicker lookup of both values
def get_meminfo():
    result = {}

    for line in open('/proc/meminfo'):
        k = line.split(':', 3)
        v = k[1].split()
        result[k[0]] = int(v[0])
    return result


def get_processes_stats(
        bpf,
        sort_field=DEFAULT_SORT_FIELD,
        sort_reverse=False):
    '''
    Return a tuple containing:
    buffer
    cached
    list of tuple with per process cache stats
    '''
    counts = bpf.get_table("counts")
    stats = defaultdict(lambda: defaultdict(int))
    for k, v in counts.items():
        stats["%d-%d-%s" % (k.pid, k.uid, k.comm.decode('utf-8', 'replace'))][k.nf] = v.value
    stats_list = []

    for pid, count in sorted(stats.items(), key=lambda stat: stat[0]):
        rtaccess = 0
        wtaccess = 0
        mpa = 0
        mbd = 0
        apcl = 0
        apd = 0
        access = 0
        misses = 0
        rhits = 0
        whits = 0

        for k, v in count.items():
            if k == 0: # NF_APCL
                apcl = max(0, v)

            if k == 1: # NF_MPA
                mpa = max(0, v)

            if k == 2: # NF_MBD
                mbd = max(0, v)

            if k == 3: # NF_APD
                apd = max(0, v)

            # access = total cache access incl. reads(mpa) and writes(mbd)
            # misses = total of add to lru which we do when we write(mbd)
            # and also the mark the page dirty(same as mbd)
            access = (mpa + mbd)
            misses = (apcl + apd)

            # rtaccess is the read hit % during the sample period.
            # wtaccess is the write hit % during the sample period.
            if mpa > 0:
                rtaccess = float(mpa) / (access + misses)
            if apcl > 0:
                wtaccess = float(apcl) / (access + misses)

            if wtaccess != 0:
                whits = 100 * wtaccess
            if rtaccess != 0:
                rhits = 100 * rtaccess

        _pid, uid, comm = pid.split('-', 2)
        stats_list.append(
            (int(_pid), uid, comm,
             access, misses, mbd,
             rhits, whits))

    stats_list = sorted(
        stats_list, key=lambda stat: stat[sort_field], reverse=sort_reverse
    )
    counts.clear()
    return stats_list


def handle_loop(stdscr, args):
    # don't wait on key press
    stdscr.nodelay(1)
    # set default sorting field
    sort_field = FIELDS.index(DEFAULT_FIELD)
    sort_reverse = True

    # load BPF program
    bpf_text = """

    #include <uapi/linux/ptrace.h>
    struct key_t {
        // NF_{APCL,MPA,MBD,APD}
        u64 nf;
        u32 pid;
        u32 uid;
        char comm[16];
    };
    enum {
        NF_APCL,
        NF_MPA,
        NF_MBD,
        NF_APD,
    };

    BPF_HASH(counts, struct key_t);

    static int __do_count(void *ctx, u64 nf) {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        if (FILTER_PID)
            return 0;

        struct key_t key = {};
        u32 uid = bpf_get_current_uid_gid();

        key.nf = nf;
        key.pid = pid;
        key.uid = uid;
        bpf_get_current_comm(&(key.comm), 16);

        counts.increment(key);
        return 0;
    }
    int do_count_apcl(struct pt_regs *ctx) {
        return __do_count(ctx, NF_APCL);
    }
    int do_count_mpa(struct pt_regs *ctx) {
        return __do_count(ctx, NF_MPA);
    }
    int do_count_mbd(struct pt_regs *ctx) {
        return __do_count(ctx, NF_MBD);
    }
    int do_count_apd(struct pt_regs *ctx) {
        return __do_count(ctx, NF_APD);
    }
    int do_count_apd_tp(void *ctx) {
        return __do_count(ctx, NF_APD);
    }

    """

    if args.pid:
        bpf_text = bpf_text.replace('FILTER_PID', 'pid != %d' % args.pid)
    else:
        bpf_text = bpf_text.replace('FILTER_PID', '0')

    b = BPF(text=bpf_text)
    b.attach_kprobe(event="add_to_page_cache_lru", fn_name="do_count_apcl")
    b.attach_kprobe(event="mark_page_accessed", fn_name="do_count_mpa")
    b.attach_kprobe(event="mark_buffer_dirty", fn_name="do_count_mbd")

    # Function account_page_dirtied() is changed to folio_account_dirtied() in 5.15.
    # Introduce tracepoint writeback_dirty_{page,folio}
    if BPF.get_kprobe_functions(b'folio_account_dirtied'):
        b.attach_kprobe(event="folio_account_dirtied", fn_name="do_count_apd")
    elif BPF.get_kprobe_functions(b'account_page_dirtied'):
        b.attach_kprobe(event="account_page_dirtied", fn_name="do_count_apd")
    elif BPF.tracepoint_exists("writeback", "writeback_dirty_folio"):
        b.attach_tracepoint(tp="writeback:writeback_dirty_folio", fn_name="do_count_apd_tp")
    elif BPF.tracepoint_exists("writeback", "writeback_dirty_page"):
        b.attach_tracepoint(tp="writeback:writeback_dirty_page", fn_name="do_count_apd_tp")
    else:
        raise Exception("Failed to attach kprobe %s or %s and any tracepoint" %
                        ("folio_account_dirtied", "account_page_dirtied"))

    exiting = 0

    while 1:
        s = stdscr.getch()
        if s == ord('q'):
            exiting = 1
        elif s == ord('r'):
            sort_reverse = not sort_reverse
        elif s == ord('<'):
            sort_field = max(0, sort_field - 1)
        elif s == ord('>'):
            sort_field = min(len(FIELDS) - 1, sort_field + 1)
        try:
            sleep(args.interval)
        except KeyboardInterrupt:
            exiting = 1
            # as cleanup can take many seconds, trap Ctrl-C:
            signal.signal(signal.SIGINT, signal_ignore)

        # Get memory info
        mem = get_meminfo()
        cached = int(mem["Cached"]) / 1024
        buff = int(mem["Buffers"]) / 1024

        process_stats = get_processes_stats(
            b,
            sort_field=sort_field,
            sort_reverse=sort_reverse)
        stdscr.clear()
        stdscr.addstr(
            0, 0,
            "%-8s Buffers MB: %.0f / Cached MB: %.0f "
            "/ Sort: %s / Order: %s" % (
                strftime("%H:%M:%S"), buff, cached, FIELDS[sort_field],
                sort_reverse and "descending" or "ascending"
            )
        )

        # header
        stdscr.addstr(
            1, 0,
            "{0:8} {1:8} {2:16} {3:8} {4:8} {5:8} {6:10} {7:10}".format(
                *FIELDS
            ),
            curses.A_REVERSE
        )
        (height, width) = stdscr.getmaxyx()
        for i, stat in enumerate(process_stats):
            uid = int(stat[1])
            try:
                username = pwd.getpwuid(uid)[0]
            except KeyError:
                # `pwd` throws a KeyError if the user cannot be found. This can
                # happen e.g. when the process is running in a cgroup that has
                # different users from the host.
                username = 'UNKNOWN({})'.format(uid)

            stdscr.addstr(
                i + 2, 0,
                "{0:8} {username:8.8} {2:16} {3:8} {4:8} "
                "{5:8} {6:9.1f}% {7:9.1f}%".format(
                    *stat, username=username
                )
            )
            if i > height - 4:
                break
        stdscr.refresh()
        if exiting:
            print("Detaching...")
            return


def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Show Linux page cache hit/miss statistics including read '
                    'and write hit % per processes in a UI like top.'
    )
    parser.add_argument("-p", "--pid", type=int, metavar="PID",
        help="trace this PID only")
    parser.add_argument(
        'interval', type=int, default=5, nargs='?',
        help='Interval between probes.'
    )

    args = parser.parse_args()
    return args

args = parse_arguments()
curses.wrapper(handle_loop, args)
