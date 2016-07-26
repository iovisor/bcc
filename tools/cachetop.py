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

from __future__ import absolute_import
from __future__ import division
# Do not import unicode_literals until #623 is fixed
# from __future__ import unicode_literals
from __future__ import print_function

from collections import defaultdict
from time import strftime

import argparse
import curses
import pwd
from time import sleep
from libs import utils
from libs import cache

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


def get_processes_stats(
        bpf,
        sort_field=FIELDS.index(DEFAULT_FIELD),
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
        stats["%d-%d-%s" % (k.pid, k.uid, k.comm)][k.ip] = v
    stats_list = []

    for pid, count in sorted(stats.items(), key=lambda stat: stat[0]):
        (access, misses, mbd, rhits, whits) = cache.compute_cache_stats(count)
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
    sort_reverse = False

    # load BPF program
    bpf_text = """

    #include <uapi/linux/ptrace.h>
    struct key_t {
        u64 ip;
        u32 pid;
        u32 uid;
        char comm[16];
    };

    BPF_HASH(counts, struct key_t);

    int do_count(struct pt_regs *ctx) {
        struct key_t key = {};
        u64 zero = 0 , *val;
        u64 pid = bpf_get_current_pid_tgid();
        u32 uid = bpf_get_current_uid_gid();

        key.ip = PT_REGS_IP(ctx);
        key.pid = pid & 0xFFFFFFFF;
        key.uid = uid & 0xFFFFFFFF;
        bpf_get_current_comm(&(key.comm), 16);

        val = counts.lookup_or_init(&key, &zero);  // update counter
        (*val)++;
        return 0;
    }

    """
    b = cache.bpf_start(bpf_text)

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

        # Get memory info
        mem = utils.get_meminfo()
        cached = int(mem["Cached"]) / 1024
        buff = int(mem["Buffers"]) / 1024

        process_stats = get_processes_stats(
            b,
            sort_field=sort_field,
            sort_reverse=sort_reverse)
        stdscr.clear()
        stdscr.addstr(
            0, 0,
            "%-8s Buffers MB: %.0f / Cached MB: %.0f" % (
                strftime("%H:%M:%S"), buff, cached
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
            stdscr.addstr(
                i + 2, 0,
                "{0:8} {username:8.8} {2:16} {3:8} {4:8} "
                "{5:8} {6:9.1f}% {7:9.1f}%".format(
                    *stat, username=pwd.getpwuid(int(stat[1]))[0]
                )
            )
            if i > height - 4:
                break
        stdscr.refresh()

        try:
            sleep(args.interval)
        except KeyboardInterrupt:
            exiting = 1
            utils.handle_sigint()

        if exiting:
            print("Detaching...")
            return


def parse_arguments():
    parser = argparse.ArgumentParser(
        description='show Linux page cache hit/miss statistics including read '
                    'and write hit % per processes in a UI like top.'
    )
    parser.add_argument(
        'interval', type=int, default=5, nargs='?',
        help='Interval between probes.'
    )

    args = parser.parse_args()
    return args

args = parse_arguments()
curses.wrapper(handle_loop, args)
