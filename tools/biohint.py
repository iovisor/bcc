# Copyright (c) 2025 Samsung Electronics Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License")
from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
from pathlib import Path
from threading import Event
import argparse
import json
import sys
import os
import signal

disklookup = {}
mounts = "/proc/mounts"
epilog = """examples:
    ./biohint                   # Summarize block I/O hint in histogram.
    ./biohint 1 10              # Print 10 reports at 1 second intervals.
    ./biohint -t 1              # Print summary with timestamp at 1 second intervals.
    ./biohint -s                # Show histograms of every device separately.
    ./biohint -d /mnt/data      # Trace the device which has been mounted on '/mnt/data'.
"""
hints = """
    0: NOT_SET
    1: NONE
    2: SHORT
    3: MEDIUM
    4: LONG
    5: EXTREME
"""
bpf_text = """
#include <linux/blk_types.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/time64.h>

typedef struct disk_key {
    u64 dev;
    u64 slot;
} disk_key_t;

STORAGE

RAW_TRACEPOINT_PROBE(block_bio_queue)
{
    struct bio *b = (void *)ctx->args[0];
    unsigned int flags = b->bi_opf;
    unsigned int flag = flags & REQ_OP_MASK;
    dev_t dev = b->bi_bdev->bd_dev;
    HINT_GET

    DISK_FILTER

    if(flag | REQ_OP_WRITE){
        STORE
    }
    return 0;
}
"""
class EqualSignHelpFormatter(argparse.RawDescriptionHelpFormatter):
    def _format_action_invocation(self, action):
        if not action.option_strings:
            #positional arguments
            metavar = self._metavar_formatter(action, action.dest)(1)
            if isinstance(metavar, tuple):
                metavar = ' '.join(metavar)
            return metavar
        else:
            #optional arguments
            parts = []
            for option_string in action.option_strings:
                if option_string == "--dev":
                    parts.append(f"{option_string}={action.metavar}")
                elif option_string == "-d":
                    parts.append(f"{option_string} {action.metavar}")
                else:
                    parts.append(f"{option_string}")
            return ", ".join(parts)
    def _format_action(self, action):
        help_text = action.help
        option_str = self._format_action_invocation(action)

        if help_text == "Trace the device which has been mounted on specific directory":
            return f"    {option_str}\t\t{help_text}\n"
        elif help_text == "Print histograms of every device separately":
            return f"    {option_str}\t\t{help_text}\n"
        else:
            return f"    {option_str}\t\t\t{help_text}\n"

def args_config():
    parser = argparse.ArgumentParser(
        description = "Summarize write hint in block of FDP SSDs",
        formatter_class = EqualSignHelpFormatter,
        epilog = epilog)
    parser.add_argument("-t", "--ts", action = "store_true",
        help = "Print histogram with timestamp")
    parser.add_argument("-s", "--devices", action = "store_true",
        help = "Print histograms of every device separately")
    parser.add_argument("interval", nargs = "?", default = 99999999, type = int,
        help = "Specify the amount of time in seconds between each report")
    parser.add_argument("count", nargs = "?", default = 99999999, type = int,
        help = "Limit the number of report, the default is ....")
    parser.add_argument("-d", "--dir", type = str, metavar = '<dir>',
        help = "Trace the device which has been mounted on specific directory")
    parser._optionals._actions[0].help = "Show this help"
    args = parser.parse_args()
    return args

def bpf_text_config(args, is_hint):
    global bpf_text
    global disklookup
    if(args.dir):
        args.dir = str(Path(args.dir).resolve())
    storage_str = ""
    store_str = ""
    disk_filter_str = ""
    if args.devices:
        storage_str += "BPF_HISTOGRAM(dist, disk_key_t);"
        store_str += """
        disk_key_t dkey = {};
        dkey.dev = dev;
        dkey.slot = hint;
        dist.atomic_increment(dkey);
        """
    else:
        storage_str += "BPF_HISTOGRAM(dist);"
        store_str += "dist.atomic_increment(hint);"

    if args.dir is not None:
        if args.dir not in disklookup:
            print("erro: invalid mount point!")
            return False
        disk_path = disklookup[args.dir]
        if not os.path.exists(disk_path):
            print("no such dev '%s'" % args.dev)
            exit(1)

        stat_info = os.stat(disk_path)
        dev = os.major(stat_info.st_rdev) << 20 | os.minor(stat_info.st_rdev)

        disk_filter_str += """
        if(dev != %s) {
            return 0;
        }
        """ % (dev)
    bpf_text = bpf_text.replace("STORAGE", storage_str)
    bpf_text = bpf_text.replace("STORE", store_str)
    bpf_text = bpf_text.replace("DISK_FILTER", disk_filter_str)

    if  is_hint == True:
        bpf_text = bpf_text.replace("HINT_GET", "u32 hint = b->bi_write_hint;")
    else:
        bpf_text = bpf_text.replace("HINT_GET", "return 0;")

    return True

def disk_print(d):
    major = d >> 20
    minor = d & ((1 << 20) - 1)

    disk = str(major) + "," + str(minor)
    if disk in disklookup:
        diskname = disklookup[disk]
    else:
        diskname = "?"

    return diskname

def disk_look():
    with open(mounts) as stats:
        for line in stats:
            a = line.split()
            disklookup[a[1]] = a[0]
    return disklookup

def print_linear_hist(dic_hint, max):
    dic_hint = dict(sorted(dic_hint.items(), key = lambda x: x[0]))
    print("{:>10}:".format("hint"), "{:<10}".format("count"), " {:<40}".format("distribution"))
    for key, value in dic_hint.items():
        num = int(value / max * 40)
        print("{:>10}:".format(key), "{:<10}".format(value), "|{:<40}|".format("*"*num))

def main():
    args = args_config()
    global hints
    global disklookup
    print("the program is being configured!")
    print(hints)

    disklookup = disk_look()
    is_hint = BPF.kernel_struct_has_field(b'bio', b'bi_write_hint')
    if bpf_text_config(args, is_hint) == False:
        return
    b = BPF(text = bpf_text)

    countdown = int(args.count)
    exiting = 0 if args.interval else 1
    dist = b.get_table("dist")
    print("configure complete! the program is running!")

    while True:
        try:
            sleep(int(args.interval))
        except KeyboardInterrupt:
            exiting = 1
        dic_hint = {}
        dic_hint_max = {}
        hint_max = 0
        if args.ts:
            print("%-8s\n" % strftime("%H:%M:%S"), end = "")

        for key, value in dist.items():
            cnt = value.value
            if args.devices:
                dev = key.dev
                hint = key.slot
                disk_name = disk_print(dev)
                if disk_name in dic_hint:
                    dic_hint[disk_name][hint] = cnt
                    dic_hint_max[disk_name] = max(dic_hint_max[disk_name], cnt)
                else:
                    dic_temp = {}
                    dic_temp[hint] = cnt
                    dic_hint[disk_name] = dic_temp
                    dic_hint_max[disk_name] = cnt
             else:
                hint = key.value
                if cnt == 0:
                    continue
                dic_hint[hint] = cnt
                hint_max = max(hint_max, cnt)

        if args.devices:
            for key, value in dic_hint.items():
                print("disk = ", key)
                print_linear_hist(value, dic_hint_max[key])
        else:
            print_linear_hist(dic_hint, hint_max)
        print()
        print()
        countdown -= 1
        if exiting or countdown == 0:
            exit(0)

if __name__ == '__main__':
    main()
