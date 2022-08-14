#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# virtiostat    Show virtio devices input/output statistics.
#               For Linux, uses BCC, eBPF.
#
# USAGE: virtiostat [-h] [-T] [-D] [-d DRIVER] [-n DEVNAME] [INTERVAL] [COUNT]
#
# Copyright (c) 2021 zhenwei pi
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 13-Feb-2021  zhenwei pi  Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse

# arguments
examples = """examples:
    ./virtiostat                 # print 3(default) second summaries
    ./virtiostat  1  10          # print 1 second summaries, 10 times
    ./virtiostat -T              # show timestamps
    ./virtiostat -d virtio_blk   # only show virtio block devices
    ./virtiostat -n virtio0      # only show virtio0 device
    ./virtiostat -D              # show debug bpf text
"""
parser = argparse.ArgumentParser(
    description="Show virtio devices input/output statistics",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("interval", nargs="?", default=3,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("-T", "--timestamp", action="store_true",
    help="show timestamp on output")
parser.add_argument("-d", "--driver",
    help="filter for driver name")
parser.add_argument("-n", "--devname",
    help="filter for device name")
parser.add_argument("-D", "--debug", action="store_true",
    help="print BPF program before starting (for debugging purposes)")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()

# define BPF program
bpf_text = """
#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "bcc"
#endif
#include <linux/virtio.h>
#include <bcc/proto.h>

/* typically virtio scsi has max SGs of 6 */
#define VIRTIO_MAX_SGS  6
/* typically virtio blk has max SEG of 128 */
#define SG_MAX          128

/* local strcmp function, max length 16 to protect instruction loops */
#define CMPMAX	16

static int local_strcmp(const char *cs, const char *ct)
{
    int len = 0;
    unsigned char c1, c2;

    while (len++ < CMPMAX) {
        c1 = *cs++;
        c2 = *ct++;
        if (c1 != c2)
            return c1 < c2 ? -1 : 1;
        if (!c1)
            break;
    }
    return 0;
}

typedef struct virtio_stat {
    char driver[16];
    char dev[12];
    char vqname[12];
    u32 in_sgs;
    u32 out_sgs;
    u64 in_bw;
    u64 out_bw;
} virtio_stat_t;

BPF_HASH(stats, u64, virtio_stat_t);

static struct scatterlist *__sg_next(struct scatterlist *sgp)
{
    struct scatterlist sg;

    bpf_probe_read_kernel(&sg, sizeof(sg), sgp);
    if (sg_is_last(&sg))
        return NULL;

    sgp++;

    bpf_probe_read_kernel(&sg, sizeof(sg), sgp);
    if (unlikely(sg_is_chain(&sg)))
        sgp = sg_chain_ptr(&sg);

    return sgp;
}

static u64 count_len(struct scatterlist **sgs, unsigned int num)
{
    u64 length = 0;
    unsigned int i, n;
    struct scatterlist *sgp = NULL;

    for (i = 0; (i < VIRTIO_MAX_SGS) && (i < num); i++) {
        for (n = 0, sgp = sgs[i]; sgp && (n < SG_MAX); sgp = __sg_next(sgp)) {
            length += sgp->length;
            n++;
        }

        /* Suggested by Yonghong Song:
         * IndVarSimplifyPass with clang 12 may cause verifier failure:
         *   ; for (i = 0; (i < VIRTIO_MAX_SGS) && (i < num); i++) { // Line  60
         *   90:   15 08 15 00 00 00 00 00 if r8 == 0 goto +21
         *   91:   bf 81 00 00 00 00 00 00 r1 = r8
         *   92:   07 01 00 00 ff ff ff ff r1 += -1
         *   93:   67 01 00 00 20 00 00 00 r1 <<= 32
         *   94:   77 01 00 00 20 00 00 00 r1 >>= 32
         *   95:   b7 02 00 00 05 00 00 00 r2 = 5
         *   96:   2d 12 01 00 00 00 00 00 if r2 > r1 goto +1
         *   97:   b7 08 00 00 06 00 00 00 r8 = 6
         *   98:   b7 02 00 00 00 00 00 00 r2 = 0
         *   99:   b7 09 00 00 00 00 00 00 r9 = 0
         *  100:   7b 8a 68 ff 00 00 00 00 *(u64 *)(r10 - 152) = r8
         *  101:   05 00 35 00 00 00 00 00 goto +53
         * Note that r1 is refined by r8 is saved to stack for later use.
         * This will give verifier u64_max loop bound and eventually cause
         * verification failure. Workaround with the below asm code.
         */
#if __clang_major__ >= 7
        asm volatile("" : "=r"(i) : "0"(i));
#endif
    }

    return length;
}

static void record(struct virtqueue *vq, struct scatterlist **sgs,
                   unsigned int out_sgs, unsigned int in_sgs)
{
    virtio_stat_t newvs = {0};
    virtio_stat_t *vs;
    u64 key = (u64)vq;
    u64 in_bw = 0;

    DRIVERFILTER
    DEVNAMEFILTER

    /* Workaround: separate two count_len() calls, one here and the
     * other below. Otherwise, compiler may generate some spills which
     * harms verifier pruning. This happens in llvm12, but not llvm4.
     * Below code works on both cases.
     */
    if (in_sgs)
        in_bw = count_len(sgs + out_sgs, in_sgs);

    vs = stats.lookup(&key);
    if (!vs) {
        bpf_probe_read_kernel_str(newvs.driver, sizeof(newvs.driver), vq->vdev->dev.driver->name);
        bpf_probe_read_kernel_str(newvs.dev, sizeof(newvs.dev), vq->vdev->dev.kobj.name);
        bpf_probe_read_kernel_str(newvs.vqname, sizeof(newvs.vqname), vq->name);
        newvs.out_sgs = out_sgs;
        newvs.in_sgs = in_sgs;
        if (out_sgs)
            newvs.out_bw = count_len(sgs, out_sgs);
        newvs.in_bw = in_bw;
        stats.update(&key, &newvs);
    } else {
        vs->out_sgs += out_sgs;
        vs->in_sgs += in_sgs;
        if (out_sgs)
            vs->out_bw += count_len(sgs, out_sgs);
        vs->in_bw += in_bw;
    }
}

int trace_virtqueue_add_sgs(struct pt_regs *ctx, struct virtqueue *vq,
                            struct scatterlist **sgs, unsigned int out_sgs,
                            unsigned int in_sgs, void *data, gfp_t gfp)

{
    record(vq, sgs, out_sgs, in_sgs);

    return 0;
}

int trace_virtqueue_add_outbuf(struct pt_regs *ctx, struct virtqueue *vq,
                              struct scatterlist *sg, unsigned int num,
                              void *data, gfp_t gfp)
{
    record(vq, &sg, 1, 0);

    return 0;
}

int trace_virtqueue_add_inbuf(struct pt_regs *ctx, struct virtqueue *vq,
                             struct scatterlist *sg, unsigned int num,
                             void *data, gfp_t gfp)
{
    record(vq, &sg, 0, 1);

    return 0;
}

int trace_virtqueue_add_inbuf_ctx(struct pt_regs *ctx, struct virtqueue *vq,
                                  struct scatterlist *sg, unsigned int num,
                                  void *data, void *_ctx, gfp_t gfp)
{
    record(vq, &sg, 0, 1);

    return 0;
}
"""

# filter for driver name
if args.driver:
    bpf_text = bpf_text.replace('DRIVERFILTER',
        """char filter_driver[] = \"%s\";
        char driver[16];
        bpf_probe_read_kernel_str(driver, sizeof(driver), vq->vdev->dev.driver->name);
        if (local_strcmp(filter_driver, driver))
        return;""" % (args.driver))
else:
    bpf_text = bpf_text.replace('DRIVERFILTER', '')

# filter for dev name
if args.devname:
    bpf_text = bpf_text.replace('DEVNAMEFILTER',
        """char filter_devname[] = \"%s\";
        char devname[16];
        bpf_probe_read_kernel_str(devname, sizeof(devname), vq->vdev->dev.kobj.name);
        if (local_strcmp(filter_devname, devname))
        return;""" % (args.devname))
else:
    bpf_text = bpf_text.replace('DEVNAMEFILTER', '')


# debug mode: print bpf text
if args.debug:
    print(bpf_text)

# dump mode: print bpf text and exit
if args.ebpf:
    print(bpf_text)
    exit()

# load BPF program
b = BPF(text=bpf_text)
b.attach_kprobe(event="virtqueue_add_sgs", fn_name="trace_virtqueue_add_sgs")
b.attach_kprobe(event="virtqueue_add_outbuf", fn_name="trace_virtqueue_add_outbuf")
b.attach_kprobe(event="virtqueue_add_inbuf", fn_name="trace_virtqueue_add_inbuf")
b.attach_kprobe(event="virtqueue_add_inbuf_ctx", fn_name="trace_virtqueue_add_inbuf_ctx")

print("Tracing virtio devices statistics ... Hit Ctrl-C to end.")

# start main loop
exiting = 0 if args.interval else 1
seconds = 0
while (1):
    try:
        sleep(int(args.interval))
        seconds = seconds + int(args.interval)
    except KeyboardInterrupt:
        exiting = 1

    if args.timestamp:
        print("%-8s\n" % strftime("%H:%M:%S"), end="")
    else:
        print("--------", end="\n")

    print("%14s %8s %10s %7s %7s %14s %14s" % ("Driver", "Device", "VQ Name", "In SGs", "Out SGs", "In BW", "Out BW"))
    stats = b.get_table("stats")
    for k, v in sorted(stats.items(), key=lambda vs: vs[1].dev):
        print("%14s %8s %10s %7d %7d %14d %14d" % (v.driver, v.dev, v.vqname, v.in_sgs, v.out_sgs, v.in_bw, v.out_bw))

    stats.clear()

    if exiting or seconds >= int(args.count):
        exit()
