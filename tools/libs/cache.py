#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# libs.cache    helper methods common to BCC cache tools.
#
#
# Copyright (c) 2016-present, Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 25-Jul-2016   Emmanuel Bretelle first version

from __future__ import print_function

import re

from bcc import BPF


def compute_cache_stats(stats, debug=False):
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
    for k, v in stats.items():
        if not (type(k) == int or type(k) == long):
            k = k.ip

        if re.match('mark_page_accessed', BPF.ksym(k)) is not None:
            mpa = max(0, v.value)

        if re.match('mark_buffer_dirty', BPF.ksym(k)) is not None:
            mbd = max(0, v.value)

        if re.match('add_to_page_cache_lru', BPF.ksym(k)) is not None:
            apcl = max(0, v.value)

        if re.match('account_page_dirtied', BPF.ksym(k)) is not None:
            apd = max(0, apd)

        # access = total cache access incl. reads(mpa) and writes(mbd)
        # misses = total of add to lru which we do when we write(mbd)
        # and also the mark the page dirty(same as mbd)
        access = (mpa + mbd)
        misses = (apcl + apd)

        # rtaccess is the read hit % during the sample period.
        # wtaccess is the write hit % during the smaple period.
        if mpa > 0:
            rtaccess = float(mpa) / (access + misses)
        if apcl > 0:
            wtaccess = float(apcl) / (access + misses)

        if wtaccess != 0:
            whits = 100 * wtaccess
        if rtaccess != 0:
            rhits = 100 * rtaccess

    if debug:
        print("%d %d %d %d %d %d %f %f %d %d\n" % (
                mpa, mbd, apcl, apd, access, misses,
                rtaccess, wtaccess, rhits, whits))

    return (
        access, misses, mbd,
        rhits, whits
    )


def bpf_start(bpf_text):
    b = BPF(text=bpf_text)
    b.attach_kprobe(event="add_to_page_cache_lru", fn_name="do_count")
    b.attach_kprobe(event="mark_page_accessed", fn_name="do_count")
    b.attach_kprobe(event="account_page_dirtied", fn_name="do_count")
    b.attach_kprobe(event="mark_buffer_dirty", fn_name="do_count")
    return b
