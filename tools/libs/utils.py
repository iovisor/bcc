#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# libs.utils    Helper functions common to bcc tools.
#
# Copyright (c) 2016-present, Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 22-Jul-2016   Emmanuel Bretelle first version

import signal


# Function to gather data from /proc/meminfo
# return dictionary for quicker lookup of both values
def get_meminfo():
    result = {}

    for line in open('/proc/meminfo'):
        k = line.split(':', 3)
        v = k[1].split()
        result[k[0]] = int(v[0])
    return result


def handle_sigint():
    def _(signal, frame):
        pass
    # as cleanup can take many seconds, trap Ctrl-C:
    signal.signal(signal.SIGINT, _)
