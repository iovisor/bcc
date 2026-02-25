#!/usr/bin/env python
# Path related helper functions
#
# Copyright (c) 2025 Rong Tao
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 30-Jun-2025   Rong Tao        Created this.

import os

def full_path_split_names(str, name_max=255, max_entries=32):
    name_max = 255
    max_entries = 32
    chunks = [str[i:i + name_max] for i in range(0, name_max * max_entries, name_max)]
    return [chunk.split(b'\x00', 1)[0] for chunk in chunks]


# parse full-path, see tools/full_path.h
def get_full_path(name, depth, name_max=255, max_entries=32):
    names = full_path_split_names(bytes(name), name_max, max_entries)
    picked = names[:depth + 1]
    picked_str = []
    for x in picked:
        s = x.decode('utf-8', 'ignore') if isinstance(x, bytes) else str(x)
        # remove mountpoint '/' and empty string
        if s != "/" and s != "":
            picked_str.append(s)
    joined = '/'.join(picked_str[::-1])
    result = joined if joined.startswith('/') else '/' + joined
    return result
