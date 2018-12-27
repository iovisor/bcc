#!/usr/bin/env python

# Copyright (c) Barefoot Networks, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# Runs the compiler on all files in the 'testprograms' folder
# Writes outputs in the 'testoutputs' folder

from __future__ import print_function
from bcc import BPF
import os, sys
sys.path.append("../compiler") # To get hold of p4toEbpf
                               # We want to run it without installing it
import p4toEbpf
import os

def drop_extension(filename):
    return os.path.splitext(os.path.basename(filename))[0]

filesFailed = {}  # map error kind -> list[ (file, error) ]

def set_error(kind, file, error):
    if kind in filesFailed:
        filesFailed[kind].append((file, error))
    else:
        filesFailed[kind] = [(file, error)]

def is_root():
    # Is this code portable?
    return os.getuid() == 0

def main():
    testpath = "testprograms"
    destFolder = "testoutputs"
    files = os.listdir(testpath)
    files.sort()
    filesDone = 0
    errors = 0

    if not is_root():
        print("Loading EBPF programs requires root privilege.")
        print("Will only test compilation, not loading.")
        print("(Run with sudo to test program loading.)")

    for f in files:
        path = os.path.join(testpath, f)

        if not os.path.isfile(path):
            continue
        if not path.endswith(".p4"):
            continue

        destname = drop_extension(path) + ".c"
        destname = os.path.join(destFolder, destname)

        args = [path, "-o", destname]

        result = p4toEbpf.process(args)
        if result.kind != "OK":
            errors += 1
            print(path, result.error)
            set_error(result.kind, path, result.error)
        else:
            # Try to load the compiled function
            if is_root():
                try:
                    print("Compiling and loading BPF program")
                    b = BPF(src_file=destname, debug=0)
                    fn = b.load_func("ebpf_filter", BPF.SCHED_CLS)
                except Exception as e:
                    print(e)
                    set_error("BPF error", path, str(e))

        filesDone += 1

    print("Compiled", filesDone, "files", errors, "errors")
    for key in sorted(filesFailed):
        print(key, ":", len(filesFailed[key]), "programs")
        for v in filesFailed[key]:
            print("\t", v)
    exit(len(filesFailed) != 0)


if __name__ == "__main__":
    main()
