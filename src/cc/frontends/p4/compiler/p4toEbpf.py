#!/usr/bin/env python

# Copyright (c) Barefoot Networks, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# Compiler from P4 to EBPF
# (See http://www.slideshare.net/PLUMgrid/ebpf-and-linux-networking).
# This compiler in fact generates a C source file
# which can be compiled to EBPF using the LLVM compiler
# with the ebpf target.
#
# Main entry point.

import argparse
import os
import traceback
import sys
import target
from p4_hlir.main import HLIR
from ebpfProgram import EbpfProgram
from compilationException import *
from programSerializer import ProgramSerializer


def get_parser():
    parser = argparse.ArgumentParser(description='p4toEbpf arguments')
    parser.add_argument('source', metavar='source', type=str,
                        help='a P4 source file to compile')
    parser.add_argument('-g', dest='generated', default="router",
                        help="kind of output produced: filter or router")
    parser.add_argument('-o', dest='output_file', default="output.c",
                        help="generated C file name")
    return parser


def process(input_args):
    parser = get_parser()
    args, unparsed_args = parser.parse_known_args(input_args)

    has_remaining_args = False
    preprocessor_args = []
    for a in unparsed_args:
        if a[:2] == "-D" or a[:2] == "-I" or a[:2] == "-U":
            input_args.remove(a)
            preprocessor_args.append(a)
        else:
            has_remaining_args = True

    # trigger error
    if has_remaining_args:
        parser.parse_args(input_args)

    if args.generated == "router":
        isRouter = True
    elif args.generated == "filter":
        isRouter = False
    else:
        print("-g should be one of 'filter' or 'router'")

    print("*** Compiling ", args.source)
    return compileP4(args.source, args.output_file, isRouter, preprocessor_args)


class CompileResult(object):
    def __init__(self, kind, error):
        self.kind = kind
        self.error = error

    def __str__(self):
        if self.kind == "OK":
            return "Compilation successful"
        else:
            return "Compilation failed with error: " + self.error


def compileP4(inputFile, gen_file, isRouter, preprocessor_args):
    h = HLIR(inputFile)

    for parg in preprocessor_args:
        h.add_preprocessor_args(parg)
    if not h.build():
        return CompileResult("HLIR", "Error while building HLIR")

    try:
        basename = os.path.basename(inputFile)
        basename = os.path.splitext(basename)[0]

        config = target.BccConfig()
        e = EbpfProgram(basename, h, isRouter, config)
        serializer = ProgramSerializer()
        e.toC(serializer)
        f = open(gen_file, 'w')
        f.write(serializer.toString())
        return CompileResult("OK", "")
    except CompilationException, e:
        prefix = ""
        if e.isBug:
            prefix = "### Compiler bug: "
        return CompileResult("bug", prefix + e.show())
    except NotSupportedException, e:
        return CompileResult("not supported", e.show())
    except:
        return CompileResult("exception", traceback.format_exc())


# main entry point
if __name__ == "__main__":
    result = process(sys.argv[1:])
    if result.kind != "OK":
        print(str(result))
