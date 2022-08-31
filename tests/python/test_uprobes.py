#!/usr/bin/env python3
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

import bcc
import ctypes
import errno
import os
import subprocess
import shutil
import time
import unittest

class TestUprobes(unittest.TestCase):
    def test_simple_library(self):
        text = b"""
#include <uapi/linux/ptrace.h>
BPF_ARRAY(stats, u64, 1);
static void incr(int idx) {
    u64 *ptr = stats.lookup(&idx);
    if (ptr)
        ++(*ptr);
}
int count(struct pt_regs *ctx) {
    bpf_trace_printk("count() uprobe fired");
    u32 pid = bpf_get_current_pid_tgid();
    if (pid == PID)
        incr(0);
    return 0;
}"""
        test_pid = os.getpid()
        text = text.replace(b"PID", b"%d" % test_pid)
        b = bcc.BPF(text=text)
        b.attach_uprobe(name=b"c", sym=b"malloc_stats", fn_name=b"count", pid=test_pid)
        b.attach_uretprobe(name=b"c", sym=b"malloc_stats", fn_name=b"count", pid=test_pid)
        libc = ctypes.CDLL("libc.so.6")
        libc.malloc_stats.restype = None
        libc.malloc_stats.argtypes = []
        libc.malloc_stats()
        self.assertEqual(b[b"stats"][ctypes.c_int(0)].value, 2)
        b.detach_uretprobe(name=b"c", sym=b"malloc_stats", pid=test_pid)
        b.detach_uprobe(name=b"c", sym=b"malloc_stats", pid=test_pid)

    def test_simple_binary(self):
        text = b"""
#include <uapi/linux/ptrace.h>
BPF_ARRAY(stats, u64, 1);
static void incr(int idx) {
    u64 *ptr = stats.lookup(&idx);
    if (ptr)
        ++(*ptr);
}
int count(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    incr(0);
    return 0;
}"""
        b = bcc.BPF(text=text)
        pythonpath = b"/usr/bin/python3"
        symname = b"_start"
        b.attach_uprobe(name=pythonpath, sym=symname, fn_name=b"count")
        b.attach_uretprobe(name=pythonpath, sym=symname, fn_name=b"count")
        with os.popen(pythonpath.decode() + " -V") as f:
            pass
        self.assertGreater(b[b"stats"][ctypes.c_int(0)].value, 0)
        b.detach_uretprobe(name=pythonpath, sym=symname)
        b.detach_uprobe(name=pythonpath, sym=symname)

    def test_mount_namespace(self):
        text = b"""
#include <uapi/linux/ptrace.h>
BPF_TABLE("array", int, u64, stats, 1);
static void incr(int idx) {
    u64 *ptr = stats.lookup(&idx);
    if (ptr)
        ++(*ptr);
}
int count(struct pt_regs *ctx) {
    bpf_trace_printk("count() uprobe fired");
    u32 pid = bpf_get_current_pid_tgid();
    if (pid == PID)
        incr(0);
    return 0;
}"""
        # Need to import libc from ctypes to access unshare(2)
        libc = ctypes.CDLL("libc.so.6", use_errno=True)

        # Need to find path to libz.so.1
        libz_path = None
        p = subprocess.Popen(["ldconfig", "-p"], stdout=subprocess.PIPE)
        for l in p.stdout:
            n = l.split()
            if n[0] == b"libz.so.1":
                # if libz was already found, override only if new lib is more
                # specific (e.g. libc6,x86-64 vs libc6)
                if not libz_path or len(n[1].split(b",")) > 1:
                    libz_path = n[-1]
        p.wait()
        p.stdout.close()
        p = None

        self.assertIsNotNone(libz_path)

        # fork a child that we'll place in a separate mount namespace
        child_pid = os.fork()
        if child_pid == 0:
            # Unshare CLONE_NEWNS
            if libc.unshare(0x00020000) == -1:
                e = ctypes.get_errno()
                raise OSError(e, errno.errorcode[e])

            # Remount root MS_REC|MS_PRIVATE
            if libc.mount(None, b"/", None, (1<<14)|(1<<18) , None) == -1:
                e = ctypes.get_errno()
                raise OSError(e, errno.errorcode[e])

            if libc.mount(b"tmpfs", b"/tmp", b"tmpfs", 0, None) == -1:
                e = ctypes.get_errno()
                raise OSError(e, errno.errorcode[e])

            shutil.copy(libz_path, b"/tmp")

            libz = ctypes.CDLL("/tmp/libz.so.1")
            time.sleep(3)
            libz.zlibVersion()
            time.sleep(5)
            os._exit(0)

        libname = b"/tmp/libz.so.1"
        symname = b"zlibVersion"
        text = text.replace(b"PID", b"%d" % child_pid)
        b = bcc.BPF(text=text)
        b.attach_uprobe(name=libname, sym=symname, fn_name=b"count", pid=child_pid)
        b.attach_uretprobe(name=libname, sym=symname, fn_name=b"count", pid=child_pid)
        time.sleep(5)
        self.assertEqual(b[b"stats"][ctypes.c_int(0)].value, 2)
        b.detach_uretprobe(name=libname, sym=symname, pid=child_pid)
        b.detach_uprobe(name=libname, sym=symname, pid=child_pid)
        os.wait()

if __name__ == "__main__":
    unittest.main()
