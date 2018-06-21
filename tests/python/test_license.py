#!/usr/bin/env python
# Copyright (c) 2018 Clevernet, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

import unittest
from bcc import BPF

class TestLicense(unittest.TestCase):
    gpl_only_text = """
#include <uapi/linux/ptrace.h>
struct gpl_s {
    u64 ts;
};
BPF_PERF_OUTPUT(events);
int license_program(struct pt_regs *ctx) {
    struct gpl_s data = {};
    data.ts = bpf_ktime_get_ns();
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

    proprietary_text = """
#include <uapi/linux/ptrace.h>
struct key_t {
    u64 ip;
    u32 pid;
    u32 uid;
    char comm[16];
};

BPF_HASH(counts, struct key_t);

int license_program(struct pt_regs *ctx) {
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

    def license(self, lic):
        return '''
#define BPF_LICENSE %s
''' % (lic)

    def load_bpf_code(self, bpf_code):
        event_name = bpf_code.get_syscall_fnname("read")
        bpf_code.attach_kprobe(event=event_name, fn_name="license_program")
        bpf_code.detach_kprobe(event=event_name)

    def test_default(self):
        b = BPF(text=self.gpl_only_text)
        self.load_bpf_code(b)

    def test_gpl_helper_macro(self):
        b = BPF(text=self.gpl_only_text + self.license('GPL'))
        self.load_bpf_code(b)

    def test_proprietary_macro(self):
        b = BPF(text=self.proprietary_text + self.license('Proprietary'))
        self.load_bpf_code(b)

    def test_gpl_compatible_macro(self):
        b = BPF(text=self.gpl_only_text + self.license('Dual BSD/GPL'))
        self.load_bpf_code(b)

    def test_proprietary_words_macro(self):
        b = BPF(text=self.proprietary_text + self.license('Proprietary license'))
        self.load_bpf_code(b)

    @unittest.expectedFailure
    def test_cflags_fail(self):
        b = BPF(text=self.gpl_only_text, cflags=["-DBPF_LICENSE=GPL"])
        self.load_bpf_code(b)

    @unittest.expectedFailure
    def test_cflags_macro_fail(self):
        b = BPF(text=self.gpl_only_text + self.license('GPL'), cflags=["-DBPF_LICENSE=GPL"])
        self.load_bpf_code(b)

    @unittest.expectedFailure
    def test_empty_fail_macro(self):
        b = BPF(text=self.gpl_only_text + self.license(''))
        self.load_bpf_code(b)

    @unittest.expectedFailure
    def test_proprietary_fail_macro(self):
        b = BPF(text=self.gpl_only_text + self.license('Proprietary license'))
        self.load_bpf_code(b)

    @unittest.expectedFailure
    def test_proprietary_cflags_fail(self):
        b = BPF(text=self.proprietary_text, cflags=["-DBPF_LICENSE=Proprietary"])
        self.load_bpf_code(b)

if __name__ == "__main__":
    unittest.main()
