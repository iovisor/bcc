#!/usr/bin/env python

from unittest import main, TestCase

from bcc import BPF

class TestIncrement(TestCase):
    def test_arbitrary_increment_simple(self):
        b = BPF(text=b"""
#include <uapi/linux/ptrace.h>
struct bpf_map;
BPF_HASH(map);
int map_delete(struct pt_regs *ctx, struct bpf_map *bpfmap, u64 *k) {
    map.increment(42, 10);
    return 0;
}
""")
        b.attach_kprobe(event=b"htab_map_delete_elem", fn_name=b"map_delete")
        b.cleanup()

if __name__ == "__main__":
    main()
