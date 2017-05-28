#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
import ctypes as ct
from unittest import main, TestCase
import os
import sys
from contextlib import contextmanager

@contextmanager
def redirect_stderr(to):
    stderr_fd = sys.stderr.fileno()
    with os.fdopen(os.dup(stderr_fd), 'wb') as copied, os.fdopen(to, 'w') as to:
        sys.stderr.flush()
        os.dup2(to.fileno(), stderr_fd)
        try:
            yield sys.stderr
        finally:
            sys.stderr.flush()
            os.dup2(copied.fileno(), stderr_fd)

class TestClang(TestCase):
    def test_complex(self):
        b = BPF(src_file="test_clang_complex.c", debug=0)
        fn = b.load_func("handle_packet", BPF.SCHED_CLS)
    def test_printk(self):
        text = """
#include <bcc/proto.h>
int handle_packet(void *ctx) {
  u8 *cursor = 0;
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  bpf_trace_printk("ethernet->dst = %llx, ethernet->src = %llx\\n",
                   ethernet->dst, ethernet->src);
  return 0;
}
"""
        b = BPF(text=text, debug=0)
        fn = b.load_func("handle_packet", BPF.SCHED_CLS)

    def test_probe_read1(self):
        text = """
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
int count_sched(struct pt_regs *ctx, struct task_struct *prev) {
    pid_t p = prev->pid;
    return (p != -1);
}
"""
        b = BPF(text=text, debug=0)
        fn = b.load_func("count_sched", BPF.KPROBE)

    def test_probe_read2(self):
        text = """
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
int count_foo(struct pt_regs *ctx, unsigned long a, unsigned long b) {
    return (a != b);
}
"""
        b = BPF(text=text, debug=0)
        fn = b.load_func("count_foo", BPF.KPROBE)

    def test_probe_read_keys(self):
        text = """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
BPF_HASH(start, struct request *);
int do_request(struct pt_regs *ctx, struct request *req) {
    u64 ts = bpf_ktime_get_ns();
    start.update(&req, &ts);
    return 0;
}

int do_completion(struct pt_regs *ctx, struct request *req) {
    u64 *tsp = start.lookup(&req);
    if (tsp != 0) {
        start.delete(&req);
    }
    return 0;
}
"""
        b = BPF(text=text, debug=0)
        fns = b.load_funcs(BPF.KPROBE)

    def test_sscanf(self):
        text = """
BPF_HASH(stats, int, struct { u64 a; u64 b; u64 c:36; u64 d:28; struct { u32 a; u32 b; } s; }, 10);
int foo(void *ctx) {
    return 0;
}
"""
        b = BPF(text=text, debug=0)
        fn = b.load_func("foo", BPF.KPROBE)
        t = b.get_table("stats")
        s1 = t.key_sprintf(t.Key(2))
        self.assertEqual(s1, b"0x2")
        s2 = t.leaf_sprintf(t.Leaf(2, 3, 4, 1, (5, 6)))
        l = t.leaf_scanf(s2)
        self.assertEqual(l.a, 2)
        self.assertEqual(l.b, 3)
        self.assertEqual(l.c, 4)
        self.assertEqual(l.d, 1)
        self.assertEqual(l.s.a, 5)
        self.assertEqual(l.s.b, 6)

    def test_sscanf_array(self):
        text = """
BPF_HASH(stats, int, struct { u32 a[3]; u32 b; }, 10);
"""
        b = BPF(text=text, debug=0)
        t = b.get_table("stats")
        s1 = t.key_sprintf(t.Key(2))
        self.assertEqual(s1, b"0x2")
        s2 = t.leaf_sprintf(t.Leaf((ct.c_uint * 3)(1,2,3), 4))
        self.assertEqual(s2, b"{ [ 0x1 0x2 0x3 ] 0x4 }")
        l = t.leaf_scanf(s2)
        self.assertEqual(l.a[0], 1)
        self.assertEqual(l.a[1], 2)
        self.assertEqual(l.a[2], 3)
        self.assertEqual(l.b, 4)

    def test_sscanf_string(self):
        text = """
struct Symbol {
    char name[128];
    char path[128];
};
struct Event {
    uint32_t pid;
    uint32_t tid;
    struct Symbol stack[64];
};
BPF_TABLE("array", int, struct Event, comms, 1);
"""
        b = BPF(text=text)
        t = b.get_table("comms")
        s1 = t.leaf_sprintf(t[0])
        fill = b' { "" "" }' * 63
        self.assertEqual(s1, b'{ 0x0 0x0 [ { "" "" }%s ] }' % fill)
        l = t.Leaf(1, 2)
        name = b"libxyz"
        path = b"/usr/lib/libxyz.so"
        l.stack[0].name = name
        l.stack[0].path = path
        s2 = t.leaf_sprintf(l)
        self.assertEqual(s2,
                b'{ 0x1 0x2 [ { "%s" "%s" }%s ] }' % (name, path, fill))
        l = t.leaf_scanf(s2)
        self.assertEqual(l.pid, 1)
        self.assertEqual(l.tid, 2)
        self.assertEqual(l.stack[0].name, name)
        self.assertEqual(l.stack[0].path, path)

    def test_iosnoop(self):
        text = """
#include <linux/blkdev.h>
#include <uapi/linux/ptrace.h>

struct key_t {
    struct request *req;
};

BPF_HASH(start, struct key_t, u64, 1024);
int do_request(struct pt_regs *ctx, struct request *req) {
    struct key_t key = {};

    bpf_trace_printk("traced start %d\\n", req->__data_len);

    return 0;
}
"""
        b = BPF(text=text, debug=0)
        fn = b.load_func("do_request", BPF.KPROBE)

    def test_blk_start_request(self):
        text = """
#include <linux/blkdev.h>
#include <uapi/linux/ptrace.h>
int do_request(struct pt_regs *ctx, int req) {
    bpf_trace_printk("req ptr: 0x%x\\n", req);
    return 0;
}
"""
        b = BPF(text=text, debug=0)
        fn = b.load_func("do_request", BPF.KPROBE)

    def test_bpf_hash(self):
        text = """
BPF_HASH(table1);
BPF_HASH(table2, u32);
BPF_HASH(table3, u32, int);
"""
        b = BPF(text=text, debug=0)

    def test_consecutive_probe_read(self):
        text = """
#include <linux/fs.h>
#include <linux/mount.h>
BPF_HASH(table1, struct super_block *);
int trace_entry(struct pt_regs *ctx, struct file *file) {
    if (!file) return 0;
    struct vfsmount *mnt = file->f_path.mnt;
    if (mnt) {
        struct super_block *k = mnt->mnt_sb;
        u64 zero = 0;
        table1.update(&k, &zero);
        k = mnt->mnt_sb;
        table1.update(&k, &zero);
    }

    return 0;
}
"""
        b = BPF(text=text, debug=0)
        fn = b.load_func("trace_entry", BPF.KPROBE)

    def test_nested_probe_read(self):
        text = """
#include <linux/fs.h>
int trace_entry(struct pt_regs *ctx, struct file *file) {
    if (!file) return 0;
    const char *name = file->f_path.dentry->d_name.name;
    bpf_trace_printk("%s\\n", name);
    return 0;
}
"""
        b = BPF(text=text, debug=0)
        fn = b.load_func("trace_entry", BPF.KPROBE)

    def test_char_array_probe(self):
        BPF(text="""#include <linux/blkdev.h>
int kprobe__blk_update_request(struct pt_regs *ctx, struct request *req) {
    bpf_trace_printk("%s\\n", req->rq_disk->disk_name);
    return 0;
}""")

    def test_probe_read_helper(self):
        b = BPF(text="""
#include <linux/fs.h>
static void print_file_name(struct file *file) {
    if (!file) return;
    const char *name = file->f_path.dentry->d_name.name;
    bpf_trace_printk("%s\\n", name);
}
static void print_file_name2(int unused, struct file *file) {
    print_file_name(file);
}
int trace_entry1(struct pt_regs *ctx, struct file *file) {
    print_file_name(file);
    return 0;
}
int trace_entry2(struct pt_regs *ctx, int unused, struct file *file) {
    print_file_name2(unused, file);
    return 0;
}
""")
        fn = b.load_func("trace_entry1", BPF.KPROBE)
        fn = b.load_func("trace_entry2", BPF.KPROBE)

    def test_probe_unnamed_union_deref(self):
        text = """
#include <linux/mm_types.h>
int trace(struct pt_regs *ctx, struct page *page) {
    void *p = page->mapping;
    return p != NULL;
}
"""
        # depending on llvm, compile may pass/fail, but at least shouldn't crash
        try:
            b = BPF(text=text)
        except:
            pass

    def test_probe_struct_assign(self):
        b = BPF(text = """
#include <uapi/linux/ptrace.h>
struct args_t {
    const char *filename;
    int flags;
    int mode;
};
int kprobe__sys_open(struct pt_regs *ctx, const char *filename,
        int flags, int mode) {
    struct args_t args = {};
    args.filename = filename;
    args.flags = flags;
    args.mode = mode;
    bpf_trace_printk("%s\\n", args.filename);
    return 0;
};
""")

    def test_task_switch(self):
        b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
struct key_t {
  u32 prev_pid;
  u32 curr_pid;
};
BPF_HASH(stats, struct key_t, u64, 1024);
int kprobe__finish_task_switch(struct pt_regs *ctx, struct task_struct *prev) {
  struct key_t key = {};
  u64 zero = 0, *val;
  key.curr_pid = bpf_get_current_pid_tgid();
  key.prev_pid = prev->pid;

  val = stats.lookup_or_init(&key, &zero);
  (*val)++;
  return 0;
}
""")

    def test_probe_simple_assign(self):
        b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/gfp.h>
struct leaf { size_t size; };
BPF_HASH(simple_map, u32, struct leaf);
int kprobe____kmalloc(struct pt_regs *ctx, size_t size) {
    u32 pid = bpf_get_current_pid_tgid();
    struct leaf* leaf = simple_map.lookup(&pid);
    if (leaf)
        leaf->size += size;
    return 0;
}""")

    def test_unop_probe_read(self):
        text = """
#include <linux/blkdev.h>
int trace_entry(struct pt_regs *ctx, struct request *req) {
    if (!(req->bio->bi_flags & 1))
        return 1;
    if (((req->bio->bi_flags)))
        return 1;
    return 0;
}
"""
        b = BPF(text=text)
        fn = b.load_func("trace_entry", BPF.KPROBE)

    def test_complex_leaf_types(self):
        text = """
struct list;
struct list {
  struct list *selfp;
  struct list *another_selfp;
  struct list *selfp_array[2];
};
struct empty {
};
union emptyu {
  struct empty *em1;
  struct empty em2;
  struct empty em3;
  struct empty em4;
};
BPF_ARRAY(t1, struct list, 1);
BPF_ARRAY(t2, struct list *, 1);
BPF_ARRAY(t3, union emptyu, 1);
"""
        b = BPF(text=text)
        self.assertEqual(ct.sizeof(b["t3"].Leaf), 8)

    def test_cflags(self):
        text = """
#ifndef MYFLAG
#error "MYFLAG not set as expected"
#endif
"""
        b = BPF(text=text, cflags=["-DMYFLAG"])

    def test_exported_maps(self):
        b1 = BPF(text="""BPF_TABLE_PUBLIC("hash", int, int, table1, 10);""")
        b2 = BPF(text="""BPF_TABLE("extern", int, int, table1, 10);""")

    def test_syntax_error(self):
        with self.assertRaises(Exception):
            b = BPF(text="""int failure(void *ctx) { if (); return 0; }""")

    def test_nested_union(self):
        text = """
BPF_HASH(t1, struct bpf_tunnel_key, int, 1);
"""
        b = BPF(text=text)
        t1 = b["t1"]
        print(t1.Key().remote_ipv4)

    def test_too_many_args(self):
        text = """
#include <uapi/linux/ptrace.h>
int many(struct pt_regs *ctx, int a, int b, int c, int d, int e, int f, int g) {
    return 0;
}
"""
        with self.assertRaises(Exception):
            b = BPF(text=text)

    def test_call_macro_arg(self):
        text = """
BPF_TABLE("prog", u32, u32, jmp, 32);

#define JMP_IDX_PIPE (1U << 1)

enum action {
    ACTION_PASS
};

int process(struct xdp_md *ctx) {
    jmp.call((void *)ctx, ACTION_PASS);
    jmp.call((void *)ctx, JMP_IDX_PIPE);
    return XDP_PASS;
}
        """
        b = BPF(text=text)
        t = b["jmp"]
        self.assertEquals(len(t), 32);

    def test_update_macro_arg(self):
        text = """
BPF_ARRAY(act, u32, 32);

#define JMP_IDX_PIPE (1U << 1)

enum action {
    ACTION_PASS
};

int process(struct xdp_md *ctx) {
    act.increment(ACTION_PASS);
    act.increment(JMP_IDX_PIPE);
    return XDP_PASS;
}
        """
        b = BPF(text=text)
        t = b["act"]
        self.assertEquals(len(t), 32);

    def test_bpf_dins_pkt_rewrite(self):
        text = """
#include <bcc/proto.h>
int dns_test(struct __sk_buff *skb) {
    u8 *cursor = 0;
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    if(ethernet->type == ETH_P_IP) {
        struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
        ip->src = ip->dst;
        return 0;
    }
    return -1;
}
        """
        b = BPF(text=text)

    def test_unary_operator(self):
        text = """
#include <linux/fs.h>
#include <uapi/linux/ptrace.h>
int trace_read_entry(struct pt_regs *ctx, struct file *file) {
    return !file->f_op->read_iter;
}
        """
        b = BPF(text=text)
        b.attach_kprobe(event="__vfs_read", fn_name="trace_read_entry")

    def test_printk_f(self):
        text = """
#include <uapi/linux/ptrace.h>
int trace_entry(struct pt_regs *ctx) {
  bpf_trace_printk("%0.2f\\n", 1);
  return 0;
}
"""
        r, w = os.pipe()
        with redirect_stderr(to=w):
            BPF(text=text)
        r = os.fdopen(r)
        output = r.read()
        expectedWarn = "warning: only %d %u %x %ld %lu %lx %lld %llu %llx %p %s conversion specifiers allowed"
        self.assertIn(expectedWarn, output)
        r.close()

    def test_printk_lf(self):
        text = """
#include <uapi/linux/ptrace.h>
int trace_entry(struct pt_regs *ctx) {
  bpf_trace_printk("%lf\\n", 1);
  return 0;
}
"""
        r, w = os.pipe()
        with redirect_stderr(to=w):
            BPF(text=text)
        r = os.fdopen(r)
        output = r.read()
        expectedWarn = "warning: only %d %u %x %ld %lu %lx %lld %llu %llx %p %s conversion specifiers allowed"
        self.assertIn(expectedWarn, output)
        r.close()

    def test_printk_2s(self):
        text = """
#include <uapi/linux/ptrace.h>
int trace_entry(struct pt_regs *ctx) {
  char s1[] = "hello", s2[] = "world";
  bpf_trace_printk("%s %s\\n", s1, s2);
  return 0;
}
"""
        r, w = os.pipe()
        with redirect_stderr(to=w):
            BPF(text=text)
        r = os.fdopen(r)
        output = r.read()
        expectedWarn = "warning: cannot use several %s conversion specifiers"
        self.assertIn(expectedWarn, output)
        r.close()

    def test_map_insert(self):
        text = """
BPF_HASH(dummy);
void do_trace(struct pt_regs *ctx) {
    u64 key = 0, val = 2;
    dummy.insert(&key, &val);
    key = 1;
    dummy.update(&key, &val);
}
"""
        b = BPF(text=text)
        c_val = ct.c_ulong(1)
        b["dummy"][ct.c_ulong(0)] = c_val
        b["dummy"][ct.c_ulong(1)] = c_val
        b.attach_kprobe(event="sys_sync", fn_name="do_trace")
        libc = ct.CDLL("libc.so.6")
        libc.sync()
        self.assertEqual(1, b["dummy"][ct.c_ulong(0)].value)
        self.assertEqual(2, b["dummy"][ct.c_ulong(1)].value)

    def test_prog_array_delete(self):
        text = """
BPF_TABLE("prog", int, int, dummy, 256);
"""
        b1 = BPF(text=text)
        text = """
int do_next(struct pt_regs *ctx) {
    return 0;
}
"""
        b2 = BPF(text=text)
        fn = b2.load_func("do_next", BPF.KPROBE)
        c_key = ct.c_int(0)
        b1["dummy"][c_key] = ct.c_int(fn.fd)
        b1["dummy"].__delitem__(c_key);
        with self.assertRaises(KeyError):
            b1["dummy"][c_key]

    def test_invalid_noninline_call(self):
        text = """
int bar(void) {
    return 0;
}
int foo(struct pt_regs *ctx) {
    return bar();
}
"""
        with self.assertRaises(Exception):
            b = BPF(text=text)


if __name__ == "__main__":
    main()
