local suite = require("test_helper")
local TestClang = {}

function TestClang:test_probe_read1()
  local text = [[
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
int count_sched(struct pt_regs *ctx, struct task_struct *prev) {
    pid_t p = prev->pid;
    return (p != -1);
}
]]
  local b = BPF:new{text=text, debug=0}
  local fn = b:load_func("count_sched", 'BPF_PROG_TYPE_KPROBE')
end

function TestClang:test_probe_read2()
  local text = [[
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
int count_foo(struct pt_regs *ctx, unsigned long a, unsigned long b) {
    return (a != b);
}
]]
  local b = BPF:new{text=text, debug=0}
  local fn = b:load_func("count_foo", 'BPF_PROG_TYPE_KPROBE')
end

function TestClang:test_probe_read_keys()
  local text = [[
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
  ]]
  local b = BPF:new{text=text, debug=0}
  local fns = b:load_funcs('BPF_PROG_TYPE_KPROBE')
end

function TestClang:test_sscanf()
  local text = [[
BPF_HASH(stats, int, struct { u64 a; u64 b; u32 c:18; u32 d:14; struct { u32 a; u32 b; } s; }, 10);

int foo(void *ctx) {
    return 0;
}
]]
  local b = BPF:new{text=text, debug=0}
  local fn = b:load_func("foo", 'BPF_PROG_TYPE_KPROBE')
  local t = b:get_table("stats")
  local s1 = t:key_sprintf(2)

  assert_equals(s1, "0x2")

  local s2 = t:leaf_sprintf({{2, 3, 4, 1, {5, 6}}})
  local l = t:leaf_scanf(s2)

  assert_equals(tonumber(l.a), 2)
  assert_equals(tonumber(l.b), 3)
  assert_equals(tonumber(l.c), 4)
  assert_equals(tonumber(l.d), 1)
  assert_equals(tonumber(l.s.a), 5)
  assert_equals(tonumber(l.s.b), 6)
end

function TestClang:test_sscanf_array()
  local text = [[ BPF_HASH(stats, int, struct { u32 a[3]; u32 b; }, 10); ]]

  local b = BPF:new{text=text, debug=0}
  local t = b:get_table("stats")

  local s1 = t:key_sprintf(2)
  assert_equals(s1, "0x2")

  local s2 = t:leaf_sprintf({{{1, 2, 3}, 4}})
  assert_equals(s2, "{ [ 0x1 0x2 0x3 ] 0x4 }")

  local l = t:leaf_scanf(s2)
  assert_equals(l.a[0], 1)
  assert_equals(l.a[1], 2)
  assert_equals(l.a[2], 3)
  assert_equals(l.b, 4)
end

function TestClang:test_iosnoop()
  local text = [[
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
]]

  local b = BPF:new{text=text, debug=0}
  local fn = b:load_func("do_request", 'BPF_PROG_TYPE_KPROBE')
end

function TestClang:test_blk_start_request()
  local text = [[
#include <linux/blkdev.h>
#include <uapi/linux/ptrace.h>
int do_request(struct pt_regs *ctx, int req) {
    bpf_trace_printk("req ptr: 0x%x\n", req);
    return 0;
}
]]
  local b = BPF:new{text=text, debug=0}
  local fn = b:load_func("do_request", 'BPF_PROG_TYPE_KPROBE')
end

function TestClang:test_bpf_hash()
  local text = [[
BPF_HASH(table1);
BPF_HASH(table2, u32);
BPF_HASH(table3, u32, int);
]]
  local b = BPF:new{text=text, debug=0}
end

function TestClang:test_consecutive_probe_read()
  local text = [[
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
]]
  local b = BPF:new{text=text, debug=0}
  local fn = b:load_func("trace_entry", 'BPF_PROG_TYPE_KPROBE')
end

function TestClang:test_nested_probe_read()
  local text = [[
#include <linux/fs.h>
int trace_entry(struct pt_regs *ctx, struct file *file) {
    if (!file) return 0;
    const char *name = file->f_path.dentry->d_name.name;
    bpf_trace_printk("%s\\n", name);
    return 0;
}
]]
  local b = BPF:new{text=text, debug=0}
  local fn = b:load_func("trace_entry", 'BPF_PROG_TYPE_KPROBE')
end

function TestClang:test_char_array_probe()
  local b = BPF:new{text=[[#include <linux/blkdev.h>
int kprobe__blk_update_request(struct pt_regs *ctx, struct request *req) {
    bpf_trace_printk("%s\\n", req->rq_disk->disk_name);
    return 0;
}]]}
end

function TestClang:test_probe_read_helper()
  local b = BPF:new{text=[[
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
]]}
  local fn1 = b:load_func("trace_entry1", 'BPF_PROG_TYPE_KPROBE')
  local fn2 = b:load_func("trace_entry2", 'BPF_PROG_TYPE_KPROBE')
end

function TestClang:test_probe_struct_assign()
  local b = BPF:new{text = [[
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
]]}
end

function TestClang:test_task_switch()
  local b = BPF:new{text=[[
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
]]}
end

function TestClang:test_probe_simple_assign()
  local b = BPF:new{text=[[
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
}]]}
end

function TestClang:test_unop_probe_read()
  local text = [[
#include <linux/blkdev.h>
int trace_entry(struct pt_regs *ctx, struct request *req) {
    if (!(req->bio->bi_flags & 1))
        return 1;
    if (((req->bio->bi_flags)))
        return 1;
    return 0;
}
]]
  local b = BPF:new{text=text}
  local fn = b:load_func("trace_entry", 'BPF_PROG_TYPE_KPROBE')
end

function TestClang:test_complex_leaf_types()
  local text = [[
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
]]
  local b = BPF:new{text=text}
  local ffi = require("ffi")

  -- TODO: ptrs?
  assert_equals(ffi.sizeof(b:get_table("t3").c_leaf), 8)
end

function TestClang:test_cflags()
  local text = [[
#ifndef MYFLAG
#error "MYFLAG not set as expected"
#endif
]]
  local b = BPF:new{text=text, cflags={"-DMYFLAG"}}
end

function TestClang:test_exported_maps()
  local b1 = BPF{text=[[BPF_TABLE_PUBLIC("hash", int, int, table1, 10);]]}
  local b2 = BPF{text=[[BPF_TABLE("extern", int, int, table1, 10);]]}
end

function TestClang:test_syntax_error()
  assert_error_msg_contains(
    "failed to compile BPF module",
    BPF.new,
    BPF, {text=[[int failure(void *ctx) { if (); return 0; }]]})
end

suite("TestClang", TestClang)
