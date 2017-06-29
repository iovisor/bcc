# bcc Reference Guide

Intended for search (Ctrl-F) and reference. For tutorials, start with [tutorial.md](tutorial.md).

This guide is incomplete. If something feels missing, check the bcc and kernel source. And if you confirm we're missing something, please send a pull request to fix it, and help out everyone.

## Contents

- [BPF C](#bpf-c)
    - [Events & Arguments](#events--arguments)
        - [1. kprobes](#1-kprobes)
        - [2. kretprobes](#2-kretprobes)
        - [3. Tracepoints](#3-tracepoints)
        - [4. uprobes](#4-uprobes)
        - [5. uretprobes](#5-uretprobes)
        - [6. USDT probes](#6-usdt-probes)
    - [Data](#data)
        - [1. bpf_probe_read()](#1-bpf_probe_read)
        - [2. bpf_probe_read_str()](#2-bpf_probe_read_str)
        - [3. bpf_ktime_get_ns()](#3-bpf_ktime_get_ns)
        - [4. bpf_get_current_pid_tgid()](#4-bpf_get_current_pid_tgid)
        - [5. bpf_get_current_uid_gid()](#5-bpf_get_current_uid_gid)
        - [6. bpf_get_current_comm()](#6-bpf_get_current_comm)
        - [7. bpf_log2l()](#7-bpflog2l)
    - [Output](#output)
        - [1. bpf_trace_printk()](#1-bpf_trace_printk)
        - [2. BPF_PERF_OUTPUT](#2-bpf_perf_output)
        - [3. perf_submit()](#3-perf_submit)
    - [Maps](#maps)
        - [1. BPF_TABLE](#1-bpf_table)
        - [2. BPF_HASH](#2-bpf_hash)
        - [3. BPF_ARRAY](#3-bpf_array)
        - [4. BPF_HISTOGRAM](#4-bpf_histogram)
        - [5. BPF_STACK_TRACE](#5-bpf_stack_trace)
        - [6. BPF_PERF_ARRAY](#6-bpf_perf_array)
        - [7. BPF_PERCPU_ARRAY](#7-bpf_percpu_array)
        - [8. map.lookup()](#8-maplookup)
        - [9. map.lookup_or_init()](#9-maplookup_or_init)
        - [10. map.delete()](#10-mapdelete)
        - [11. map.update()](#11-mapupdate)
        - [12. map.insert()](#12-mapinsert)
        - [13. map.increment()](#13-mapincrement)
        - [14. map.get_stackid()](#14-mapget_stackid)
        - [15. map.perf_read()](#15-mapperf_read)

- [bcc Python](#bcc-python)
    - [Initialization](#initialization)
        - [1. BPF](#1-bpf)
        - [2. USDT](#2-usdt)
    - [Events](#events)
        - [1. attach_kprobe()](#1-attach_kprobe)
        - [2. attach_kretprobe()](#2-attach_kretprobe)
        - [3. attach_tracepoint()](#3-attach_tracepoint)
        - [4. attach_uprobe()](#4-attach_uprobe)
        - [5. attach_uretprobe()](#5-attach_uretprobe)
        - [6. USDT.enable_probe()](#6-usdtenable_probe)
    - [Debug Output](#debug-output)
        - [1. trace_print()](#1-trace_print)
        - [2. trace_fields()](#2-trace_fields)
    - [Output](#output)
        - [1. kprobe_poll()](#1-kprobe_poll)
    - [Maps](#maps)
        - [1. get_table()](#1-get_table)
        - [2. open_perf_buffer()](#2-open_perf_buffer)
        - [3. items()](#3-items)
        - [4. values()](#4-values)
        - [5. clear()](#5-clear)
        - [6. print_log2_hist()](#6-print_log2_hist)
        - [7. print_linear_hist()](#6-print_linear_hist)
    - [Helpers](#helpers)
        - [1. ksym()](#1-ksym)
        - [2. ksymname()](#2-ksymname)
        - [3. sym()](#3-sym)
        - [4. num_open_kprobes()](#4-num_open_kprobes)

- [BPF Errors](#bpf-errors)
    - [1. Invalid mem access](#1-invalid-mem-access)

# BPF C

This section describes the C part of a bcc program.

## Events & Arguments

### 1. kprobes

Syntax: kprobe__*kernel_function_name*

```kprobe__``` is a special prefix that creates a kprobe (dynamic tracing of a kernel function call) for the kernel function name provided as the remainder. You can also use kprobes by declaring a normal C function, then using the Python ```BPF.attach_kprobe()``` (covered later) to associate it with a kernel function.

Arguments are specified on the function declaration: kprobe__*kernel_function_name*(struct pt_regs *ctx [, *argument1* ...])

For example:

```C
int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
    [...]
}
```

This instruments the tcp_v4_connect() kernel function using a kprobe, with the following arguments:

- ```struct pt_regs *ctx```: Registers and BPF context.
- ```struct sock *sk```: First argument to tcp_v4_connect().

The first argument is always ```struct pt_regs *```, the remainder are the arguments to the function (they don't need to be specified, if you don't intend to use them).

Examples in situ:
[code](https://github.com/iovisor/bcc/blob/4afa96a71c5dbfc4c507c3355e20baa6c184a3a8/examples/tracing/tcpv4connect.py#L28) ([output](https://github.com/iovisor/bcc/blob/5bd0eb21fd148927b078deb8ac29fff2fb044b66/examples/tracing/tcpv4connect_example.txt#L8)),
[code](https://github.com/iovisor/bcc/commit/310ab53710cfd46095c1f6b3e44f1dbc8d1a41d8#diff-8cd1822359ffee26e7469f991ce0ef00R26) ([output](https://github.com/iovisor/bcc/blob/3b9679a3bd9b922c736f6061dc65cb56de7e0250/examples/tracing/bitehist_example.txt#L6))
<!--- I can't add search links here, since github currently cannot handle partial-word searches needed for "kprobe__" --->

### 2. kretprobes

Syntax: kretprobe__*kernel_function_name*

```kretprobe__``` is a special prefix that creates a kretprobe (dynamic tracing of a kernel function return) for the kernel function name provided as the remainder. You can also use kretprobes by declaring a normal C function, then using the Python ```BPF.attach_kretprobe()``` (covered later) to associate it with a kernel function.

Return value is available as ```PT_REGS_RC(ctx)```, given a function declaration of: kretprobe__*kernel_function_name*(struct pt_regs *ctx)

For example:

```C
int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    [...]
}
```

This instruments the return of the tcp_v4_connect() kernel function using a kretprobe, and stores the return value in ```ret```.

Examples in situ:
[code](https://github.com/iovisor/bcc/blob/4afa96a71c5dbfc4c507c3355e20baa6c184a3a8/examples/tracing/tcpv4connect.py#L38) ([output](https://github.com/iovisor/bcc/blob/5bd0eb21fd148927b078deb8ac29fff2fb044b66/examples/tracing/tcpv4connect_example.txt#L8))

### 3. Tracepoints

Syntax: TRACEPOINT_PROBE(*category*, *event*)

This is a macro that instruments the tracepoint defined by *category*:*event*.

Arguments are available in an ```args``` struct, which are the tracepoint arguments. One way to list these is to cat the relevant format file under /sys/kernel/debug/tracing/events/*category*/*event*/format.

For example:

```C
TRACEPOINT_PROBE(random, urandom_read) {
    // args is from /sys/kernel/debug/tracing/events/random/urandom_read/format
    bpf_trace_printk("%d\\n", args->got_bits);
    return 0;
}
```

This instruments the random:urandom_read tracepoint, and prints the tracepoint argument ```got_bits```.

Examples in situ:
[code](https://github.com/iovisor/bcc/blob/a4159da8c4ea8a05a3c6e402451f530d6e5a8b41/examples/tracing/urandomread.py#L19) ([output](https://github.com/iovisor/bcc/commit/e422f5e50ecefb96579b6391a2ada7f6367b83c4#diff-41e5ecfae4a3b38de5f4e0887ed160e5R10)),
[search /examples](https://github.com/iovisor/bcc/search?q=TRACEPOINT_PROBE+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=TRACEPOINT_PROBE+path%3Atools&type=Code)

### 4. uprobes

These are instrumented by declaring a normal function in C, then associating it as a uprobe probe in Python via ```BPF.attach_uprobe()``` (covered later).

Arguments can be examined using ```PT_REGS_PARM``` macros.

For example:

```C
int count(struct pt_regs *ctx) {
    char buf[64];
    bpf_probe_read(&buf, sizeof(buf), (void *)PT_REGS_PARM1(ctx));
    bpf_trace_printk("%s %d", buf, PT_REGS_PARM2(ctx));
    return(0);
}
```

This reads the first argument as a string, and then prints it with the second argument as an integer.

Examples in situ:
[code](https://github.com/iovisor/bcc/blob/4afa96a71c5dbfc4c507c3355e20baa6c184a3a8/examples/tracing/strlen_count.py#L26)

### 5. uretprobes

These are instrumented by declaring a normal function in C, then associating it as a uretprobe probe in Python via ```BPF.attach_uretprobe()``` (covered later).

Return value is available as ```PT_REGS_RC(ctx)```, given a function declaration of: *function_name*(struct pt_regs *ctx)

For example:

```C
BPF_HISTOGRAM(dist);
int count(struct pt_regs *ctx) {
    dist.increment(PT_REGS_RC(ctx));
    return 0;
}
```

This increments the bucket in the ```dist``` histogram that is indexed by the return value.

Examples in situ:
[code](https://github.com/iovisor/bcc/blob/4afa96a71c5dbfc4c507c3355e20baa6c184a3a8/examples/tracing/strlen_hist.py#L39) ([output](https://github.com/iovisor/bcc/blob/4afa96a71c5dbfc4c507c3355e20baa6c184a3a8/examples/tracing/strlen_hist.py#L15)),
[code](https://github.com/iovisor/bcc/blob/4afa96a71c5dbfc4c507c3355e20baa6c184a3a8/tools/bashreadline.py) ([output](https://github.com/iovisor/bcc/commit/aa87997d21e5c1a6a20e2c96dd25eb92adc8e85d#diff-2fd162f9e594206f789246ce97d62cf0R7))

### 6. USDT probes

These are User Statically-Defined Tracing (USDT) probes, which may be placed in some applications or libraries to provide a user-level equivalent of tracepoints. The primary BPF method provided for USDT support method is ```enable_probe()```. USDT probes are instrumented by declaring a normal function in C, then associating it as a USDT probe in Python via ```USDT.enable_probe()```.

Arguments can be read via: bpf_usdt_readarg(*index*, ctx, &addr)

For example:

```C
int do_trace(struct pt_regs *ctx) {
    uint64_t addr;
    char path[128];
    bpf_usdt_readarg(6, ctx, &addr);
    bpf_probe_read(&path, sizeof(path), (void *)addr);
    bpf_trace_printk("path:%s\\n", path);
    return 0;
};
```

This reads the sixth USDT argument, and then pulls it in as a string to ```path```.

Examples in situ:
[code](https://github.com/iovisor/bcc/commit/4f88a9401357d7b75e917abd994aa6ea97dda4d3#diff-04a7cad583be5646080970344c48c1f4R24),
[search /examples](https://github.com/iovisor/bcc/search?q=bpf_usdt_readarg+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=bpf_usdt_readarg+path%3Atools&type=Code)

## Data

### 1. bpf_probe_read()

Syntax: ```int bpf_probe_read(void *dst, int size, void *src)```

Return: 0 on success

This copies a memory location to the BPF stack, so that BPF can later operate on it. For safety, all memory reads must pass through bpf_probe_read(). This happens automatically in some cases, such as dereferencing kernel variables, as bcc will rewrite the BPF program to include the necessary bpf_probe_reads().

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=bpf_probe_read+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=bpf_probe_read+path%3Atools&type=Code)

### 2. bpf_probe_read_str()

Syntax: ```int bpf_probe_read_str(void *dst, int size, void *src)```

Return:
  - \> 0 length of the string including the trailing NUL on success
  - \< 0 error

This copies a `NULL` terminated string from memory location to BPF stack, so that BPF can later operate on it. In case the string length is smaller than size, the target is not padded with further `NULL` bytes. In case the string length is larger than size, just `size - 1` bytes are copied and the last byte is set to `NULL`.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=bpf_probe_read_str+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=bpf_probe_read_str+path%3Atools&type=Code)

### 3. bpf_ktime_get_ns()

Syntax: ```u64 bpf_ktime_get_ns(void)```

Return: current time in nanoseconds

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=bpf_ktime_get_ns+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=bpf_ktime_get_ns+path%3Atools&type=Code)

### 4. bpf_get_current_pid_tgid()

Syntax: ```u64 bpf_get_current_pid_tgid(void)```

Return: ```current->tgid << 32 | current->pid```

Returns the process ID in the lower 32 bits (kernel's view of the PID, which in user space is usually presented as the thread ID), and the thread group ID in the upper 32 bits (what user space often thinks of as the PID). By directly setting this to a u32, we discard the upper 32 bits.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=bpf_get_current_pid_tgid+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=bpf_get_current_pid_tgid+path%3Atools&type=Code)

### 5. bpf_get_current_uid_gid()

Syntax: ```u64 bpf_get_current_uid_gid(void)```

Return: ```current_gid << 32 | current_uid```

Returns the user ID and group IDs.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=bpf_get_current_uid_gid+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=bpf_get_current_uid_gid+path%3Atools&type=Code)

### 6. bpf_get_current_comm()

Syntax: ```bpf_get_current_comm(char *buf, int size_of_buf)```

Return: 0 on success

Populates the first argument address with the current process name. It should be a pointer to a char array of at least size TASK_COMM_LEN, which is defined in linux/sched.h. For example:

```C
#include <linux/sched.h>

int do_trace(struct pt_regs *ctx) {
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
[...]
```

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=bpf_get_current_comm+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=bpf_get_current_comm+path%3Atools&type=Code)

### 7. bpf_log2l()

Syntax: ```unsigned int bpf_log2l(unsigned long v)```

Returns the log-2 of the provided value. This is often used to create indexes for histograms, to construct power-of-2 histograms.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=bpf_log2l+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=bpf_log2l+path%3Atools&type=Code)

## Output

### 1. bpf_trace_printk()

Syntax: ```int bpf_trace_printk(const char *fmt, int fmt_size, ...)```

Return: 0 on success

A simple kernel facility for printf() to the common trace_pipe (/sys/kernel/debug/tracing/trace_pipe). This is ok for some quick examples, but has limitations: 3 args max, 1 %s only, and trace_pipe is globally shared, so concurrent programs will have clashing output. A better interface is via BPF_PERF_OUTPUT().

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=bpf_trace_printk+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=bpf_trace_printk+path%3Atools&type=Code)

### 2. BPF_PERF_OUTPUT

Syntax: ```BPF_PERF_OUTPUT(name)```

Creates a BPF table for pushing out custom event data to user space via a perf ring buffer. This is the preferred method for pushing per-event data to user space.

For example:

```C
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

int hello(struct pt_regs *ctx) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
```

The output table is named ```events```, and data is pushed to it via ```events.perf_submit()```.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=BPF_PERF_OUTPUT+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=BPF_PERF_OUTPUT+path%3Atools&type=Code)

### 3. perf_submit()

Syntax: ```int perf_submit((void *)ctx, (void *)data, u32 data_size)```

Return: 0 on success

A method of a BPF_PERF_OUTPUT table, for submitting custom event data to user space. See the BPF_PERF_OUTPUT entry. (This ultimately calls bpf_perf_event_output().)

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=perf_submit+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=perf_submit+path%3Atools&type=Code)

## Maps

Maps are BPF data stores, and are the basis for higher level object types including tables, hashes, and histograms.

### 1. BPF_TABLE

Syntax: ```BPF_TABLE(_table_type, _key_type, _leaf_type, _name, _max_entries)```

Creates a map named ```_name```. Most of the time this will be used via higher-level macros, like BPF_HASH, BPF_HIST, etc.

Methods (covered later): map.lookup(), map.lookup_or_init(), map.delete(), map.update(), map.insert(), map.increment().

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=BPF_TABLE+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=BPF_TABLE+path%3Atools&type=Code)

### 2. BPF_HASH

Syntax: ```BPF_HASH(name [, key_type [, leaf_type [, size]]])```

Creates a hash map (associative array) named ```name```, with optional parameters.

Defaults: ```BPF_HASH(name, key_type=u64, leaf_type=u64, size=10240)```

For example:

```C
BPF_HASH(start, struct request *);
```

This creates a hash named ```start``` where the key is a ```struct request *```, and the value defaults to u64. This hash is used by the disksnoop.py example for saving timestamps for each I/O request, where the key is the pointer to struct request, and the value is the timestamp.

Methods (covered later): map.lookup(), map.lookup_or_init(), map.delete(), map.update(), map.insert(), map.increment().

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=BPF_HASH+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=BPF_HASH+path%3Atools&type=Code)

### 3. BPF_ARRAY

Syntax: ```BPF_ARRAY(name [, leaf_type [, size]])```

Creates an int-indexed array which is optimized for fastest lookup and update, named ```name```, with optional parameters.

Defaults: ```BPF_ARRAY(name, leaf_type=u64, size=10240)```

For example:

```C
BPF_ARRAY(counts, u64, 32);
```

This creates an array named ```counts``` where with 32 buckets and 64-bit integer values. This array is used by the funccount.py example for saving call count of each function.

Methods (covered later): map.lookup(), map.update(), map.increment(). Note that all array elements are pre-allocated with zero values and can not be deleted.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=BPF_ARRAY+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=BPF_ARRAY+path%3Atools&type=Code)

### 4. BPF_HISTOGRAM

Syntax: ```BPF_HISTOGRAM(name [, key_type [, size ]])```

Creates a histogram map named ```name```, with optional parameters.

Defaults: ```BPF_HISTOGRAM(name, key_type=int, size=64)```

For example:

```C
BPF_HISTOGRAM(dist);
```

This creates a histogram named ```dist```, which defaults to 64 buckets indexed by keys of type int.

Methods (covered later): map.increment().

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=BPF_HISTOGRAM+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=BPF_HISTOGRAM+path%3Atools&type=Code)

### 5. BPF_STACK_TRACE

Syntax: ```BPF_STACK_TRACE(name, max_entries)```

Creates stack trace map named ```name```, with a maximum entry count provided. These maps are used to store stack traces.

For example:

```C
BPF_STACK_TRACE(stack_traces, 1024);
```

This creates stack trace map named ```stack_traces```, with a maximum number of stack trace entries of 1024.

Methods (covered later): map.get_stackid().

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=BPF_STACK_TRACE+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=BPF_STACK_TRACE+path%3Atools&type=Code)

### 6. BPF_PERF_ARRAY

Syntax: ```BPF_PERF_ARRAY(name, max_entries)```

Creates perf array named ```name```, with a maximum entry count provided, which must be equal to the number of system cpus. These maps are used to fetch hardware performance counters.

For example:

```C
text="""
BPF_PERF_ARRAY(cpu_cycles, NUM_CPUS);
"""
b = bcc.BPF(text=text, cflags=["-DNUM_CPUS=%d" % multiprocessing.cpu_count()])
b["cpu_cycles"].open_perf_event(b["cpu_cycles"].HW_CPU_CYCLES)
```

This creates a perf array named ```cpu_cycles```, with number of entries equal to the number of cpus/cores. The array is configured so that later calling map.perf_read() will return a hardware-calculated counter of the number of cycles elapsed from some point in the past. Only one type of hardware counter may be configured per table at a time.

Methods (covered later): map.perf_read().

Examples in situ:
[search /tests](https://github.com/iovisor/bcc/search?q=BPF_PERF_ARRAY+path%3Atests&type=Code)

### 7. BPF_PERCPU_ARRAY

Syntax: ```BPF_PERCPU_ARRAY(name [, leaf_type [, size]])```

Creates NUM_CPU int-indexed arrays which are optimized for fastest lookup and update, named ```name```, with optional parameters. Each CPU will have a separate copy of this array. The copies are not kept synchronized in any way.


Defaults: ```BPF_PERCPU_ARRAY(name, leaf_type=u64, size=10240)```

For example:

```C
BPF_PERCPU_ARRAY(counts, u64, 32);
```

This creates NUM_CPU arrays named ```counts``` where with 32 buckets and 64-bit integer values.

Methods (covered later): map.lookup(), map.update(), map.increment(). Note that all array elements are pre-allocated with zero values and can not be deleted.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=BPF_PERCPU_ARRAY+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=BPF_PERCPU_ARRAY+path%3Atools&type=Code)

### 8. map.lookup()

Syntax: ```*val map.lookup(&key)```

Lookup the key in the map, and return a pointer to its value if it exists, else NULL. We pass the key in as an address to a pointer.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=lookup+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=lookup+path%3Atools&type=Code)

### 9. map.lookup_or_init()

Syntax: ```*val map.lookup_or_init(&key, &zero)```

Lookup the key in the map, and return a pointer to its value if it exists, else initialize the key's value to the second argument. This is often used to initialize values to zero.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=lookup_or_init+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=lookup_or_init+path%3Atools&type=Code)

### 10. map.delete()

Syntax: ```map.delete(&key)```

Delete the key from the hash.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=delete+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=delete+path%3Atools&type=Code)

### 11. map.update()

Syntax: ```map.update(&key, &val)```

Associate the value in the second argument to the key, overwriting any previous value.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=update+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=update+path%3Atools&type=Code)

### 12. map.insert()

Syntax: ```map.insert(&key, &val)```

Associate the value in the second argument to the key, only if there was no previous value.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=insert+path%3Aexamples&type=Code)

### 13. map.increment()

Syntax: ```map.increment(key)```

Increments the key's value by one. Used for histograms.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=increment+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=increment+path%3Atools&type=Code)

### 14. map.get_stackid()

Syntax: ```int map.get_stackid(void *ctx, u64 flags)```

This walks the stack found via the struct pt_regs in ```ctx```, saves it in the stack trace map, and returns a unique ID for the stack trace.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=get_stackid+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=get_stackid+path%3Atools&type=Code)

### 15. map.perf_read()

Syntax: ```u64 map.perf_read(u32 cpu)```

This returns the hardware performance counter as configured in [5. BPF_PERF_ARRAY](#5-bpf_perf_array)

Examples in situ:
[search /tests](https://github.com/iovisor/bcc/search?q=perf_read+path%3Atests&type=Code)

# bcc Python

## Initialization

Constructors.

### 1. BPF

Syntax: ```BPF({text=BPF_program | src_file=filename} [, usdt_contexts=[USDT_object, ...]])```

Creates a BPF object. This is the main object for defining a BPF program, and interacting with its output.

Examples:

```Python
# define entire BPF program in one line:
BPF(text='int do_trace(void *ctx) { bpf_trace_printk("hit!\\n"); return 0; }');

# define program as a variable:
prog = """
int hello(void *ctx) {
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}
"""
b = BPF(text=prog)

# source a file:
b = BPF(src_file = "vfsreadlat.c")

# include a USDT object:
u = USDT(pid=int(pid))
[...]
b = BPF(text=bpf_text, usdt_contexts=[u])
```

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=BPF+path%3Aexamples+language%3Apython&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=BPF+path%3Atools+language%3Apython&type=Code)

### 2. USDT

Syntax: ```USDT({pid=pid | path=path})```

Creates an object to instrument User Statically-Defined Tracing (USDT) probes. Its primary method is ```enable_probe()```.

Arguments:

- pid: attach to this process ID.
- path: instrument USDT probes from this binary path.

Examples:

```Python
# include a USDT object:
u = USDT(pid=int(pid))
[...]
b = BPF(text=bpf_text, usdt_contexts=[u])
```

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=USDT+path%3Aexamples+language%3Apython&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=USDT+path%3Atools+language%3Apython&type=Code)

## Events

### 1. attach_kprobe()

Syntax: ```BPF.attach_kprobe(event="event", fn_name="name")```

Instruments the kernel function ```event()``` using kernel dynamic tracing of the function entry, and attaches our C defined function ```name()``` to be called when the kernel function is called.

For example:

```Python
b.attach_kprobe(event="sys_clone", fn_name="do_trace")
```

This will instrument the kernel ```sys_clone()``` function, which will then run our BPF defined ```do_trace()``` function each time it is called.

You can call attach_kprobe() more than once, and attach your BPF function to multiple kernel functions.

See the previous kprobes section for how to instrument arguments from BPF.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=attach_kprobe+path%3Aexamples+language%3Apython&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=attach_kprobe+path%3Atools+language%3Apython&type=Code)

### 2. attach_kretprobe()

Syntax: ```BPF.attach_kretprobe(event="event", fn_name="name")```

Instruments the return of the kernel function ```event()``` using kernel dynamic tracing of the function return, and attaches our C defined function ```name()``` to be called when the kernel function returns.

For example:

```Python
b.attach_kretprobe(event="vfs_read", fn_name="do_return")
```

This will instrument the kernel ```vfs_read()``` function, which will then run our BPF defined ```do_return()``` function each time it is called.

You can call attach_kretprobe() more than once, and attach your BPF function to multiple kernel function returns.

See the previous kretprobes section for how to instrument the return value from BPF.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=attach_kretprobe+path%3Aexamples+language%3Apython&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=attach_kretprobe+path%3Atools+language%3Apython&type=Code)

### 3. attach_tracepoint()

Syntax: ```BPF.attach_tracepoint(tp="tracepoint", fn_name="name")```

Instruments the kernel tracepoint described by ```tracepoint```, and when hit, runs the BPF function ```name()```.

This is an explicit way to instrument tracepoints. The ```TRACEPOINT_PROBE``` syntax, covered in the earlier tracepoints section, is an alternate method with the advantage of auto-declaring an ```args``` struct containing the tracepoint arguments. With ```attach_tracepoint()```, the tracepoint arguments need to be declared in the BPF program.

For example:

```Python
# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>

struct urandom_read_args {
    // from /sys/kernel/debug/tracing/events/random/urandom_read/format
    u64 __unused__;
    u32 got_bits;
    u32 pool_left;
    u32 input_left;
};

int printarg(struct urandom_read_args *args) {
    bpf_trace_printk("%d\\n", args->got_bits);
    return 0;
};
"""

# load BPF program
b = BPF(text=bpf_text)
b.attach_tracepoint("random:urandom_read", "printarg")
```

Notice how the first argument to ```printarg()``` is now our defined struct.

Examples in situ:
[code](https://github.com/iovisor/bcc/blob/a4159da8c4ea8a05a3c6e402451f530d6e5a8b41/examples/tracing/urandomread-explicit.py#L41)

### 4. attach_uprobe()

Syntax: ```BPF.attach_uprobe(name="location", sym="symbol", fn_name="name")```

Instruments the user-level function ```symbol()``` from either the library or binary named by ```location``` using user-level dynamic tracing of the function entry, and attach our C defined function ```name()``` to be called whenever the user-level function is called.

Libraries can be given in the name argument without the lib prefix, or with the full path (/usr/lib/...). Binaries can be given only with the full path (/bin/sh).

For example:

```Python
b.attach_uprobe(name="c", sym="strlen", fn_name="count")
```

This will instrument ```strlen()``` function from libc, and call our BPF function ```count()``` when it is called. Note how the "lib" in "libc" is not necessary to specify.

Other examples:

```Python
b.attach_uprobe(name="c", sym="getaddrinfo", fn_name="do_entry")
b.attach_uprobe(name="/usr/bin/python", sym="main", fn_name="do_main")
```

You can call attach_uprobe() more than once, and attach your BPF function to multiple user-level functions.

See the previous uprobes section for how to instrument arguments from BPF.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=attach_uprobe+path%3Aexamples+language%3Apython&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=attach_uprobe+path%3Atools+language%3Apython&type=Code)

### 5. attach_uretprobe()

Syntax: ```BPF.attach_uretprobe(name="location", sym="symbol", fn_name="name")```

Instruments the return of the user-level function ```symbol()``` from either the library or binary named by ```location``` using user-level dynamic tracing of the function return, and attach our C defined function ```name()``` to be called whenever the user-level function returns.

For example:

```Python
b.attach_uretprobe(name="c", sym="strlen", fn_name="count")
```

This will instrument ```strlen()``` function from libc, and call our BPF function ```count()``` when it returns.

Other examples:

```Python
b.attach_uprobe(name="c", sym="getaddrinfo", fn_name="do_entry")
b.attach_uprobe(name="/usr/bin/python", sym="main", fn_name="do_main")
```

You can call attach_uretprobe() more than once, and attach your BPF function to multiple user-level functions.

See the previous uretprobes section for how to instrument the return value from BPF.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=attach_uretprobe+path%3Aexamples+language%3Apython&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=attach_uretprobe+path%3Atools+language%3Apython&type=Code)

### 6. USDT.enable_probe()

Syntax: ```USDT.enable_probe(probe=probe, fn_name=name)```

Attaches a BPF C function ```name``` to the USDT probe ```probe```.

Example:

```Python
# enable USDT probe from given PID
u = USDT(pid=int(pid))
u.enable_probe(probe="http__server__request", fn_name="do_trace")
```

To check if your binary has USDT probes, and what they are, you can run ```readelf -n binary``` and check the stap debug section.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=enable_probe+path%3Aexamples+language%3Apython&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=enable_probe+path%3Atools+language%3Apython&type=Code)

## Debug Output

### 1. trace_print()

Syntax: ```BPF.trace_print(fmt="fields")```

This method continually reads the globally shared /sys/kernel/debug/tracing/trace_pipe file and prints its contents. This file can be written to via BPF and the bpf_trace_printk() function, however, that method has limitations, including a lack of concurrent tracing support. The BPF_PERF_OUTPUT mechanism, covered earlier, is preferred.

Arguments:

- ```fmt```: optional, and can contain a field formatting string. It defaults to ```None```.

Examples:

```Python
# print trace_pipe output as-is:
b.trace_print()

# print PID and message:
b.trace_print(fmt="{1} {5}")
```

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=trace_print+path%3Aexamples+language%3Apython&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=trace_print+path%3Atools+language%3Apython&type=Code)

### 2. trace_fields()

Syntax: ```BPF.trace_fields(nonblocking=False)```

This method reads one line from the globally shared /sys/kernel/debug/tracing/trace_pipe file and returns it as fields. This file can be written to via BPF and the bpf_trace_printk() function, however, that method has limitations, including a lack of concurrent tracing support. The BPF_PERF_OUTPUT mechanism, covered earlier, is preferred.

Arguments:

- ```nonblocking```: optional, defaults to ```False```. When set to ```True```, the program will not block waiting for input.

Examples:

```Python
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    [...]
```

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=trace_print+path%3Aexamples+language%3Apython&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=trace_print+path%3Atools+language%3Apython&type=Code)

## Output

Normal output from a BPF program is either:

- per-event: using PERF_EVENT_OUTPUT, open_perf_buffer(), and kprobe_poll().
- map summary: using items(), or print_log2_hist(), covered in the Maps section.

### 1. kprobe_poll()

Syntax: ```BPF.kprobe_poll()```

This polls from the ring buffers for all of the open kprobes, calling the callback function that was given in the BPF constructor for each entry, usually via ```open_perf_buffer()```.

Example:

```Python
# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    b.kprobe_poll()
```

Examples in situ:
[code](https://github.com/iovisor/bcc/blob/08fbceb7e828f0e3e77688497727c5b2405905fd/examples/tracing/hello_perf_output.py#L61),
[search /examples](https://github.com/iovisor/bcc/search?q=kprobe_poll+path%3Aexamples+language%3Apython&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=kprobe_poll+path%3Atools+language%3Apython&type=Code)

## Maps

Maps are BPF data stores, and are used in bcc to implement a table, and then higher level objects on top of tables, including hashes and histograms.

### 1. get_table()

Syntax: ```BPF.get_table(name)```

Returns a table object. This is no longer used, as tables can now be read as items from BPF. Eg: ```BPF[name]```.

Examples:

```Python
counts = b.get_table("counts")

counts = b["counts"]
```

These are equivalent.

### 2. open_perf_buffer()

Syntax: ```table.open_perf_buffers(callback, page_cnt=N, lost_cb=None)```

This operates on a table as defined in BPF as BPF_PERF_OUTPUT(), and associates the callback Python function ```callback``` to be called when data is available in the perf ring buffer. This is part of the recommended mechanism for transferring per-event data from kernel to user space. The size of the perf ring buffer can be specified via the ```page_cnt``` parameter, which must be a power of two number of pages and defaults to 8. If the callback is not processing data fast enough, some submitted data may be lost. ```lost_cb``` will be called to log / monitor the lost count. If ```lost_cb``` is the default ```None``` value, it will just print a line of message to ```stderr```.

Example:

```Python
# process event
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    [...]

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    b.kprobe_poll()
```

Note that the data structure transferred will need to be declared in C in the BPF program, and in Python. For example:

```C
// define output data structure in C
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
```

```Python
# define output data structure in Python
TASK_COMM_LEN = 16    # linux/sched.h
class Data(ct.Structure):
    _fields_ = [("pid", ct.c_ulonglong),
                ("ts", ct.c_ulonglong),
                ("comm", ct.c_char * TASK_COMM_LEN)]
```

Perhaps in a future bcc version, the Python data structure will be automatically generated from the C declaration.

Examples in situ:
[code](https://github.com/iovisor/bcc/blob/08fbceb7e828f0e3e77688497727c5b2405905fd/examples/tracing/hello_perf_output.py#L59),
[search /examples](https://github.com/iovisor/bcc/search?q=open_perf_buffer+path%3Aexamples+language%3Apython&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=open_perf_buffer+path%3Atools+language%3Apython&type=Code)

### 3. items()

Syntax: ```table.items()```

Returns an array of the keys in a table. This can be used with BPF_HASH maps to fetch, and iterate, over the keys.

Example:

```Python
# print output
print("%10s %s" % ("COUNT", "STRING"))
counts = b.get_table("counts")
for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
    print("%10d \"%s\"" % (v.value, k.c.encode('string-escape')))
```

This example also uses the ```sorted()``` method to sort by value.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=clear+items%3Aexamples+language%3Apython&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=clear+items%3Atools+language%3Apython&type=Code)

### 4. values()

Syntax: ```table.values()```

Returns an array of the values in a table.

### 5. clear()

Syntax: ```table.clear()```

Clears the table: deletes all entries.

Example:

```Python
# print map summary every second:
while True:
    time.sleep(1)
    print("%-8s\n" % time.strftime("%H:%M:%S"), end="")
    dist.print_log2_hist(sym + " return:")
    dist.clear()
```

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=clear+path%3Aexamples+language%3Apython&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=clear+path%3Atools+language%3Apython&type=Code)

### 6. print_log2_hist()

Syntax: ```table.print_log2_hist(val_type="value", section_header="Bucket ptr", section_print_fn=None)```

Prints a table as a log2 histogram in ASCII. The table must be stored as log2, which can be done using the BPF function ```bpf_log2l()```.

Arguments:

- val_type: optional, column header.
- section_header: if the histogram has a secondary key, multiple tables will print and section_header can be used as a header description for each.
- section_print_fn: if section_print_fn is not None, it will be passed the bucket value.

Example:

```Python
b = BPF(text="""
BPF_HISTOGRAM(dist);

int kprobe__blk_account_io_completion(struct pt_regs *ctx, struct request *req)
{
	dist.increment(bpf_log2l(req->__data_len / 1024));
	return 0;
}
""")
[...]

b["dist"].print_log2_hist("kbytes")
```

Output:

```
     kbytes          : count     distribution
       0 -> 1        : 3        |                                      |
       2 -> 3        : 0        |                                      |
       4 -> 7        : 211      |**********                            |
       8 -> 15       : 0        |                                      |
      16 -> 31       : 0        |                                      |
      32 -> 63       : 0        |                                      |
      64 -> 127      : 1        |                                      |
     128 -> 255      : 800      |**************************************|
```

This output shows a multi-modal distribution, with the largest mode of 128->255 kbytes and a count of 800.

This is an efficient way to summarize data, as the summarization is performed in-kernel, and only the count column is passed to user space.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=print_log2_hist+path%3Aexamples+language%3Apython&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=print_log2_hist+path%3Atools+language%3Apython&type=Code)

### 6. print_linear_hist()

Syntax: ```table.print_linear_hist(val_type="value", section_header="Bucket ptr", section_print_fn=None)```

Prints a table as a linear histogram in ASCII. This is intended to visualize small integer ranges, eg, 0 to 100.

Arguments:

- val_type: optional, column header.
- section_header: if the histogram has a secondary key, multiple tables will print and section_header can be used as a header description for each.
- section_print_fn: if section_print_fn is not None, it will be passed the bucket value.

Example:

```Python
b = BPF(text="""
BPF_HISTOGRAM(dist);

int kprobe__blk_account_io_completion(struct pt_regs *ctx, struct request *req)
{
	dist.increment(req->__data_len / 1024);
	return 0;
}
""")
[...]

b["dist"].print_linear_hist("kbytes")
```

Output:

```
     kbytes        : count     distribution
        0          : 3        |******                                  |
        1          : 0        |                                        |
        2          : 0        |                                        |
        3          : 0        |                                        |
        4          : 19       |****************************************|
        5          : 0        |                                        |
        6          : 0        |                                        |
        7          : 0        |                                        |
        8          : 4        |********                                |
        9          : 0        |                                        |
        10         : 0        |                                        |
        11         : 0        |                                        |
        12         : 0        |                                        |
        13         : 0        |                                        |
        14         : 0        |                                        |
        15         : 0        |                                        |
        16         : 2        |****                                    |
[...]
```

This is an efficient way to summarize data, as the summarization is performed in-kernel, and only the values in the count column are passed to user space.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=print_linear_hist+path%3Aexamples+language%3Apython&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=print_linear_hist+path%3Atools+language%3Apython&type=Code)

## Helpers

Some helper methods provided by bcc. Note that since we're in Python, we can import any Python library and their methods, including, for example, the libraries: argparse, collections, ctypes, datetime, re, socket, struct, subprocess, sys, and time.

### 1. ksym()

Syntax: ```BPF.ksym(addr)```

Translate a kernel memory address into a kernel function name, which is returned.

Example:

```Python
print("kernel function: " + b.ksym(addr))
```

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=ksym+path%3Aexamples+language%3Apython&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=ksym+path%3Atools+language%3Apython&type=Code)

### 2. ksymname()

Syntax: ```BPF.ksymname(name)```

Translate a kernel name into an address. This is the reverse of ksym. Returns -1 when the function name is unknown.

Example:

```Python
print("kernel address: %x" % b.ksymname("vfs_read"))
```

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=ksymname+path%3Aexamples+language%3Apython&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=ksymname+path%3Atools+language%3Apython&type=Code)

### 3. sym()

Syntax: ```BPF.sym(addr, pid, show_module=False, show_offset=False)```

Translate a memory address into a function name for a pid, which is returned. A pid of less than zero will access the kernel symbol cache. The `show_module` and `show_offset` parameters control whether the module in which the symbol lies should be displayed, and whether the instruction offset from the beginning of the symbol should be displayed. These extra parameters default to `False`.

Example:

```Python
print("function: " + b.sym(addr, pid))
```

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=sym+path%3Aexamples+language%3Apython&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=sym+path%3Atools+language%3Apython&type=Code)

### 4. num_open_kprobes()

Syntax: ```BPF.num_open_kprobes()```

Returns the number of open k[ret]probes. Can be useful for scenarios where event_re is used while attaching and detaching probes. Excludes perf_events readers.

Example:

```Python
b.attach_kprobe(event_re=pattern, fn_name="trace_count")
matched = b.num_open_kprobes()
if matched == 0:
    print("0 functions matched by \"%s\". Exiting." % args.pattern)
    exit()
```

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=num_open_kprobes+path%3Aexamples+language%3Apython&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=num_open_kprobes+path%3Atools+language%3Apython&type=Code)

# BPF Errors

See the "Understanding eBPF verifier messages" section in the kernel source under Documentation/networking/filter.txt.

## 1. Invalid mem access

This can be due to trying to read memory directly, instead of operating on memory on the BPF stack. All memory reads must be passed via bpf_probe_read() to copy memory into the BPF stack, which can be automatic by the bcc rewriter in some cases of simple dereferencing. bpf_probe_read() does all the required checks.

Example:

```
bpf: Permission denied
0: (bf) r6 = r1
1: (79) r7 = *(u64 *)(r6 +80)
2: (85) call 14
3: (bf) r8 = r0
[...]
23: (69) r1 = *(u16 *)(r7 +16)
R7 invalid mem access 'inv'

Traceback (most recent call last):
  File "./tcpaccept", line 179, in <module>
    b = BPF(text=bpf_text)
  File "/usr/lib/python2.7/dist-packages/bcc/__init__.py", line 172, in __init__
    self._trace_autoload()
  File "/usr/lib/python2.7/dist-packages/bcc/__init__.py", line 612, in _trace_autoload
    fn = self.load_func(func_name, BPF.KPROBE)
  File "/usr/lib/python2.7/dist-packages/bcc/__init__.py", line 212, in load_func
    raise Exception("Failed to load BPF program %s" % func_name)
Exception: Failed to load BPF program kretprobe__inet_csk_accept
```
