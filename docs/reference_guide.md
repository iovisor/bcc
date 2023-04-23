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
        - [7. Raw Tracepoints](#7-raw-tracepoints)
        - [8. system call tracepoints](#8-system-call-tracepoints)
        - [9. kfuncs](#9-kfuncs)
        - [10. kretfuncs](#10-kretfuncs)
        - [11. lsm probes](#11-lsm-probes)
        - [12. bpf iterators](#12-bpf-iterators)
    - [Data](#data)
        - [1. bpf_probe_read_kernel()](#1-bpf_probe_read_kernel)
        - [2. bpf_probe_read_kernel_str()](#2-bpf_probe_read_kernel_str)
        - [3. bpf_ktime_get_ns()](#3-bpf_ktime_get_ns)
        - [4. bpf_get_current_pid_tgid()](#4-bpf_get_current_pid_tgid)
        - [5. bpf_get_current_uid_gid()](#5-bpf_get_current_uid_gid)
        - [6. bpf_get_current_comm()](#6-bpf_get_current_comm)
        - [7. bpf_get_current_task()](#7-bpf_get_current_task)
        - [8. bpf_log2l()](#8-bpf_log2l)
        - [9. bpf_get_prandom_u32()](#9-bpf_get_prandom_u32)
        - [10. bpf_probe_read_user()](#10-bpf_probe_read_user)
        - [11. bpf_probe_read_user_str()](#11-bpf_probe_read_user_str)
        - [12. bpf_get_ns_current_pid_tgid()](#12-bpf_get_ns_current_pid_tgid)
    - [Debugging](#debugging)
        - [1. bpf_override_return()](#1-bpf_override_return)
    - [Output](#output)
        - [1. bpf_trace_printk()](#1-bpf_trace_printk)
        - [2. BPF_PERF_OUTPUT](#2-bpf_perf_output)
        - [3. perf_submit()](#3-perf_submit)
        - [4. perf_submit_skb()](#4-perf_submit_skb)
        - [5. BPF_RINGBUF_OUTPUT](#5-bpf_ringbuf_output)
        - [6. ringbuf_output()](#6-ringbuf_output)
        - [7. ringbuf_reserve()](#7-ringbuf_reserve)
        - [8. ringbuf_submit()](#8-ringbuf_submit)
        - [9. ringbuf_discard()](#9-ringbuf_discard)
    - [Maps](#maps)
        - [1. BPF_TABLE](#1-bpf_table)
        - [2. BPF_HASH](#2-bpf_hash)
        - [3. BPF_ARRAY](#3-bpf_array)
        - [4. BPF_HISTOGRAM](#4-bpf_histogram)
        - [5. BPF_STACK_TRACE](#5-bpf_stack_trace)
        - [6. BPF_PERF_ARRAY](#6-bpf_perf_array)
        - [7. BPF_PERCPU_HASH](#7-bpf_percpu_hash)
        - [8. BPF_PERCPU_ARRAY](#8-bpf_percpu_array)
        - [9. BPF_LPM_TRIE](#9-bpf_lpm_trie)
        - [10. BPF_PROG_ARRAY](#10-bpf_prog_array)
        - [11. BPF_DEVMAP](#11-bpf_devmap)
        - [12. BPF_CPUMAP](#12-bpf_cpumap)
        - [13. BPF_XSKMAP](#13-bpf_xskmap)
        - [14. BPF_ARRAY_OF_MAPS](#14-bpf_array_of_maps)
        - [15. BPF_HASH_OF_MAPS](#15-bpf_hash_of_maps)
        - [16. BPF_STACK](#16-bpf_stack)
        - [17. BPF_QUEUE](#17-bpf_queue)
        - [18. BPF_SOCKHASH](#18-bpf_sockhash)
        - [19. map.lookup()](#19-maplookup)
        - [20. map.lookup_or_try_init()](#20-maplookup_or_try_init)
        - [21. map.delete()](#21-mapdelete)
        - [22. map.update()](#22-mapupdate)
        - [23. map.insert()](#23-mapinsert)
        - [24. map.increment()](#24-mapincrement)
        - [25. map.get_stackid()](#25-mapget_stackid)
        - [26. map.perf_read()](#26-mapperf_read)
        - [27. map.call()](#27-mapcall)
        - [28. map.redirect_map()](#28-mapredirect_map)
        - [29. map.push()](#29-mappush)
        - [30. map.pop()](#30-mappop)
        - [31. map.peek()](#31-mappeek)
        - [32. map.sock_hash_update()](#32-mapsock_hash_update)
        - [33. map.msg_redirect_hash()](#33-mapmsg_redirect_hash)
        - [34. map.sk_redirect_hash()](#34-mapsk_redirect_hash)
    - [Licensing](#licensing)
    - [Rewriter](#rewriter)

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
        - [7. attach_raw_tracepoint()](#7-attach_raw_tracepoint)
        - [8. attach_raw_socket()](#8-attach_raw_socket)
        - [9. attach_xdp()](#9-attach_xdp)
        - [10. attach_func()](#10-attach_func)
        - [11. detach_func()](#11-detach_func)
        - [12. detach_kprobe()](#12-detach_kprobe)
        - [13. detach_kretprobe()](#13-detach_kretprobe)
    - [Debug Output](#debug-output)
        - [1. trace_print()](#1-trace_print)
        - [2. trace_fields()](#2-trace_fields)
    - [Output APIs](#output-apis)
        - [1. perf_buffer_poll()](#1-perf_buffer_poll)
        - [2. ring_buffer_poll()](#2-ring_buffer_poll)
        - [3. ring_buffer_consume()](#3-ring_buffer_consume)
    - [Map APIs](#map-apis)
        - [1. get_table()](#1-get_table)
        - [2. open_perf_buffer()](#2-open_perf_buffer)
        - [3. items()](#3-items)
        - [4. values()](#4-values)
        - [5. clear()](#5-clear)
        - [6. items_lookup_and_delete_batch()](#6-items_lookup_and_delete_batch)
        - [7. items_lookup_batch()](#7-items_lookup_batch)
        - [8. items_delete_batch()](#8-items_delete_batch)
        - [9. items_update_batch()](#9-items_update_batch)
        - [10. print_log2_hist()](#10-print_log2_hist)
        - [11. print_linear_hist()](#11-print_linear_hist)
        - [12. open_ring_buffer()](#12-open_ring_buffer)
        - [13. push()](#13-push)
        - [14. pop()](#14-pop)
        - [15. peek()](#15-peek)
    - [Helpers](#helpers)
        - [1. ksym()](#1-ksym)
        - [2. ksymname()](#2-ksymname)
        - [3. sym()](#3-sym)
        - [4. num_open_kprobes()](#4-num_open_kprobes)
        - [5. get_syscall_fnname()](#5-get_syscall_fnname)

- [BPF Errors](#bpf-errors)
    - [1. Invalid mem access](#1-invalid-mem-access)
    - [2. Cannot call GPL only function from proprietary program](#2-cannot-call-gpl-only-function-from-proprietary-program)

- [Environment Variables](#Environment-Variables)
    - [1. kernel source directory](#1-kernel-source-directory)
    - [2. kernel version overriding](#2-kernel-version-overriding)

# BPF C

This section describes the C part of a bcc program.

## Events & Arguments

### 1. kprobes

Syntax: kprobe__*kernel_function_name*

```kprobe__``` is a special prefix that creates a kprobe (dynamic tracing of a kernel function call) for the kernel function name provided as the remainder. You can also use kprobes by declaring a normal C function, then using the Python ```BPF.attach_kprobe()``` (covered later) to associate it with a kernel function.

Arguments are specified on the function declaration: kprobe__*kernel_function_name*(struct pt_regs *ctx [, *argument1* ...])

For example:

```C
int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
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

The tracepoint name is `<category>:<event>`.
The probe function name is `tracepoint__<category>__<event>`.

Arguments are available in an ```args``` struct, which are the tracepoint arguments. One way to list these is to cat the relevant format file under /sys/kernel/debug/tracing/events/*category*/*event*/format.

The ```args``` struct can be used in place of ``ctx`` in each functions requiring a context as an argument. This includes notably [perf_submit()](#3-perf_submit).

For example:

```C
TRACEPOINT_PROBE(random, urandom_read) {
    // args is from /sys/kernel/debug/tracing/events/random/urandom_read/format
    bpf_trace_printk("%d\\n", args->got_bits);
    return 0;
}
```

This instruments the tracepoint `random:urandom_read tracepoint`, and prints the tracepoint argument ```got_bits```.
When using Python API, this probe is automatically attached to the right tracepoint target.
For C++, this tracepoint probe can be attached by specifying the tracepoint target and function name explicitly:
`BPF::attach_tracepoint("random:urandom_read", "tracepoint__random__urandom_read")`
Note the name of the probe function defined above is `tracepoint__random__urandom_read`.

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
    bpf_probe_read_user(&buf, sizeof(buf), (void *)PT_REGS_PARM1(ctx));
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
    bpf_probe_read_user(&path, sizeof(path), (void *)addr);
    bpf_trace_printk("path:%s\\n", path);
    return 0;
};
```

This reads the sixth USDT argument, and then pulls it in as a string to ```path```.

When initializing USDTs via the third argument of ```BPF::init``` in the C API, if any USDT fails to ```init```, entire ```BPF::init``` will fail. If you're OK with some USDTs failing to ```init```, use ```BPF::init_usdt``` before calling ```BPF::init```.

Examples in situ:
[code](https://github.com/iovisor/bcc/commit/4f88a9401357d7b75e917abd994aa6ea97dda4d3#diff-04a7cad583be5646080970344c48c1f4R24),
[search /examples](https://github.com/iovisor/bcc/search?q=bpf_usdt_readarg+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=bpf_usdt_readarg+path%3Atools&type=Code)

### 7. Raw Tracepoints

Syntax: RAW_TRACEPOINT_PROBE(*event*)

This is a macro that instruments the raw tracepoint defined by *event*.

The argument is a pointer to struct ```bpf_raw_tracepoint_args```, which is defined in [bpf.h](https://github.com/iovisor/bcc/blob/master/src/cc/compat/linux/virtual_bpf.h).  The struct field ```args``` contains all parameters of the raw tracepoint where you can found at linux tree [include/trace/events](https://github.com/torvalds/linux/tree/master/include/trace/events)
directory.

For example:
```C
RAW_TRACEPOINT_PROBE(sched_switch)
{
    // TP_PROTO(bool preempt, struct task_struct *prev, struct task_struct *next)
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *next= (struct task_struct *)ctx->args[2];
    s32 prev_tgid, next_tgid;

    bpf_probe_read_kernel(&prev_tgid, sizeof(prev->tgid), &prev->tgid);
    bpf_probe_read_kernel(&next_tgid, sizeof(next->tgid), &next->tgid);
    bpf_trace_printk("%d -> %d\\n", prev_tgid, next_tgid);
}
```

This instruments the sched:sched_switch tracepoint, and prints the prev and next tgid.

Examples in situ:
[search /tools](https://github.com/iovisor/bcc/search?q=RAW_TRACEPOINT_PROBE+path%3Atools&type=Code)

### 8. system call tracepoints

Syntax: ```syscall__SYSCALLNAME```

```syscall__``` is a special prefix that creates a kprobe for the system call name provided as the remainder. You can use it by declaring a normal C function, then using the Python ```BPF.get_syscall_fnname(SYSCALLNAME)``` and ```BPF.attach_kprobe()``` to associate it.

Arguments are specified on the function declaration: ```syscall__SYSCALLNAME(struct pt_regs *ctx, [, argument1 ...])```.

For example:
```C
int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    [...]
}
```

This instruments the execve system call.

The first argument is always ```struct pt_regs *```, the remainder are the arguments to the function (they don't need to be specified, if you don't intend to use them).

Corresponding Python code:
```Python
b = BPF(text=bpf_text)
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
```

Examples in situ:
[code](https://github.com/iovisor/bcc/blob/552658edda09298afdccc8a4b5e17311a2d8a771/tools/execsnoop.py#L101) ([output](https://github.com/iovisor/bcc/blob/552658edda09298afdccc8a4b5e17311a2d8a771/tools/execsnoop_example.txt#L8))

### 9. kfuncs

Syntax: KFUNC_PROBE(*function*, typeof(arg1) arg1, typeof(arg2) arge ...)
        MODULE_KFUNC_PROBE(*module*, *function*, typeof(arg1) arg1, typeof(arg2) arge ...)

This is a macro that instruments the kernel function via trampoline
*before* the function is executed. It's defined by *function* name and
the function arguments defined as *argX*.

For example:
```C
KFUNC_PROBE(do_sys_open, int dfd, const char *filename, int flags, int mode)
{
    ...
```

This instruments the do_sys_open kernel function and make its arguments
accessible as standard argument values.

Examples in situ:
[search /tools](https://github.com/iovisor/bcc/search?q=KFUNC_PROBE+path%3Atools&type=Code)

### 10. kretfuncs

Syntax: KRETFUNC_PROBE(*event*, typeof(arg1) arg1, typeof(arg2) arge ..., int ret)
        MODULE_KRETFUNC_PROBE(*module*, *function*, typeof(arg1) arg1, typeof(arg2) arge ...)

This is a macro that instruments the kernel function via trampoline
*after* the function is executed. It's defined by *function* name and
the function arguments defined as *argX*.

The last argument of the probe is the return value of the instrumented function.

For example:
```C
KRETFUNC_PROBE(do_sys_open, int dfd, const char *filename, int flags, int mode, int ret)
{
    ...
```

This instruments the do_sys_open kernel function and make its arguments
accessible as standard argument values together with its return value.

Examples in situ:
[search /tools](https://github.com/iovisor/bcc/search?q=KRETFUNC_PROBE+path%3Atools&type=Code)


### 11. LSM Probes

Syntax: LSM_PROBE(*hook*, typeof(arg1) arg1, typeof(arg2) arg2 ...)

This is a macro that instruments an LSM hook as a BPF program. It can be
used to audit security events and implement MAC security policies in BPF.
It is defined by specifying the hook name followed by its arguments.

Hook names can be found in
[include/linux/security.h](https://github.com/torvalds/linux/blob/v5.15/include/linux/security.h#L260)
by taking functions like `security_hookname` and taking just the `hookname` part.
For example, `security_bpf` would simply become `bpf`.

Unlike other BPF program types, the return value specified in an LSM probe
matters. A return value of 0 allows the hook to succeed, whereas
any non-zero return value will cause the hook to fail and deny the
security operation.

The following example instruments a hook that denies all future BPF operations:
```C
LSM_PROBE(bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
    return -EPERM;
}
```

This instruments the `security_bpf` hook and causes it to return `-EPERM`.
Changing `return -EPERM` to `return 0` would cause the BPF program
to allow the operation instead.

LSM probes require at least a 5.7+ kernel with the following configuation options set:
- `CONFIG_BPF_LSM=y`
- `CONFIG_LSM` comma separated string must contain "bpf" (for example,
  `CONFIG_LSM="lockdown,yama,bpf"`)

Examples in situ:
[search /tests](https://github.com/iovisor/bcc/search?q=LSM_PROBE+path%3Atests&type=Code)

### 12. BPF ITERATORS

Syntax: BPF_ITER(target)

This is a macro to define a program signature for a bpf iterator program. The argument *target* specifies what to iterate for the program.

Currently, kernel does not have interface to discover what targets are supported. A good place to find what is supported is in [tools/testing/selftests/bpf/prog_test/bpf_iter.c](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/prog_tests/bpf_iter.c) and some sample bpf iter programs are in [tools/testing/selftests/bpf/progs](https://github.com/torvalds/linux/tree/master/tools/testing/selftests/bpf/progs) with file name prefix *bpf_iter*.

The following example defines a program for target *task*, which traverses all tasks in the kernel.
```C
BPF_ITER(task)
{
  struct seq_file *seq = ctx->meta->seq;
  struct task_struct *task = ctx->task;

  if (task == (void *)0)
    return 0;

  ... task->pid, task->tgid, task->comm, ...
  return 0;
}
```

BPF iterators are introduced in 5.8 kernel for task, task_file, bpf_map, netlink_sock and ipv6_route . In 5.9, support is added to tcp/udp sockets and bpf map element (hashmap, arraymap and sk_local_storage_map) traversal.

## Data

### 1. bpf_probe_read_kernel()

Syntax: ```int bpf_probe_read_kernel(void *dst, int size, const void *src)```

Return: 0 on success

This copies size bytes from kernel address space to the BPF stack, so that BPF can later operate on it. For safety, all kernel memory reads must pass through bpf_probe_read_kernel(). This happens automatically in some cases, such as dereferencing kernel variables, as bcc will rewrite the BPF program to include the necessary bpf_probe_read_kernel().

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=bpf_probe_read_kernel+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=bpf_probe_read_kernel+path%3Atools&type=Code)

### 2. bpf_probe_read_kernel_str()

Syntax: ```int bpf_probe_read_kernel_str(void *dst, int size, const void *src)```

Return:
  - \> 0 length of the string including the trailing NULL on success
  - \< 0 error

This copies a `NULL` terminated string from kernel address space to the BPF stack, so that BPF can later operate on it. In case the string length is smaller than size, the target is not padded with further `NULL` bytes. In case the string length is larger than size, just `size - 1` bytes are copied and the last byte is set to `NULL`.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=bpf_probe_read_kernel_str+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=bpf_probe_read_kernel_str+path%3Atools&type=Code)

### 3. bpf_ktime_get_ns()

Syntax: ```u64 bpf_ktime_get_ns(void)```

Return: u64 number of nanoseconds. Starts at system boot time but stops during suspend.

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

### 7. bpf_get_current_task()

Syntax: ```bpf_get_current_task()```

Return: current task as a pointer to struct task_struct.

Returns a pointer to the current task's task_struct object. This helper can be used to compute the on-CPU time for a process, identify kernel threads, get the current CPU's run queue, or retrieve many other pieces of information.

With Linux 4.13, due to issues with field randomization, you may need two #define directives before the includes:
```C
#define randomized_struct_fields_start  struct {
#define randomized_struct_fields_end    };
#include <linux/sched.h>

int do_trace(void *ctx) {
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
[...]
```

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=bpf_get_current_task+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=bpf_get_current_task+path%3Atools&type=Code)

### 8. bpf_log2l()

Syntax: ```unsigned int bpf_log2l(unsigned long v)```

Returns the log-2 of the provided value. This is often used to create indexes for histograms, to construct power-of-2 histograms.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=bpf_log2l+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=bpf_log2l+path%3Atools&type=Code)

### 9. bpf_get_prandom_u32()

Syntax: ```u32 bpf_get_prandom_u32()```

Returns a pseudo-random u32.

Example in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=bpf_get_prandom_u32+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=bpf_get_prandom_u32+path%3Atools&type=Code)

### 10. bpf_probe_read_user()

Syntax: ```int bpf_probe_read_user(void *dst, int size, const void *src)```

Return: 0 on success

This attempts to safely read size bytes from user address space to the BPF stack, so that BPF can later operate on it. For safety, all user address space memory reads must pass through bpf_probe_read_user().

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=bpf_probe_read_user+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=bpf_probe_read_user+path%3Atools&type=Code)

### 11. bpf_probe_read_user_str()

Syntax: ```int bpf_probe_read_user_str(void *dst, int size, const void *src)```

Return:
  - \> 0 length of the string including the trailing NULL on success
  - \< 0 error

This copies a `NULL` terminated string from user address space to the BPF stack, so that BPF can later operate on it. In case the string length is smaller than size, the target is not padded with further `NULL` bytes. In case the string length is larger than size, just `size - 1` bytes are copied and the last byte is set to `NULL`.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=bpf_probe_read_user_str+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=bpf_probe_read_user_str+path%3Atools&type=Code)


### 12. bpf_get_ns_current_pid_tgid()

Syntax: ```u32 bpf_get_ns_current_pid_tgid(u64 dev, u64 ino, struct bpf_pidns_info* nsdata, u32 size)```

Values for *pid* and *tgid* as seen from the current *namespace* will be returned in *nsdata*.

Return 0 on success, or one of the following in case of failure:

- **-EINVAL** if dev and inum supplied don't match dev_t and inode number with nsfs of current task, or if dev conversion to dev_t lost high bits.

- **-ENOENT** if pidns does not exists for the current task.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=bpf_get_ns_current_pid_tgid+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=bpf_get_ns_current_pid_tgid+path%3Atools&type=Code)


## Debugging

### 1. bpf_override_return()

Syntax: ```int bpf_override_return(struct pt_regs *, unsigned long rc)```

Return: 0 on success

When used in a program attached to a function entry kprobe, causes the
execution of the function to be skipped, immediately returning `rc` instead.
This is used for targeted error injection.

bpf_override_return will only work when the kprobed function is whitelisted to
allow error injections. Whitelisting entails tagging a function with
`ALLOW_ERROR_INJECTION()` in the kernel source tree; see `io_ctl_init` for
an example. If the kprobed function is not whitelisted, the bpf program will
fail to attach with ` ioctl(PERF_EVENT_IOC_SET_BPF): Invalid argument`


```C
int kprobe__io_ctl_init(void *ctx) {
	bpf_override_return(ctx, -ENOMEM);
	return 0;
}
```

## Output

### 1. bpf_trace_printk()

Syntax: ```int bpf_trace_printk(const char *fmt, ...)```

Return: 0 on success

A simple kernel facility for printf() to the common trace_pipe (/sys/kernel/debug/tracing/trace_pipe). This is ok for some quick examples, but has limitations: 3 args max, 1 %s only, and trace_pipe is globally shared, so concurrent programs will have clashing output. A better interface is via BPF_PERF_OUTPUT(). Note that calling this helper is made simpler than the original kernel version, which has ```fmt_size``` as the second parameter.

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

The ```ctx``` parameter is provided in [kprobes](#1-kprobes) or [kretprobes](#2-kretprobes). For ```SCHED_CLS``` or ```SOCKET_FILTER``` programs, the ```struct __sk_buff *skb``` must be used instead.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=perf_submit+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=perf_submit+path%3Atools&type=Code)

### 4. perf_submit_skb()

Syntax: ```int perf_submit_skb((void *)ctx, u32 packet_size, (void *)data, u32 data_size)```

Return: 0 on success

A method of a BPF_PERF_OUTPUT table available in networking program types, for submitting custom event data to user space, along with the first ```packet_size``` bytes of the packet buffer. See the BPF_PERF_OUTPUT entry. (This ultimately calls bpf_perf_event_output().)

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=perf_submit_skb+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=perf_submit_skb+path%3Atools&type=Code)

### 5. BPF_RINGBUF_OUTPUT

Syntax: ```BPF_RINGBUF_OUTPUT(name, page_cnt)```

Creates a BPF table for pushing out custom event data to user space via a ringbuf ring buffer.
```BPF_RINGBUF_OUTPUT``` has several advantages over ```BPF_PERF_OUTPUT```, summarized as follows:

- Buffer is shared across all CPUs, meaning no per-CPU allocation
- Supports two APIs for BPF programs
    - ```map.ringbuf_output()``` works like ```map.perf_submit()``` (covered in [ringbuf_output](#6-ringbuf_output))
    - ```map.ringbuf_reserve()```/```map.ringbuf_submit()```/```map.ringbuf_discard()```
      split the process of reserving buffer space and submitting events into two steps
      (covered in [ringbuf_reserve](#7-ringbuf_reserve), [ringbuf_submit](#8-ringbuf_submit), [ringbuf_discard](#9-ringbuf_discard))
- BPF APIs do not require access to a CPU ctx argument
- Superior performance and latency in userspace thanks to a shared ring buffer manager
- Supports two ways of consuming data in userspace

Starting in Linux 5.8, this should be the preferred method for pushing per-event data to user space.

Example of both APIs:

```C
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};

// Creates a ringbuf called events with 8 pages of space, shared across all CPUs
BPF_RINGBUF_OUTPUT(events, 8);

int first_api_example(struct pt_regs *ctx) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.ringbuf_output(&data, sizeof(data), 0 /* flags */);

    return 0;
}

int second_api_example(struct pt_regs *ctx) {
    struct data_t *data = events.ringbuf_reserve(sizeof(struct data_t));
    if (!data) { // Failed to reserve space
        return 1;
    }

    data->pid = bpf_get_current_pid_tgid();
    data->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    events.ringbuf_submit(data, 0 /* flags */);

    return 0;
}
```

The output table is named ```events```. Data is allocated via ```events.ringbuf_reserve()``` and pushed to it via ```events.ringbuf_submit()```.

Examples in situ: <!-- TODO -->
[search /examples](https://github.com/iovisor/bcc/search?q=BPF_RINGBUF_OUTPUT+path%3Aexamples&type=Code),

### 6. ringbuf_output()

Syntax: ```int ringbuf_output((void *)data, u64 data_size, u64 flags)```

Return: 0 on success

Flags:
 - ```BPF_RB_NO_WAKEUP```: Do not sent notification of new data availability
 - ```BPF_RB_FORCE_WAKEUP```: Send notification of new data availability unconditionally

A method of the BPF_RINGBUF_OUTPUT table, for submitting custom event data to user space. This method works like ```perf_submit()```,
although it does not require a ctx argument.

Examples in situ: <!-- TODO -->
[search /examples](https://github.com/iovisor/bcc/search?q=ringbuf_output+path%3Aexamples&type=Code),

### 7. ringbuf_reserve()

Syntax: ```void* ringbuf_reserve(u64 data_size)```

Return: Pointer to data struct on success, NULL on failure

A method of the BPF_RINGBUF_OUTPUT table, for reserving space in the ring buffer and simultaenously
allocating a data struct for output. Must be used with one of ```ringbuf_submit``` or ```ringbuf_discard```.

Examples in situ: <!-- TODO -->
[search /examples](https://github.com/iovisor/bcc/search?q=ringbuf_reserve+path%3Aexamples&type=Code),

### 8. ringbuf_submit()

Syntax: ```void ringbuf_submit((void *)data, u64 flags)```

Return: Nothing, always succeeds

Flags:
 - ```BPF_RB_NO_WAKEUP```: Do not sent notification of new data availability
 - ```BPF_RB_FORCE_WAKEUP```: Send notification of new data availability unconditionally

A method of the BPF_RINGBUF_OUTPUT table, for submitting custom event data to user space. Must be preceded by a call to
```ringbuf_reserve()``` to reserve space for the data.

Examples in situ: <!-- TODO -->
[search /examples](https://github.com/iovisor/bcc/search?q=ringbuf_submit+path%3Aexamples&type=Code),

### 9. ringbuf_discard()

Syntax: ```void ringbuf_discard((void *)data, u64 flags)```

Return: Nothing, always succeeds

Flags:
 - ```BPF_RB_NO_WAKEUP```: Do not sent notification of new data availability
 - ```BPF_RB_FORCE_WAKEUP```: Send notification of new data availability unconditionally

A method of the BPF_RINGBUF_OUTPUT table, for discarding custom event data; userspace
ignores the data associated with the discarded event. Must be preceded by a call to
```ringbuf_reserve()``` to reserve space for the data.

Examples in situ: <!-- TODO -->
[search /examples](https://github.com/iovisor/bcc/search?q=ringbuf_submit+path%3Aexamples&type=Code),

### 10. ringbuf_query()

Syntax: ```u64 ringbuf_query(u64 flags)```

Return: Requested value, or 0, if flags are not recognized

Flags:
 - ```BPF_RB_AVAIL_DATA```: Amount of data not yet consumed
 - ```BPF_RB_RING_SIZE```: The size of ring buffer
 - ```BPF_RB_CONS_POS```: Consumer position
 - ```BPF_RB_PROD_POS```: Producer(s) position

A method of the BPF_RINGBUF_OUTPUT table, for getting various properties of ring buffer. Returned values are momentarily snapshots of ring buffer state and could be off by the time helper returns, so this should be used only for debugging/reporting reasons or for implementing various heuristics, that take into account highly-changeable nature of some of those characteristics.

Examples in situ: <!-- TODO -->
[search /examples](https://github.com/iovisor/bcc/search?q=ringbuf_query+path%3Aexamples&type=Code),

## Maps

Maps are BPF data stores, and are the basis for higher level object types including tables, hashes, and histograms.

### 1. BPF_TABLE

Syntax: ```BPF_TABLE(_table_type, _key_type, _leaf_type, _name, _max_entries)```

Creates a map named ```_name```. Most of the time this will be used via higher-level macros, like BPF_HASH, BPF_ARRAY, BPF_HISTOGRAM, etc.

`BPF_F_TABLE` is a variant that takes a flag in the last parameter. `BPF_TABLE(...)` is actually a wrapper to `BPF_F_TABLE(..., 0 /* flag */)`.

Methods (covered later): map.lookup(), map.lookup_or_try_init(), map.delete(), map.update(), map.insert(), map.increment().

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=BPF_TABLE+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=BPF_TABLE+path%3Atools&type=Code)

#### Pinned Maps

Syntax: ```BPF_TABLE_PINNED(_table_type, _key_type, _leaf_type, _name, _max_entries, "/sys/fs/bpf/xyz")```

Create a new map if it doesn't exist and pin it to the bpffs as a FILE, otherwise use the map that was pinned to the bpffs. The type information is not enforced and the actual map type depends on the map that got pinned to the location.

For example:

```C
BPF_TABLE_PINNED("hash", u64, u64, ids, 1024, "/sys/fs/bpf/ids");
```

### 2. BPF_HASH

Syntax: ```BPF_HASH(name [, key_type [, leaf_type [, size]]])```

Creates a hash map (associative array) named ```name```, with optional parameters.

Defaults: ```BPF_HASH(name, key_type=u64, leaf_type=u64, size=10240)```

For example:

```C
BPF_HASH(start, struct request *);
```

This creates a hash named ```start``` where the key is a ```struct request *```, and the value defaults to u64. This hash is used by the disksnoop.py example for saving timestamps for each I/O request, where the key is the pointer to struct request, and the value is the timestamp.

This is a wrapper macro for `BPF_TABLE("hash", ...)`.

Methods (covered later): map.lookup(), map.lookup_or_try_init(), map.delete(), map.update(), map.insert(), map.increment().

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

This is a wrapper macro for `BPF_TABLE("array", ...)`.

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

This is a wrapper macro for `BPF_TABLE("histgram", ...)`.

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

This is a wrapper macro for `BPF_TABLE("stacktrace", ...)`.

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

### 7. BPF_PERCPU_HASH

Syntax: ```BPF_PERCPU_HASH(name [, key_type [, leaf_type [, size]]])```

Creates NUM_CPU int-indexed hash maps (associative arrays) named ```name```, with optional parameters. Each CPU will have a separate copy of this array. The copies are not kept synchronized in any way.

Note that due to limits defined in the kernel (in linux/mm/percpu.c), the ```leaf_type``` cannot have a size of more than 32KB.
In other words, ```BPF_PERCPU_HASH``` elements cannot be larger than 32KB in size.


Defaults: ```BPF_PERCPU_HASH(name, key_type=u64, leaf_type=u64, size=10240)```

For example:

```C
BPF_PERCPU_HASH(start, struct request *);
```

This creates NUM_CPU hashes named ```start``` where the key is a ```struct request *```, and the value defaults to u64.

This is a wrapper macro for `BPF_TABLE("percpu_hash", ...)`.

Methods (covered later): map.lookup(), map.lookup_or_try_init(), map.delete(), map.update(), map.insert(), map.increment().

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=BPF_PERCPU_HASH+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=BPF_PERCPU_HASH+path%3Atools&type=Code)


### 8. BPF_PERCPU_ARRAY

Syntax: ```BPF_PERCPU_ARRAY(name [, leaf_type [, size]])```

Creates NUM_CPU int-indexed arrays which are optimized for fastest lookup and update, named ```name```, with optional parameters. Each CPU will have a separate copy of this array. The copies are not kept synchronized in any way.

Note that due to limits defined in the kernel (in linux/mm/percpu.c), the ```leaf_type``` cannot have a size of more than 32KB.
In other words, ```BPF_PERCPU_ARRAY``` elements cannot be larger than 32KB in size.


Defaults: ```BPF_PERCPU_ARRAY(name, leaf_type=u64, size=10240)```

For example:

```C
BPF_PERCPU_ARRAY(counts, u64, 32);
```

This creates NUM_CPU arrays named ```counts``` where with 32 buckets and 64-bit integer values.

This is a wrapper macro for `BPF_TABLE("percpu_array", ...)`.

Methods (covered later): map.lookup(), map.update(), map.increment(). Note that all array elements are pre-allocated with zero values and can not be deleted.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=BPF_PERCPU_ARRAY+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=BPF_PERCPU_ARRAY+path%3Atools&type=Code)

### 9. BPF_LPM_TRIE

Syntax: `BPF_LPM_TRIE(name [, key_type [, leaf_type [, size]]])`

Creates a longest prefix match trie map named `name`, with optional parameters.

Defaults: `BPF_LPM_TRIE(name, key_type=u64, leaf_type=u64, size=10240)`

For example:

```c
BPF_LPM_TRIE(trie, struct key_v6);
```

This creates an LPM trie map named `trie` where the key is a `struct key_v6`, and the value defaults to u64.

This is a wrapper macro to `BPF_F_TABLE("lpm_trie", ..., BPF_F_NO_PREALLOC)`.

Methods (covered later): map.lookup(), map.lookup_or_try_init(), map.delete(), map.update(), map.insert(), map.increment().

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=BPF_LPM_TRIE+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=BPF_LPM_TRIE+path%3Atools&type=Code)

### 10. BPF_PROG_ARRAY

Syntax: ```BPF_PROG_ARRAY(name, size)```

This creates a program array named ```name``` with ```size``` entries. Each entry of the array is either a file descriptor to a bpf program or ```NULL```. The array acts as a jump table so that bpf programs can "tail-call" other bpf programs.

This is a wrapper macro for `BPF_TABLE("prog", ...)`.

Methods (covered later): map.call().

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=BPF_PROG_ARRAY+path%3Aexamples&type=Code),
[search /tests](https://github.com/iovisor/bcc/search?q=BPF_PROG_ARRAY+path%3Atests&type=Code),
[assign fd](https://github.com/iovisor/bcc/blob/master/examples/networking/tunnel_monitor/monitor.py#L24-L26)

### 11. BPF_DEVMAP

Syntax: ```BPF_DEVMAP(name, size)```

This creates a device map named ```name``` with ```size``` entries. Each entry of the map is an `ifindex` to a network interface. This map is only used in XDP.

For example:
```C
BPF_DEVMAP(devmap, 10);
```

Methods (covered later): map.redirect_map().

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=BPF_DEVMAP+path%3Aexamples&type=Code),

### 12. BPF_CPUMAP

Syntax: ```BPF_CPUMAP(name, size)```

This creates a cpu map named ```name``` with ```size``` entries. The index of the map represents the CPU id and each entry is the size of the ring buffer allocated for the CPU. This map is only used in XDP.

For example:
```C
BPF_CPUMAP(cpumap, 16);
```

Methods (covered later): map.redirect_map().

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=BPF_CPUMAP+path%3Aexamples&type=Code),

### 13. BPF_XSKMAP

Syntax: ```BPF_XSKMAP(name, size [, "/sys/fs/bpf/xyz"])```

This creates a xsk map named ```name``` with ```size``` entries and pin it to the bpffs as a FILE. Each entry represents one NIC's queue id. This map is only used in XDP to redirect packet to an AF_XDP socket. If the AF_XDP socket is binded to a queue which is different than the current packet's queue id, the packet will be dropped. For kernel v5.3 and latter, `lookup` method is available and can be used to check whether and AF_XDP socket is available for the current packet's queue id. More details at [AF_XDP](https://www.kernel.org/doc/html/latest/networking/af_xdp.html).

For example:
```C
BPF_XSKMAP(xsks_map, 8);
```

Methods (covered later): map.redirect_map(). map.lookup()

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=BPF_XSKMAP+path%3Aexamples&type=Code),

### 14. BPF_ARRAY_OF_MAPS

Syntax: ```BPF_ARRAY_OF_MAPS(name, inner_map_name, size)```

This creates an array map with a map-in-map type (BPF_MAP_TYPE_HASH_OF_MAPS) map named ```name``` with ```size``` entries. The inner map meta data is provided by map ```inner_map_name``` and can be most of array or hash maps except ```BPF_MAP_TYPE_PROG_ARRAY```, ```BPF_MAP_TYPE_CGROUP_STORAGE``` and ```BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE```.

For example:
```C
BPF_TABLE("hash", int, int, ex1, 1024);
BPF_TABLE("hash", int, int, ex2, 1024);
BPF_ARRAY_OF_MAPS(maps_array, "ex1", 10);
```

### 15. BPF_HASH_OF_MAPS

Syntax: ```BPF_HASH_OF_MAPS(name, key_type, inner_map_name, size)```

This creates a hash map with a map-in-map type (BPF_MAP_TYPE_HASH_OF_MAPS) map named ```name``` with ```size``` entries. The inner map meta data is provided by map ```inner_map_name``` and can be most of array or hash maps except ```BPF_MAP_TYPE_PROG_ARRAY```, ```BPF_MAP_TYPE_CGROUP_STORAGE``` and ```BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE```.

For example:
```C
BPF_ARRAY(ex1, int, 1024);
BPF_ARRAY(ex2, int, 1024);
BPF_HASH_OF_MAPS(maps_hash, struct custom_key, "ex1", 10);
```

### 16. BPF_STACK

Syntax: ```BPF_STACK(name, leaf_type, max_entries[, flags])```

Creates a stack named ```name``` with value type ```leaf_type``` and max entries ```max_entries```.
Stack and Queue maps are only available from Linux 4.20+.

For example:

```C
BPF_STACK(stack, struct event, 10240);
```

This creates a stack named ```stack``` where the value type is ```struct event```, that holds up to 10240 entries.

Methods (covered later): map.push(), map.pop(), map.peek().

Examples in situ:
[search /tests](https://github.com/iovisor/bcc/search?q=BPF_STACK+path%3Atests&type=Code),

### 17. BPF_QUEUE

Syntax: ```BPF_QUEUE(name, leaf_type, max_entries[, flags])```

Creates a queue named ```name``` with value type ```leaf_type``` and max entries ```max_entries```.
Stack and Queue maps are only available from Linux 4.20+.

For example:

```C
BPF_QUEUE(queue, struct event, 10240);
```

This creates a queue named ```queue``` where the value type is ```struct event```, that holds up to 10240 entries.

Methods (covered later): map.push(), map.pop(), map.peek().

Examples in situ:
[search /tests](https://github.com/iovisor/bcc/search?q=BPF_QUEUE+path%3Atests&type=Code),

### 18. BPF_SOCKHASH

Syntax: ```BPF_SOCKHASH(name[, key_type [, max_entries)```

Creates a hash named ```name```, with optional parameters. sockhash is only available from Linux 4.18+.

Default: ```BPF_SOCKHASH(name, key_type=u32, max_entries=10240)```

For example:

```C
struct sock_key {
  u32 remote_ip4;
  u32 local_ip4;
  u32 remote_port;
  u32 local_port;
};
BPF_HASH(skh, struct sock_key, 65535);
```

This creates a hash named ```skh``` where the key is a ```struct sock_key```.

A sockhash is a BPF map type that holds references to sock structs. Then with a new sk/msg redirect bpf helper BPF programs can use the map to redirect skbs/msgs between sockets (```map.sk_redirect_hash()/map.msg_redirect_hash()```).

The difference between ```BPF_SOCKHASH``` and ```BPF_SOCKMAP``` is that ```BPF_SOCKMAP``` is implemented based on an array, and enforces keys to be four bytes. While ```BPF_SOCKHASH``` is implemented based on hash table, and the type of key can be specified freely.

Methods (covered later): map.sock_hash_update(), map.msg_redirect_hash(), map.sk_redirect_hash().

[search /tests](https://github.com/iovisor/bcc/search?q=BPF_SOCKHASH+path%3Atests&type=Code)

### 19. map.lookup()

Syntax: ```*val map.lookup(&key)```

Lookup the key in the map, and return a pointer to its value if it exists, else NULL. We pass the key in as an address to a pointer.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=lookup+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=lookup+path%3Atools&type=Code)

### 20. map.lookup_or_try_init()

Syntax: ```*val map.lookup_or_try_init(&key, &zero)```

Lookup the key in the map, and return a pointer to its value if it exists, else initialize the key's value to the second argument. This is often used to initialize values to zero. If the key cannot be inserted (e.g. the map is full) then NULL is returned.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=lookup_or_try_init+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=lookup_or_try_init+path%3Atools&type=Code)

Note: The old map.lookup_or_init() may cause return from the function, so lookup_or_try_init() is recommended as it
does not have this side effect.

### 21. map.delete()

Syntax: ```map.delete(&key)```

Delete the key from the hash.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=delete+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=delete+path%3Atools&type=Code)

### 22. map.update()

Syntax: ```map.update(&key, &val)```

Associate the value in the second argument to the key, overwriting any previous value.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=update+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=update+path%3Atools&type=Code)

### 23. map.insert()

Syntax: ```map.insert(&key, &val)```

Associate the value in the second argument to the key, only if there was no previous value.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=insert+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=insert+path%3Atools&type=Code)

### 24. map.increment()

Syntax: ```map.increment(key[, increment_amount])```

Increments the key's value by `increment_amount`, which defaults to 1. Used for histograms.

```map.increment()``` are not atomic. In the concurrency case. If you want more accurate results, use ```map.atomic_increment()``` instead of ```map.increment()```. The overhead of ```map.increment()``` and ```map.atomic_increment()``` is similar.

Note. When using ```map.atomic_increment()``` to operate on a BPF map of type ```BPF_MAP_TYPE_HASH```, ```map.atomic_increment()``` does not guarantee the atomicity of the operation when the specified key does not exist.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=increment+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=increment+path%3Atools&type=Code)

### 25. map.get_stackid()

Syntax: ```int map.get_stackid(void *ctx, u64 flags)```

This walks the stack found via the struct pt_regs in ```ctx```, saves it in the stack trace map, and returns a unique ID for the stack trace.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=get_stackid+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=get_stackid+path%3Atools&type=Code)

### 26. map.perf_read()

Syntax: ```u64 map.perf_read(u32 cpu)```

This returns the hardware performance counter as configured in [5. BPF_PERF_ARRAY](#5-bpf_perf_array)

Examples in situ:
[search /tests](https://github.com/iovisor/bcc/search?q=perf_read+path%3Atests&type=Code)

### 27. map.call()

Syntax: ```void map.call(void *ctx, int index)```

This invokes ```bpf_tail_call()``` to tail-call the bpf program which the ```index``` entry in [BPF_PROG_ARRAY](#10-bpf_prog_array) points to. A tail-call is different from the normal call. It reuses the current stack frame after jumping to another bpf program and never goes back. If the ```index``` entry is empty, it won't jump anywhere and the program execution continues as normal.

For example:

```C
BPF_PROG_ARRAY(prog_array, 10);

int tail_call(void *ctx) {
    bpf_trace_printk("Tail-call\n");
    return 0;
}

int do_tail_call(void *ctx) {
    bpf_trace_printk("Original program\n");
    prog_array.call(ctx, 2);
    return 0;
}
```

```Python
b = BPF(src_file="example.c")
tail_fn = b.load_func("tail_call", BPF.KPROBE)
prog_array = b.get_table("prog_array")
prog_array[c_int(2)] = c_int(tail_fn.fd)
b.attach_kprobe(event="some_kprobe_event", fn_name="do_tail_call")
```

This assigns ```tail_call()``` to ```prog_array[2]```. In the end of ```do_tail_call()```, ```prog_array.call(ctx, 2)``` tail-calls ```tail_call()``` and executes it.

**NOTE:** To prevent infinite loop, the maximum number of tail-calls is 32 ([```MAX_TAIL_CALL_CNT```](https://github.com/torvalds/linux/search?l=C&q=MAX_TAIL_CALL_CNT+path%3Ainclude%2Flinux&type=Code)).

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?l=C&q=call+path%3Aexamples&type=Code),
[search /tests](https://github.com/iovisor/bcc/search?l=C&q=call+path%3Atests&type=Code)

### 28. map.redirect_map()

Syntax: ```int map.redirect_map(int index, int flags)```

This redirects the incoming packets based on the ```index``` entry. If the map is [BPF_DEVMAP](#11-bpf_devmap), the packet will be sent to the transmit queue of the network interface that the entry points to. If the map is [BPF_CPUMAP](#12-bpf_cpumap), the packet will be sent to the ring buffer of the ```index``` CPU and be processed by the CPU later. If the map is [BPF_XSKMAP](#13-bpf_xskmap), the packet will be sent to the AF_XDP socket attached to the queue.

If the packet is redirected successfully, the function will return XDP_REDIRECT. Otherwise, it will return XDP_ABORTED to discard the packet.

For example:
```C
BPF_DEVMAP(devmap, 1);

int redirect_example(struct xdp_md *ctx) {
    return devmap.redirect_map(0, 0);
}
int xdp_dummy(struct xdp_md *ctx) {
    return XDP_PASS;
}
```

```Python
ip = pyroute2.IPRoute()
idx = ip.link_lookup(ifname="eth1")[0]

b = bcc.BPF(src_file="example.c")

devmap = b.get_table("devmap")
devmap[c_uint32(0)] = c_int(idx)

in_fn = b.load_func("redirect_example", BPF.XDP)
out_fn = b.load_func("xdp_dummy", BPF.XDP)
b.attach_xdp("eth0", in_fn, 0)
b.attach_xdp("eth1", out_fn, 0)
```

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?l=C&q=redirect_map+path%3Aexamples&type=Code),

### 29. map.push()

Syntax: ```int map.push(&val, int flags)```

Push an element onto a Stack or Queue table.
Passing BPF_EXIST as a flag causes the Queue or Stack to discard the oldest element if it is full.
Returns 0 on success, negative error on failure.

Examples in situ:
[search /tests](https://github.com/iovisor/bcc/search?q=push+path%3Atests&type=Code),

### 30. map.pop()

Syntax: ```int map.pop(&val)```

Pop an element from a Stack or Queue table. ```*val``` is populated with the result.
Unlike peeking, popping removes the element.
Returns 0 on success, negative error on failure.

Examples in situ:
[search /tests](https://github.com/iovisor/bcc/search?q=pop+path%3Atests&type=Code),

### 31. map.peek()

Syntax: ```int map.peek(&val)```

Peek an element at the head of a Stack or Queue table. ```*val``` is populated with the result.
Unlike popping, peeking does not remove the element.
Returns 0 on success, negative error on failure.

Examples in situ:
[search /tests](https://github.com/iovisor/bcc/search?q=peek+path%3Atests&type=Code),

### 32. map.sock_hash_update()

Syntax: ```int map.sock_hash_update(struct bpf_sock_ops *skops, &key, int flags)```

Add an entry to, or update a sockhash map referencing sockets. The skops is used as a new value for the entry associated to key. flags is one of:

```
BPF_NOEXIST: The entry for key must not exist in the map.
BPF_EXIST: The entry for key must already exist in the map.
BPF_ANY: No condition on the existence of the entry for key.
```

If the map has eBPF programs (parser and verdict), those will be inherited by the socket being added. If the socket is already attached to eBPF programs, this results in an error.

Return 0 on success, or a negative error in case of failure.

Examples in situ:
[search /tests](https://github.com/iovisor/bcc/search?q=sock_hash_update+path%3Atests&type=Code),

### 33. map.msg_redirect_hash()

Syntax: ```int map.msg_redirect_hash(struct sk_msg_buff *msg, void *key, u64 flags)```

This helper is used in programs implementing policies at the socket level. If the message msg is allowed to pass (i.e. if the verdict eBPF program returns SK_PASS), redirect it to the socket referenced by map (of type BPF_MAP_TYPE_SOCKHASH) using hash key. Both ingress and egress interfaces can be used for redirection. The BPF_F_INGRESS value in flags is used to make the distinction (ingress path is selected if the flag is present, egress path otherwise). This is the only flag supported for now.

Return SK_PASS on success, or SK_DROP on error.

Examples in situ:
[search /tests](https://github.com/iovisor/bcc/search?q=msg_redirect_hash+path%3Atests&type=Code),

### 34. map.sk_redirect_hash()

Syntax: ```int map.sk_redirect_hash(struct sk_buff *skb, void *key, u64 flags)```

This helper is used in programs implementing policies at the skb socket level. If the sk_buff skb is allowed to pass (i.e. if the verdict eBPF program returns SK_PASS), redirect it to the socket referenced by map (of  type  BPF_MAP_TYPE_SOCKHASH) using hash key. Both ingress and egress interfaces can be used for redirection. The BPF_F_INGRESS value in flags is used to make the distinction (ingress path is selected if the flag is present, egress otherwise). This is the only flag supported for now.

Return SK_PASS on success, or SK_DROP on error.

Examples in situ:
[search /tests](https://github.com/iovisor/bcc/search?q=sk_redirect_hash+path%3Atests&type=Code),

## Licensing

Depending on which [BPF helpers](kernel-versions.md#helpers) are used, a GPL-compatible license is required.

The special BCC macro `BPF_LICENSE` specifies the license of the BPF program. You can set the license as a comment in your source code, but the kernel has a special interface to specify it programmatically. If you need to use GPL-only helpers, it is recommended to specify the macro in your C code so that the kernel can understand it:

```C
// SPDX-License-Identifier: GPL-2.0+
#define BPF_LICENSE GPL
```

Otherwise, the kernel may reject loading your program (see the [error description](#2-cannot-call-gpl-only-function-from-proprietary-program) below). Note that it supports multiple words and quotes are not necessary:

```C
// SPDX-License-Identifier: GPL-2.0+ OR BSD-2-Clause
#define BPF_LICENSE Dual BSD/GPL
```

Check the [BPF helpers reference](kernel-versions.md#helpers) to see which helpers are GPL-only and what the kernel understands as GPL-compatible.

**If the macro is not specified, BCC will automatically define the license of the program as GPL.**

## Rewriter

One of jobs for rewriter is to turn implicit memory accesses to explicit ones using kernel helpers. Recent kernel introduced a config option ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE which will be set for architectures who user address space and kernel address are disjoint. x86 and arm has this config option set while s390 does not. If ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE is not set, the bpf old helper `bpf_probe_read()` will not be available. Some existing users may have implicit memory accesses to access user memory, so using `bpf_probe_read_kernel()` will cause their application to fail. Therefore, for non-s390, the rewriter will use `bpf_probe_read()` for these implicit memory accesses. For s390, `bpf_probe_read_kernel()` is used as default and users should use `bpf_probe_read_user()` explicitly when accessing user memories.

# bcc Python

## Initialization

Constructors.

### 1. BPF

Syntax: ```BPF({text=BPF_program | src_file=filename} [, usdt_contexts=[USDT_object, ...]] [, cflags=[arg1, ...]] [, debug=int])```

Creates a BPF object. This is the main object for defining a BPF program, and interacting with its output.

Exactly one of `text` or `src_file` must be supplied (not both).

The `cflags` specifies additional arguments to be passed to the compiler, for example `-DMACRO_NAME=value` or `-I/include/path`.  The arguments are passed as an array, with each element being an additional argument.  Note that strings are not split on whitespace, so each argument must be a different element of the array, e.g. `["-include", "header.h"]`.

The `debug` flags control debug output, and can be or'ed together:
- `DEBUG_LLVM_IR = 0x1` compiled LLVM IR
- `DEBUG_BPF = 0x2` loaded BPF bytecode and register state on branches
- `DEBUG_PREPROCESSOR = 0x4` pre-processor result
- `DEBUG_SOURCE = 0x8` ASM instructions embedded with source
- `DEBUG_BPF_REGISTER_STATE = 0x10` register state on all instructions in addition to DEBUG_BPF
- `DEBUG_BTF = 0x20` print the messages from the `libbpf` library.

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

# add include paths:
u = BPF(text=prog, cflags=["-I/path/to/include"])
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
You can also call attach_kprobe() more than once to attach multiple BPF functions to the same kernel function.

See the previous kprobes section for how to instrument arguments from BPF.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=attach_kprobe+path%3Aexamples+language%3Apython&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=attach_kprobe+path%3Atools+language%3Apython&type=Code)

### 2. attach_kretprobe()

Syntax: ```BPF.attach_kretprobe(event="event", fn_name="name" [, maxactive=int])```

Instruments the return of the kernel function ```event()``` using kernel dynamic tracing of the function return, and attaches our C defined function ```name()``` to be called when the kernel function returns.

For example:

```Python
b.attach_kretprobe(event="vfs_read", fn_name="do_return")
```

This will instrument the kernel ```vfs_read()``` function, which will then run our BPF defined ```do_return()``` function each time it is called.

You can call attach_kretprobe() more than once, and attach your BPF function to multiple kernel function returns.
You can also call attach_kretprobe() more than once to attach multiple BPF functions to the same kernel function return.

When a kretprobe is installed on a kernel function, there is a limit on how many parallel calls it can catch. You can change that limit with ```maxactive```. See the kprobes documentation for its default value.

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
[code](https://github.com/iovisor/bcc/blob/a4159da8c4ea8a05a3c6e402451f530d6e5a8b41/examples/tracing/urandomread-explicit.py#L41),
[search /examples](https://github.com/iovisor/bcc/search?q=attach_tracepoint+path%3Aexamples+language%3Apython&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=attach_tracepoint+path%3Atools+language%3Apython&type=Code)

### 4. attach_uprobe()

Syntax: ```BPF.attach_uprobe(name="location", sym="symbol", fn_name="name" [, sym_off=int])```, ```BPF.attach_uprobe(name="location", sym_re="regex", fn_name="name")```, ```BPF.attach_uprobe(name="location", addr=int, fn_name="name")```


Instruments the user-level function ```symbol()``` from either the library or binary named by ```location``` using user-level dynamic tracing of the function entry, and attach our C defined function ```name()``` to be called whenever the user-level function is called. If ```sym_off``` is given, the function is attached to the offset within the symbol.

The real address ```addr``` may be supplied in place of ```sym```, in which case ```sym``` must be set to its default value. If the file is a non-PIE executable, ```addr``` must be a virtual address, otherwise it must be an offset relative to the file load address.

Instead of a symbol name, a regular expression can be provided in ```sym_re```. The uprobe will then attach to symbols that match the provided regular expression.

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
b.attach_uretprobe(name="c", sym="getaddrinfo", fn_name="do_return")
b.attach_uretprobe(name="/usr/bin/python", sym="main", fn_name="do_main")
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

### 7. attach_raw_tracepoint()

Syntax: ```BPF.attach_raw_tracepoint(tp="tracepoint", fn_name="name")```

Instruments the kernel raw tracepoint described by ```tracepoint``` (```event``` only, no ```category```), and when hit, runs the BPF function ```name()```.

This is an explicit way to instrument tracepoints. The ```RAW_TRACEPOINT_PROBE``` syntax, covered in the earlier raw tracepoints section, is an alternate method.

For example:

```Python
b.attach_raw_tracepoint("sched_switch", "do_trace")
```

Examples in situ:
[search /tools](https://github.com/iovisor/bcc/search?q=attach_raw_tracepoint+path%3Atools+language%3Apython&type=Code)

### 8. attach_raw_socket()

Syntax: ```BPF.attach_raw_socket(fn, dev)```

Attaches a BPF function to the specified network interface.

The ```fn``` must be the type of ```BPF.function``` and the bpf_prog type needs to be ```BPF_PROG_TYPE_SOCKET_FILTER```  (```fn=BPF.load_func(func_name, BPF.SOCKET_FILTER)```)

```fn.sock``` is a non-blocking raw socket that was created and bound to ```dev```.

All network packets processed by ```dev``` are copied to the ```recv-q``` of ```fn.sock``` after being processed by bpf_prog. Try to recv packet form ```fn.sock``` with rev/recvfrom/recvmsg. Note that if the ```recv-q``` is not read in time after the ```recv-q``` is full, the copied packets will be discarded.

We can use this feature to capture network packets just like ```tcpdump```.

We can use ```ss --bpf --packet -p``` to observe ```fn.sock```.

Example:

```Python
BPF.attach_raw_socket(bpf_func, ifname)
```

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=attach_raw_socket+path%3Aexamples+language%3Apython&type=Code)
### 9. attach_xdp()
Syntax: ```BPF.attach_xdp(dev="device", fn=b.load_func("fn_name",BPF.XDP), flags)```

Instruments the network driver described by ```dev``` , and then receives the packet, run the BPF function ```fn_name()``` with flags.

Here is a list of optional flags.

```Python
# from xdp_flags uapi/linux/if_link.h
XDP_FLAGS_UPDATE_IF_NOEXIST = (1 << 0)
XDP_FLAGS_SKB_MODE = (1 << 1)
XDP_FLAGS_DRV_MODE = (1 << 2)
XDP_FLAGS_HW_MODE = (1 << 3)
XDP_FLAGS_REPLACE = (1 << 4)
```

You can use flags like this ```BPF.attach_xdp(dev="device", fn=b.load_func("fn_name",BPF.XDP), flags=BPF.XDP_FLAGS_UPDATE_IF_NOEXIST)```

The default value of flags is 0. This means if there is no xdp program with `device`, the fn will run with that device. If there is an xdp program running with device, the old program will be replaced with new fn program.

Currently, bcc does not support XDP_FLAGS_REPLACE flag. The following are the descriptions of other flags.

#### 1. XDP_FLAGS_UPDATE_IF_NOEXIST
If an XDP program is already attached to the specified driver, attaching the XDP program again will fail.

#### 2. XDP_FLAGS_SKB_MODE
Driver doesn’t have support for XDP, but the kernel fakes it.
XDP program works, but there’s no real performance benefit because packets are handed to kernel stack anyways which then emulates XDP – this is usually supported with generic network drivers used in home computers, laptops, and virtualized HW.

#### 3. XDP_FLAGS_DRV_MODE
A driver has XDP support and can hand then to XDP without kernel stack interaction – Few drivers can support it and those are usually for enterprise HW.

#### 4. XDP_FLAGS_HW_MODE
XDP can be loaded and executed directly on the NIC – just a handful of NICs can do that.


For example:

```Python
b.attach_xdp(dev="ens1", fn=b.load_func("do_xdp", BPF.XDP))
```

This will instrument the network device ```ens1``` , which will then run our BPF defined ```do_xdp()``` function each time it receives packets.

Don't forget to call ```b.remove_xdp("ens1")``` at the end!

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=attach_xdp+path%3Aexamples+language%3Apython&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=attach_xdp+path%3Atools+language%3Apython&type=Code)

### 10. attach_func()

Syntax: ```BPF.attach_func(fn, attachable_fd, attach_type [, flags])```

Attaches a BPF function of the specified type to a particular ```attachable_fd```. if the ```attach_type``` is ```BPF_FLOW_DISSECTOR```, the function is expected to attach to current net namespace and ```attachable_fd``` must be 0.

For example:

```Python
b.attach_func(fn, cgroup_fd, BPFAttachType.CGROUP_SOCK_OPS)
b.attach_func(fn, map_fd, BPFAttachType.SK_MSG_VERDICT)
```

Note. When attached to "global" hooks (xdp, tc, lwt, cgroup). If the "BPF function" is no longer needed after the program terminates, be sure to call `detach_func` when the program exits.

Examples in situ:

[search /examples](https://github.com/iovisor/bcc/search?q=attach_func+path%3Aexamples+language%3Apython&type=Code),

### 11. detach_func()

Syntax: ```BPF.detach_func(fn, attachable_fd, attach_type)```

Detaches a BPF function of the specified type.

For example:

```Python
b.detach_func(fn, cgroup_fd, BPFAttachType.CGROUP_SOCK_OPS)
b.detach_func(fn, map_fd, BPFAttachType.SK_MSG_VERDICT)
```

Examples in situ:

[search /examples](https://github.com/iovisor/bcc/search?q=detach_func+path%3Aexamples+language%3Apython&type=Code),

### 12. detach_kprobe()

Syntax: ```BPF.detach_kprobe(event="event", fn_name="name")```

Detach a kprobe handler function of the specified event.

For example:

```Python
b.detach_kprobe(event="__page_cache_alloc", fn_name="trace_func_entry")
```

### 13. detach_kretprobe()

Syntax: ```BPF.detach_kretprobe(event="event", fn_name="name")```

Detach a kretprobe handler function of the specified event.

For example:

```Python
b.detach_kretprobe(event="__page_cache_alloc", fn_name="trace_func_return")
```

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
[search /examples](https://github.com/iovisor/bcc/search?q=trace_fields+path%3Aexamples+language%3Apython&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=trace_fields+path%3Atools+language%3Apython&type=Code)

## Output APIs

Normal output from a BPF program is either:

- per-event: using PERF_EVENT_OUTPUT, open_perf_buffer(), and perf_buffer_poll().
- map summary: using items(), or print_log2_hist(), covered in the Maps section.

### 1. perf_buffer_poll()

Syntax: ```BPF.perf_buffer_poll(timeout=T)```

This polls from all open perf ring buffers, calling the callback function that was provided when calling open_perf_buffer for each entry.

The timeout parameter is optional and measured in milliseconds. In its absence, polling continues indefinitely.

Example:

```Python
# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit();
```

Examples in situ:
[code](https://github.com/iovisor/bcc/blob/v0.9.0/examples/tracing/hello_perf_output.py#L55),
[search /examples](https://github.com/iovisor/bcc/search?q=perf_buffer_poll+path%3Aexamples+language%3Apython&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=perf_buffer_poll+path%3Atools+language%3Apython&type=Code)

### 2. ring_buffer_poll()

Syntax: ```BPF.ring_buffer_poll(timeout=T)```

This polls from all open ringbuf ring buffers, calling the callback function that was provided when calling open_ring_buffer for each entry.

The timeout parameter is optional and measured in milliseconds. In its absence, polling continues until
there is no more data or the callback returns a negative value.

Example:

```Python
# loop with callback to print_event
b["events"].open_ring_buffer(print_event)
while 1:
    try:
        b.ring_buffer_poll(30)
    except KeyboardInterrupt:
        exit();
```

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=ring_buffer_poll+path%3Aexamples+language%3Apython&type=Code),

### 3. ring_buffer_consume()

Syntax: ```BPF.ring_buffer_consume()```

This consumes from all open ringbuf ring buffers, calling the callback function that was provided when calling open_ring_buffer for each entry.

Unlike ```ring_buffer_poll```, this method **does not poll for data** before attempting to consume.
This reduces latency at the expense of higher CPU consumption. If you are unsure which to use,
use ```ring_buffer_poll```.

Example:

```Python
# loop with callback to print_event
b["events"].open_ring_buffer(print_event)
while 1:
    try:
        b.ring_buffer_consume()
    except KeyboardInterrupt:
        exit();
```

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=ring_buffer_consume+path%3Aexamples+language%3Apython&type=Code),

## Map APIs

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
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
```

Note that the data structure transferred will need to be declared in C in the BPF program. For example:

```C
// define output data structure in C
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);
[...]
```

In Python, you can either let bcc generate the data structure from C declaration automatically (recommended):

```Python
def print_event(cpu, data, size):
    event = b["events"].event(data)
[...]
```

or define it manually:

```Python
# define output data structure in Python
TASK_COMM_LEN = 16    # linux/sched.h
class Data(ct.Structure):
    _fields_ = [("pid", ct.c_ulonglong),
                ("ts", ct.c_ulonglong),
                ("comm", ct.c_char * TASK_COMM_LEN)]

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
[...]
```

Examples in situ:
[code](https://github.com/iovisor/bcc/blob/v0.9.0/examples/tracing/hello_perf_output.py#L52),
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
[search /examples](https://github.com/iovisor/bcc/search?q=items+path%3Aexamples+language%3Apython&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=items+path%3Atools+language%3Apython&type=Code)

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

### 6. items_lookup_and_delete_batch()

Syntax: ```table.items_lookup_and_delete_batch()```

Returns an array of the keys in a table with a single call to BPF syscall. This can be used with BPF_HASH maps to fetch, and iterate, over the keys. It also clears the table: deletes all entries.
You should rather use table.items_lookup_and_delete_batch() than table.items() followed by table.clear(). It requires kernel v5.6.

Example:

```Python
# print call rate per second:
print("%9s-%9s-%8s-%9s" % ("PID", "COMM", "fname", "counter"))
while True:
    for k, v in sorted(b['map'].items_lookup_and_delete_batch(), key=lambda kv: (kv[0]).pid):
        print("%9s-%9s-%8s-%9d" % (k.pid, k.comm, k.fname, v.counter))
    sleep(1)
```

### 7. items_lookup_batch()

Syntax: ```table.items_lookup_batch()```

Returns an array of the keys in a table with a single call to BPF syscall. This can be used with BPF_HASH maps to fetch, and iterate, over the keys.
You should rather use table.items_lookup_batch() than table.items(). It requires kernel v5.6.

Example:

```Python
# print current value of map:
print("%9s-%9s-%8s-%9s" % ("PID", "COMM", "fname", "counter"))
while True:
    for k, v in sorted(b['map'].items_lookup_batch(), key=lambda kv: (kv[0]).pid):
        print("%9s-%9s-%8s-%9d" % (k.pid, k.comm, k.fname, v.counter))
```

### 8. items_delete_batch()

Syntax: ```table.items_delete_batch(keys)```

It clears all entries of a BPF_HASH map when keys is None. It is more efficient than table.clear() since it generates only one system call. You can delete a subset of a map by giving an array of keys as parameter. Those keys and their associated values will be deleted. It requires kernel v5.6.

Arguments:

- keys is optional and by default is None.



### 9. items_update_batch()

Syntax: ```table.items_update_batch(keys, values)```

Update all the provided keys with new values. The two arguments must be the same length and within the map limits (between 1 and the maximum entries). It requires kernel v5.6.

Arguments:

- keys is the list of keys to be updated
- values is the list containing the new values.


### 10. print_log2_hist()

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

int kprobe__blk_account_io_done(struct pt_regs *ctx, struct request *req)
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

### 11. print_linear_hist()

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

int kprobe__blk_account_io_done(struct pt_regs *ctx, struct request *req)
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

### 12. open_ring_buffer()

Syntax: ```table.open_ring_buffer(callback, ctx=None)```

This operates on a table as defined in BPF as BPF_RINGBUF_OUTPUT(), and associates the callback Python function ```callback``` to be called when data is available in the ringbuf ring buffer. This is part of the new (Linux 5.8+) recommended mechanism for transferring per-event data from kernel to user space. Unlike perf buffers, ringbuf sizes are specified within the BPF program, as part of the ```BPF_RINGBUF_OUTPUT``` macro. If the callback is not processing data fast enough, some submitted data may be lost. In this case, the events should be polled more frequently and/or the size of the ring buffer should be increased.

Example:

```Python
# process event
def print_event(ctx, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    [...]

# loop with callback to print_event
b["events"].open_ring_buffer(print_event)
while 1:
    try:
        b.ring_buffer_poll()
    except KeyboardInterrupt:
        exit()
```

Note that the data structure transferred will need to be declared in C in the BPF program. For example:

```C
// define output data structure in C
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_RINGBUF_OUTPUT(events, 8);
[...]
```

In Python, you can either let bcc generate the data structure from C declaration automatically (recommended):

```Python
def print_event(ctx, data, size):
    event = b["events"].event(data)
[...]
```

or define it manually:

```Python
# define output data structure in Python
TASK_COMM_LEN = 16    # linux/sched.h
class Data(ct.Structure):
    _fields_ = [("pid", ct.c_ulonglong),
                ("ts", ct.c_ulonglong),
                ("comm", ct.c_char * TASK_COMM_LEN)]

def print_event(ctx, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
[...]
```

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=open_ring_buffer+path%3Aexamples+language%3Apython&type=Code),

### 13. push()

Syntax: ```table.push(leaf, flags=0)```

Push an element onto a Stack or Queue table. Raises an exception if the operation does not succeed.
Passing QueueStack.BPF_EXIST as a flag causes the Queue or Stack to discard the oldest element if it is full.

Examples in situ:
[search /tests](https://github.com/iovisor/bcc/search?q=push+path%3Atests+language%3Apython&type=Code),

### 14. pop()

Syntax: ```leaf = table.pop()```

Pop an element from a Stack or Queue table. Unlike ```peek()```, ```pop()```
removes the element from the table before returning it.
Raises a KeyError exception if the operation does not succeed.

Examples in situ:
[search /tests](https://github.com/iovisor/bcc/search?q=pop+path%3Atests+language%3Apython&type=Code),

### 15. peek()

Syntax: ```leaf = table.peek()```

Peek the element at the head of a Stack or Queue table. Unlike ```pop()```, ```peek()```
does not remove the element from the table. Raises an exception if the operation does not succeed.

Examples in situ:
[search /tests](https://github.com/iovisor/bcc/search?q=peek+path%3Atests+language%3Apython&type=Code),

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

### 5. get_syscall_fnname()

Syntax: ```BPF.get_syscall_fnname(name : str)```

Return the corresponding kernel function name of the syscall. This helper function will try different prefixes and use the right one to concatenate with the syscall name. Note that the return value may vary in different versions of linux kernel and sometimes it will causing trouble. (see [#2590](https://github.com/iovisor/bcc/issues/2590))

Example:

```Python
print("The function name of %s in kernel is %s" % ("clone", b.get_syscall_fnname("clone")))
# sys_clone or __x64_sys_clone or ...
```

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=get_syscall_fnname+path%3Aexamples+language%3Apython&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=get_syscall_fnname+path%3Atools+language%3Apython&type=Code)

# BPF Errors

See the "Understanding eBPF verifier messages" section in the kernel source under Documentation/networking/filter.txt.

## 1. Invalid mem access

This can be due to trying to read memory directly, instead of operating on memory on the BPF stack. All kernel memory reads must be passed via bpf_probe_read_kernel() to copy kernel memory into the BPF stack, which can be automatic by the bcc rewriter in some cases of simple dereferencing. bpf_probe_read_kernel() does all the required checks.

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

## 2. Cannot call GPL only function from proprietary program

This error happens when a GPL-only helper is called from a non-GPL BPF program. To fix this error, do not use GPL-only helpers from a proprietary BPF program, or relicense the BPF program under a GPL-compatible license. Check which [BPF helpers](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#helpers) are GPL-only, and what licenses are considered GPL-compatible.

Example calling `bpf_get_stackid()`, a GPL-only BPF helper, from a proprietary program (`#define BPF_LICENSE Proprietary`):

```
bpf: Failed to load program: Invalid argument
[...]
8: (85) call bpf_get_stackid#27
cannot call GPL only function from proprietary program
```

# Environment Variables

## 1. Kernel source directory

eBPF program compilation needs kernel sources or kernel headers with headers
compiled. In case your kernel sources are at a non-standard location where BCC
cannot find then, its possible to provide BCC the absolute path of the location
by setting `BCC_KERNEL_SOURCE` to it.

## 2. Kernel version overriding

By default, BCC stores the `LINUX_VERSION_CODE` in the generated eBPF object
which is then passed along to the kernel when the eBPF program is loaded.
Sometimes this is quite inconvenient especially when the kernel is slightly
updated such as an LTS kernel release. Its extremely unlikely the slight
mismatch would cause any issues with the loaded eBPF program. By setting
`BCC_LINUX_VERSION_CODE` to the version of the kernel that's running, the check
for verifying the kernel version can be bypassed. This is needed for programs
that use kprobes. This needs to be encoded in the format: `(VERSION * 65536) +
(PATCHLEVEL * 256) + SUBLEVEL`. For example, if the running kernel is `4.9.10`,
then can set `export BCC_LINUX_VERSION_CODE=264458` to override the kernel
version check successfully.
