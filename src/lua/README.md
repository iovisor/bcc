Lua Tools for BCC
-----------------

This directory contains Lua tooling for [BCC][bcc]
(the BPF Compiler Collection).

BCC is a toolkit for creating userspace and kernel tracing programs. By
default, it comes with a library `libbcc`, some example tooling and a Python
frontend for the library.

Here we present an alternate frontend for `libbcc` implemented in LuaJIT. This
lets you write the userspace part of your tracer in Lua instead of Python.

Since LuaJIT is a JIT compiled language, tracers implemented in `bcc-lua`
exhibit significantly reduced overhead compared to their Python equivalents.
This is particularly noticeable in tracers that actively use the table APIs to
get information from the kernel.

If your tracer makes extensive use of `BPF_MAP_TYPE_PERF_EVENT_ARRAY` or
`BPF_MAP_TYPE_HASH`, you may find the performance characteristics of this
implementation very appealing, as LuaJIT can compile to native code a lot of
the callchain to process the events, and this wrapper has been designed to
benefit from such JIT compilation.

## Quickstart Guide

The following instructions assume Ubuntu 14.04 LTS.

1. Install a **very new kernel**. It has to be new and shiny for this to work. 4.3+

    ```
    VER=4.4.2-040402
    PREFIX=http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.4.2-wily/
    REL=201602171633
    wget ${PREFIX}/linux-headers-${VER}-generic_${VER}.${REL}_amd64.deb
    wget ${PREFIX}/linux-headers-${VER}_${VER}.${REL}_all.deb
    wget ${PREFIX}/linux-image-${VER}-generic_${VER}.${REL}_amd64.deb
    sudo dpkg -i linux-*${VER}.${REL}*.deb
    ```

2. Install the `libbcc` binary packages and `luajit`

    ```
    sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys D4284CDD
    echo "deb https://repo.iovisor.org/apt trusty main" | sudo tee /etc/apt/sources.list.d/iovisor.list
    sudo apt-get update
    sudo apt-get install libbcc luajit
    ```

3. Test one of the examples to ensure `libbcc` is properly installed

    ```
    sudo ./bcc-probe examples/lua/task_switch.lua
    ```

## LuaJIT BPF compiler

Now it is also possible to write Lua functions and compile them transparently to BPF bytecode, here is a simple socket filter example:

```lua
local S = require('syscall')
local bpf = require('bpf')
local map = bpf.map('array', 256)
-- Kernel-space part of the program
local prog = assert(bpf(function ()
    local proto = pkt.ip.proto  -- Get byte (ip.proto) from frame at [23]
    xadd(map[proto], 1)         -- Increment packet count
end))
-- User-space part of the program
local sock = assert(bpf.socket('lo', prog))
for i=1,10 do
    local icmp, udp, tcp = map[1], map[17], map[6]
    print('TCP', tcp, 'UDP', udp, 'ICMP', icmp, 'packets')
    S.sleep(1)
end
```

The other application of BPF programs is attaching to probes for [perf event tracing][tracing]. That means you can trace events inside the kernel (or user-space), and then collect results - for example histogram of `sendto()` latency, off-cpu time stack traces, syscall latency, and so on. While kernel probes and perf events have unstable ABI, with a dynamic language we can create and use proper type based on the tracepoint ABI on runtime.

Runtime automatically recognizes reads that needs a helper to be accessed. The type casts denote source of the objects, for example the [bashreadline][bashreadline] example that prints entered bash commands from all running shells:

```lua
local ffi = require('ffi')
local bpf = require('bpf')
-- Perf event map
local sample_t = 'struct { uint64_t pid; char str[80]; }'
local events = bpf.map('perf_event_array')
-- Kernel-space part of the program
bpf.uprobe('/bin/bash:readline' function (ptregs)
    local sample = ffi.new(sample_t)
    sample.pid = pid_tgid()
    ffi.copy(sample.str, ffi.cast('char *', req.ax)) -- Cast `ax` to string pointer and copy to buffer
    perf_submit(events, sample)                      -- Write sample to perf event map
end, true, -1, 0)
-- User-space part of the program
local log = events:reader(nil, 0, sample_t) -- Must specify PID or CPU_ID to observe
while true do
    log:block()               -- Wait until event reader is readable
    for _,e in log:read() do  -- Collect available reader events
        print(tonumber(e.pid), ffi.string(e.str))
    end
end
```

Where cast to `struct pt_regs` flags the source of data as probe arguments, which means any pointer derived
from this structure points to kernel and a helper is needed to access it. Casting `req.ax` to pointer is then required for `ffi.copy` semantics, otherwise it would be treated as `u64` and only it's value would be
copied. The type detection is automatic most of the times (socket filters and `bpf.tracepoint`), but not with uprobes and kprobes.

### Installation

```bash
$ luarocks install bpf
```

### Examples

See `examples/lua` directory.

### Helpers

* `print(...)` is a wrapper for `bpf_trace_printk`, the output is captured in `cat /sys/kernel/debug/tracing/trace_pipe`
* `bit.*` library **is** supported (`lshift, rshift, arshift, bnot, band, bor, bxor`)
* `math.*` library *partially* supported (`log2, log, log10`)
* `ffi.cast()` is implemented (including structures and arrays)
* `ffi.new(...)` allocates memory on stack, initializers are NYI
* `ffi.copy(...)` copies memory (possibly using helpers) between stack/kernel/registers
* `ntoh(x[, width])` - convert from network to host byte order.
* `hton(x[, width])` - convert from host to network byte order.
* `xadd(dst, inc)` - exclusive add, a synchronous `*dst += b` if Lua had `+=` operator

Below is a list of BPF-specific helpers:

* `time()` - return current monotonic time in nanoseconds (uses `bpf_ktime_get_ns`)
* `cpu()` - return current CPU number (uses `bpf_get_smp_processor_id`)
* `pid_tgid()` - return caller `tgid << 32 | pid` (uses `bpf_get_current_pid_tgid`)
* `uid_gid()` - return caller `gid << 32 | uid` (uses `bpf_get_current_uid_gid`)
* `comm(var)` - write current process name (uses `bpf_get_current_comm`)
* `perf_submit(map, var)` - submit variable to perf event array BPF map
* `stack_id(map, flags)` - return stack trace identifier from stack trace BPF map
* `load_bytes(off, var)` - helper for direct packet access with `skb_load_bytes()`

### Current state

* Not all LuaJIT bytecode opcodes are supported *(notable mentions below)*
* Closures `UCLO` will probably never be supported, although you can use upvalues inside compiled function.
* Type narrowing is opportunistic. Numbers are 64-bit by default, but 64-bit immediate loads are not supported (e.g. `local x = map[ffi.cast('uint64_t', 1000)]`)
* Tail calls `CALLT`, and iterators `ITERI` are NYI (as of now)
* Arbitrary ctype **is** supported both for map keys and values
* Basic optimisations like: constant propagation, partial DCE, liveness analysis and speculative register allocation are implement, but there's no control flow analysis yet. This means the compiler has the visibility when things are used and dead-stores occur, but there's no rewriter pass to eliminate them.
* No register sub-allocations, no aggressive use of caller-saved `R1-5`, no aggressive narrowing (this would require variable range assertions and variable relationships)
* Slices with not 1/2/4/8 length are NYI (requires allocating a memory on stack and using pointer type)


[bcc]: https://github.com/iovisor/bcc
[tracing]: http://www.brendangregg.com/blog/2016-03-05/linux-bpf-superpowers.html
[bashreadline]: http://www.brendangregg.com/blog/2016-02-08/linux-ebpf-bcc-uprobes.html