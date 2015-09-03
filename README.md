![BCC Logo](images/logo2.png)
# BPF Compiler Collection (BCC)

This directory contains source code for BCC, a toolkit for creating small
programs that can be dynamically loaded into a Linux kernel.

The compiler relies upon eBPF (Extended Berkeley Packet Filters), which is a
feature in Linux kernels starting from 3.15. Currently, this compiler leverages
features which are mostly available in Linux 4.1 and above.

## Installing

See [INSTALL.md](INSTALL.md) for installation steps on your platform.

## Motivation

BPF guarantees that the programs loaded into the kernel cannot crash, and
cannot run forever, but yet BPF is general purpose enough to perform many
arbitrary types of computation. Currently, it is possible to write a program in
C that will compile into a valid BPF program, yet it is vastly easier to
write a C program that will compile into invalid BPF (C is like that). The user
won't know until trying to run the program whether it was valid or not.

With a BPF-specific frontend, one should be able to write in a language and
receive feedback from the compiler on the validity as it pertains to a BPF
backend. This toolkit aims to provide a frontend that can only create valid BPF
programs while still harnessing its full flexibility.

Furthermore, current integrations with BPF have a kludgy workflow, sometimes
involving compiling directly in a linux kernel source tree. This toolchain aims
to minimize the time that a developer spends getting BPF compiled, and instead
focus on the applications that can be written and the problems that can be
solved with BPF.

The features of this toolkit include:
* End-to-end BPF workflow in a shared library
  * A modified C language for BPF backends
  * Integration with llvm-bpf backend for JIT
  * Dynamic (un)loading of JITed programs
  * Support for BPF kernel hooks: socket filters, tc classifiers,
      tc actions, and kprobes
* Bindings for Python
* Examples for socket filters, tc classifiers, and kprobes
* Self-contained tools for tracing a running system

In the future, more bindings besides python will likely be supported. Feel free
to add support for the language of your choice and send a pull request!

## Examples

This toolchain is currently composed of two parts: a C wrapper around LLVM, and
a Python API to interact with the running program. Later, we will go into more
detail of how this all works.

### Hello, World

First, we should include the BPF class from the bpf module:
```python
from bcc import BPF
```

Since the C code is so short, we will embed it inside the python script.

The BPF program always takes at least one argument, which is a pointer to the
context for this type of program. Different program types have different calling
conventions, but for this one we don't care so `void *` is fine.
```python
prog = """
int hello(void *ctx) {
  bpf_trace_printk("Hello, World!\\n");
  return 0;
};
"""
b = BPF(text=prog)
```

For this example, we will call the program every time `fork()` is called by a
userspace process. Underneath the hood, fork translates to the `clone` syscall,
so we will attach our program to the kernel symbol `sys_clone`.
```python
b.attach_kprobe(event="sys_clone", fn_name="hello")
```

The python process will then print the trace printk circular buffer until ctrl-c
is pressed. The BPF program is removed from the kernel when the userspace
process that loaded it closes the fd (or exits).
```python
b.trace_print()
```

Output:
```
bcc/examples$ sudo python hello_world.py 
          python-7282  [002] d...  3757.488508: : Hello, World!
```

[Source code listing](examples/hello_world.py)

### Networking

At RedHat Summit 2015, BCC was presented as part of a [session on BPF](http://www.devnation.org/#7784f1f7513e8542e4db519e79ff5eec).
A multi-host vxlan environment is simulated and a BPF program used to monitor
one of the physical interfaces. The BPF program keeps statistics on the inner
and outer IP addresses traversing the interface, and the userspace component
turns those statistics into a graph showing the traffic distribution at
multiple granularities. See the code [here](examples/tunnel_monitor).

[![Screenshot](http://img.youtube.com/vi/yYy3Cwce02k/0.jpg)](https://youtu.be/yYy3Cwce02k)

### Tracing

Here is a slightly more complex tracing example than Hello World. This program
will be invoked for every task change in the kernel, and record in a BPF map
the new and old pids.

The C program below introduces two new concepts.
The first is the macro `BPF_TABLE`. This defines a table (type="hash"), with key
type `key_t` and leaf type `u64` (a single counter). The table name is `stats`,
containing 1024 entries maximum. One can `lookup`, `lookup_or_init`, `update`,
and `delete` entries from the table.
The second concept is the prev argument. This argument is treated specially by
the BCC frontend, such that accesses to this variable are read from the saved
context that is passed by the kprobe infrastructure. The prototype of the args
starting from position 1 should match the prototype of the kernel function being
kprobed. If done so, the program will have seamless access to the function
parameters.
```c
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct key_t {
  u32 prev_pid;
  u32 curr_pid;
};
// map_type, key_type, leaf_type, table_name, num_entry
BPF_TABLE("hash", struct key_t, u64, stats, 1024);
int count_sched(struct pt_regs *ctx, struct task_struct *prev) {
  struct key_t key = {};
  u64 zero = 0, *val;

  key.curr_pid = bpf_get_current_pid_tgid();
  key.prev_pid = prev->pid;

  val = stats.lookup_or_init(&key, &zero);
  (*val)++;
  return 0;
}
```
[Source code listing](examples/task_switch.c)

The userspace component loads the file shown above, and attaches it to the
`finish_task_switch` kernel function (which takes one `struct task_struct *`
argument). The `get_table` API returns an object that gives dict-style access
to the stats BPF map. The python program could use that handle to modify the
kernel table as well.
```python
from bcc import BPF
from time import sleep

b = BPF(src_file="task_switch.c")
b.attach_kprobe(event="finish_task_switch", fn_name="count_sched")

# generate many schedule events
for i in range(0, 100): sleep(0.01)

for k, v in b["stats"].items():
    print("task_switch[%5d->%5d]=%u" % (k.prev_pid, k.curr_pid, v.value))
```
[Source code listing](examples/task_switch.py)

## Requirements

To get started using this toolchain in binary format, one needs:
* Linux kernel 4.1 or newer, with these flags enabled:
  * `CONFIG_BPF=y`
  * `CONFIG_BPF_SYSCALL=y`
  * `CONFIG_NET_CLS_BPF=m` [optional, for tc filters]
  * `CONFIG_NET_ACT_BPF=m` [optional, for tc actions]
  * `CONFIG_BPF_JIT=y`
  * `CONFIG_HAVE_BPF_JIT=y`
  * `CONFIG_BPF_EVENTS=y` [optional, for kprobes]
* Headers for the above kernel
* gcc, make, python
* python-pyroute2 (for some networking features only)

## Getting started

As of this writing, binary packages for the above requirements are available
in unstable formats. Both Ubuntu and Fedora have 4.2-rcX builds with the above
flags defaulted to on. LLVM provides 3.7 Ubuntu packages (but not Fedora yet).

See [INSTALL.md](INSTALL.md) for installation steps on your platform.
