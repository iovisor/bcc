# BPF Compiler Collection (BCC)

This directory contains source code for BCC, a toolkit for creating small
programs that can be dynamically loaded into a Linux kernel.

The compiler relies upon eBPF (Extended Berkeley Packet Filters), which is a
feature in Linux kernels starting from 3.19. Currently, this compiler leverages
features which are mostly available in Linux 4.1 and above.

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

In the future, more bindings besides python will likely be supported. Feel free
to add support for the language of your choice and send a pull request!

## Examples

This toolchain is currently composed of two parts: a C wrapper around LLVM, and
a Python API to interact with the running program. Later, we will go into more
detail of how this all works.

### Hello, World

First, we should include the BPF class from the bpf module:
```python
from bpf import BPF
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
fn = b.load_func("hello", BPF.KPROBE)
BPF.attach_kprobe(fn, "sys_clone")
```

The python process will then print the trace printk circular buffer until ctrl-c
is pressed. The BPF program is removed from the kernel when the userspace
process that loaded it closes the fd (or exits).
```python
from subprocess import call
try:
    call(["cat", "/sys/kernel/debug/tracing/trace_pipe"])
except KeyboardInterrupt:
    pass
```

Output:
```
bcc/examples$ sudo python hello_world.py 
          python-7282  [002] d...  3757.488508: : Hello, World!
```

[Source code listing](examples/hello_world.py)

### Networking

Walkthrough TBD, see
[Neighbor Sharing example](examples/tc_neighbor_sharing.py) for longer
example.

### Tracing

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

### Ubuntu - Docker edition

The build dependencies are captured in a [Dockerfile](Dockerfile.ubuntu), the
output of which is a .deb for easy installation.

* Start with a recent Ubuntu install (tested with 14.04 LTS)
* Install a [>= 4.2 kernel](http://kernel.ubuntu.com/~kernel-ppa/mainline/)
  with headers
* Reboot
* Install [docker](https://docs.docker.com/installation/ubuntulinux/)
  (`wget -qO- https://get.docker.com/ | sh`)
* Run the Dockerfile for Ubuntu - results in an installable .deb
  * `git clone https://github.com/iovisor/bcc; cd bcc`
  * `docker build -t bcc -f Dockerfile.ubuntu .`
  * `docker run --rm -v /tmp:/mnt bcc sh -c "cp /root/bcc/build/*.deb /mnt"`
  * `sudo dpkg -i /tmp/libbcc*.deb`
* Run the example
  * `sudo python /usr/share/bcc/examples/hello_world.py`

### Fedora - Docker edition

The build dependencies are captured in a [Dockerfile](Dockerfile.fedora), the
output of which is a .rpm for easy installation. This version takes longer since
LLVM needs to be compiled from source.

* Start with a recent Fedora install (tested with F22)
* Install a [>= 4.2 kernel](http://alt.fedoraproject.org/pub/alt/rawhide-kernel-nodebug/x86_64/)
  with headers
* Reboot
* Install [docker](https://docs.docker.com/installation/fedora/)
* Run the Dockerfile for Fedora - results in an installable .rpm
  * `git clone https://github.com/iovisor/bcc; cd bcc`
  * `docker build -t bcc -f Dockerfile.fedora .`
  * `docker run --rm -v /tmp:/mnt bcc sh -c "cp /root/bcc/build/*.rpm /mnt"`
  * `sudo rpm -ivh /tmp/libbcc*.rpm`
* Run the example
  * `sudo python /usr/share/bcc/examples/hello_world.py`

### Ubuntu - From source

To build the toolchain from source, one needs:
* LLVM 3.7 or newer, compiled with BPF support (default=on)
* Clang 3.7, built from the same tree as LLVM
* cmake, gcc (>=4.7), flex, bison

* Add the [LLVM binary repo](http://llvm.org/apt/) to your apt sources
  * `echo "deb http://llvm.org/apt/trusty/ llvm-toolchain-trusty main" \
    | sudo tee /etc/apt/sources.list.d/llvm.list`
  * `wget -O - http://llvm.org/apt/llvm-snapshot.gpg.key | sudo apt-key add -`
  * `sudo apt-get update`
* Install build dependencies
  * `sudo apt-get -y install bison build-essential cmake flex git \
    libedit-dev python zlib1g-dev`
* Install LLVM and Clang development libs
  * `sudo apt-get -y install libllvm3.7 llvm-3.7-dev libclang-3.7-dev`
* Install and compile BCC
  * `git clone https://github.com/iovisor/bcc.git`
  * `mkdir bcc/build; cd bcc/build`
  * `cmake .. -DCMAKE_INSTALL_PREFIX=/usr`
  * `make -j$(grep -c ^process /proc/cpuinfo)`
  * `sudo make install`

## Release notes

* 0.1
  * Initial commit
