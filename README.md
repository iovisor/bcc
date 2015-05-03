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

The features of this toolkit include:
* End-to-end BPF workflow in a shared library
  * The B language - a C-like language for BPF backends
  * Integration with llvm-bpf backend for JIT
  * Dynamic (un)loading of JITed programs
  * Support for BPF kernel hooks: socket filters, tc classifiers,
      tc actions, and kprobes
* Bindings for Python
* Examples for socket filters, tc classifiers, and kprobes
* Test cases!

## Requirements

To get started using this toolchain, one needs:
* Linux kernel 4.1 or newer, with these flags enabled:
  * CONFIG_BPF=y
  * CONFIG_BPF_SYSCALL=y
  * CONFIG_NET_CLS_BPF=m [optional, for tc filters]
  * CONFIG_NET_ACT_BPF=m [optional, for tc actions]
  * CONFIG_BPF_JIT=y
  * CONFIG_HAVE_BPF_JIT=y
  * CONFIG_BPF_EVENTS=y [optional, for kprobes]
* LLVM 3.7 or newer, compiled with BPF support (currently experimental)
* Clang 3.5 or newer (this requirement is orthoganal to the LLVM requirement,
                      and the versions do not necessarily need to match)
* cmake, gcc-4.9, flex, bison, xxd, libstdc++-static, libmnl-devel

## Getting started

Included in the scripts/ directory of this project is a VM kickstart script that
captures the above requirements inside a Fedora VM. Before running the script,
ensure that virt-install is available on the system.

`./build_bpf_demo.sh -n bpf-demo -k bpf_demo.ks.erb`

After setting up the initial VM, log in (the default password is 'iovisor')
and determine the DHCP IP. SSH to this IP as root.

To set up a kernel with the right options, run `bpf-kernel-setup`.

```
[root@bpf-demo ~]# bpf-kernel-setup
Cloning into 'net-next'...
```
After pulling the net-next branch, the kernel config menu should pop up. Ensure
that the below settings are proper.
```
General setup --->
  [*] Enable bpf() system call
Networking support --->
  Networking options --->
    QoS and/or fair queueing --->
      <M> BPF-based classifier
      <M> BPF based action
    [*] enable BPF Just In Time compiler
```
Once the .config is saved, the build will proceed and install the resulting
kernel. This kernel has updated userspace headers (e.g. the bpf() syscall) which
install into /usr/local/include...proper packaging for this will be
distro-dependent.

Next, run `bpf-llvm-setup` to pull and compile LLVM with BPF support enabled.
```
[root@bpf-demo ~]# bpf-llvm-setup
Cloning into 'llvm'...
```
The resulting libraries will be installed into /opt/local/llvm.

Next, reboot into the new kernel, either manually or by using the kexec helper.
```
[root@bpf-demo ~]# kexec-4.1.0-rc1+
Connection to 192.168.122.247 closed by remote host.
Connection to 192.168.122.247 closed.
```

Reconnect and run the final step, building and testing bcc.
```
[root@bpf-demo ~]# bcc-setup
Cloning into 'bcc'...
...
Linking CXX shared library libbpfprog.so
[100%] Built target bpfprog
...
Running tests...
Test project /root/bcc/build
    Start 1: py_test1
1/4 Test #1: py_test1 .........................   Passed    0.24 sec
    Start 2: py_test2
2/4 Test #2: py_test2 .........................   Passed    0.53 sec
    Start 3: py_trace1
3/4 Test #3: py_trace1 ........................   Passed    0.09 sec
    Start 4: py_trace2
4/4 Test #4: py_trace2 ........................   Passed    1.06 sec

100% tests passed, 0 tests failed out of 4
```


## Release notes

* 0.1
  * Initial commit
