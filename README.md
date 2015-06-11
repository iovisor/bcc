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
  * `CONFIG_BPF=y`
  * `CONFIG_BPF_SYSCALL=y`
  * `CONFIG_NET_CLS_BPF=m` [optional, for tc filters]
  * `CONFIG_NET_ACT_BPF=m` [optional, for tc actions]
  * `CONFIG_BPF_JIT=y`
  * `CONFIG_HAVE_BPF_JIT=y`
  * `CONFIG_BPF_EVENTS=y` [optional, for kprobes]
* Linux kernel headers, 4.1 or newer
* LLVM 3.7 or newer, compiled with BPF support (default=on)
* Clang 3.7, built from the same tree as LLVM
* pyroute2, version X.X (currently master, tag TBD) or newer
* cmake, gcc-4.7, flex, bison

## Getting started

### Demo VM

See https://github.com/iovisor/bcc/scripts/README.md for a script that can
be used to set up a libvirt VM with the required dependencies.

### Quick Setup

If the LLVM and Linux kernel requirements are satisfied, testing out this
package should be as simple as:

```
git clone https://github.com/iovisor/bcc.git
cd bcc; mkdir build; cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_PREFIX_PATH=/opt/local/llvm
make -j$(grep -c ^processor /proc/cpuinfo)
sudo make install
cd ../
sudo python examples/hello_world.py
<ctrl-C>
```

Change `CMAKE_PREFIX_PATH` if llvm is installed elsewhere.

### Cleaning up

Since packaging is currently not available, one can cleanup the collateral of
bcc by doing:

```
sudo rm -rf /usr/{lib/libbpf.prog.so,include/bcc,share/bcc}
sudo pip uninstall bpf
```

### Building LLVM

See http://llvm.org/docs/GettingStarted.html for the full guide.

The short version:

```
git clone https://github.com/llvm-mirror/llvm.git llvm
git clone https://github.com/llvm-mirror/clang.git llvm/tools/clang
mkdir llvm/build/
cd llvm/build/
cmake .. -DCMAKE_INSTALL_PREFIX=/opt/local/llvm
make -j$(grep -c ^processor /proc/cpuinfo)
sudo make install
```

## Release notes

* 0.1
  * Initial commit
