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

## Release notes

* 0.1
  * Initial commit
