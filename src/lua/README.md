Lua Tools for BCC
-----------------

This directory contains Lua tooling for [BCC](https://github.com/iovisor/bcc)
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
    echo "deb http://52.8.15.63/apt trusty main" | sudo tee /etc/apt/sources.list.d/iovisor.list
    sudo apt-get update
    sudo apt-get install libbcc luajit
    ```

3. Test one of the examples to ensure `libbcc` is properly installed

    ```
    sudo ./bcc-probe examples/lua/task_switch.lua
    ```
