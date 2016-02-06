# Compiling P4 to EBPF

Mihai Budiu - mbudiu@barefootnetworks.com

September 22, 2015

## Abstract

This document describes a prototype compiler that translates programs
written in the P4 programming languages to eBPF programs.  The
translation is performed by generating programs written in a subset of
the C programming language, that are converted to EBPF using the BPF
Compiler Collection tools.

The compiler code is licensed under an [Apache v2.0 license]
(http://www.apache.org/licenses/LICENSE-2.0.html).

## Preliminaries

In this section we give a brief overview of P4 and EBPF.  A detailed
treatment of these topics is outside the scope of this text.

### P4

P4 (http://p4.org) is a domain-specific programming language for
specifying the behavior of the dataplanes of network-forwarding
elements.  The name of the programming language comes from the title
of a paper published in the proceedings of SIGCOMM Computer
Communications Review in 2014:
http://www.sigcomm.org/ccr/papers/2014/July/0000000.0000004:
"Programming Protocol-Independent Packet Processors".

P4 itself is protocol-independent but allows programmers to express a
rich set of data plane behaviors and protocols. The core P4
abstractions are:

* Header definitions describe the format (the set of fields and their
  sizes) of each header within a packet.

* Parse graphs (finite-state machines) describe the permitted header
  sequences within received packets.

* Tables associate keys to actions. P4 tables generalize traditional
  forwarding tables; they can be used to implement routing tables,
  flow lookup tables, access-control lists, etc.

* Actions describe how packet header fields and metadata are manipulated.

* Match-action units stitch together tables and actions, and perform
  the following sequence of operations:

  * Construct lookup keys from packet fields or computed metadata,

  * Use the constructed lookup key to index into tables, choosing an
  action to execute,
  
  * Finally, execute the selected action.

* Control flow is expressed as an imperative program describing the
  data-dependent packet processing within a pipeline, including the
  data-dependent sequence of match-action unit invocations.

P4 programs describe the behavior of network-processing dataplanes.  A
P4 program is designed to operate in concert with a separate *control
plane* program.  The control plane is responsible for managing at
runtime the contents of the P4 tables.  P4 cannot be used to specify
control-planes; however, a P4 program implicitly specifies the
interface between the data-plane and the control-plane.

The P4 language is under active development; the current stable
version is 1.0.2 (see http://p4.org/spec); a reference implementation
of a compiler and associated tools is freely available using a Apache
2 open-source license (see http://p4.org/code).

### EBPF

#### Safe code

EBPF is a acronym that stands for Extended Berkeley Packet Filters.
In essence EBPF is a low-level programming language (similar to
machine code); EBPF programs are traditionally executed by a virtual
machine that resides in the Linux kernel.  EBPF programs can be
inserted and removed from a live kernel using dynamic code
instrumentation.  The main feature of EBPF programs is their *static
safety*: prior to execution all EBPF programs have to be validated as
being safe, and unsafe programs cannot be executed.  A safe program
provably cannot compromise the machine it is running on:

* it can only access a restricted memory region (on the local stack)

* it can run only for a limited amount of time; during execution it
  cannot block, sleep or take any locks

* it cannot use any kernel resources with the exception of a limited
  set of kernel services which have been specifically whitelisted,
  including operations to manipulate tables (described below)

#### Kernel hooks

EBPF programs are inserted into the kernel using *hooks*.  There are
several types of hooks available:

* any function entry point in the kernel can act as a hook; attaching
  an EBPF program to a function `foo()` will cause the EBPF program to
  execute every time some kernel thread executes `foo()`.

* EBPF programs can also be attached using the Linux Traffic Control
  (TC) subsystem, in the network packet processing datapath.  Such
  programs can be used as TC classifiers and actions.

* EBPF programs can also be attached to sockets or network interfaces.
  In this case they can be used for processing packets that flow
  through the socket/interface.

EBPF programs can be used for many purposes; the main use cases are
dynamic tracing and monitoring, and packet processing.  We are mostly
interested in the latter use case in this document.

#### EBPF Tables

The EBPF runtime exposes a bi-directional kernel-userspace data
communication channel, called *tables* (also called maps in some EBPF
documents and code samples).  EBPF tables are essentially key-value
stores, where keys and values are arbitrary fixed-size bitstrings.
The key width, value width and table size (maximum number of entries
that can be stored) are declared statically, at table creation time.

In user-space tables handles are exposed as file descriptors.  Both
user- and kernel-space programs can manipulate tables, by inserting,
deleting, looking up, modifying, and enumerating entries in a table.

In kernel space the keys and values are exposed as pointers to the raw
underlying data stored in the table, whereas in user-space the
pointers point to copies of the data.

#### Concurrency

An important aspect to understand related to EBPF is the execution
model.  An EBPF program is triggered by a kernel hook; multiple
instances of the same kernel hook can be running simultaneously on
different cores.

Each table however has a single instances across all the cores.  A
single table may be accessed simultaneously by multiple instances of
the same EBPF program running as separate kernel threads on different
cores.  EBPF tables are native kernel objects, and access to the table
contents is protected using the kernel RCU mechanism.  This makes
access to table entries safe under concurrent execution; for example,
the memory associated to a value cannot be accidentally freed while an
EBPF program holds a pointer to the respective value.  However,
accessing tables is prone to data races; since EBPF programs cannot
use locks, some of these races often cannot be avoided.

EBPF and the associated tools are also under active development, and
new capabilities are added frequently.  The P4 compiler generates code
that can be compiled using the BPF Compiler Collection (BCC)
(https://github.com/iovisor/bcc)

## Compiling P4 to EBPF

From the above description it is apparent that the P4 and EBPF
programming languages have different expressive powers.  However,
there is a significant overlap in their capabilities, in particular,
in the domain of network packet processing.  The following image
illustrates the situation:

![P4 and EBPF overlap in capabilities](scope.png)

We expect that the overlapping region will grow in size as both P4 and
EBPF continue to mature.

The current version of the P4 to EBPF compiler translates programs
written in the version 1.1 of the P4 programming language to programs
written in a restricted subset of C.  The subset of C is chosen such
that it should be compilable to EBPF using BCC.

```
         --------------              -------
P4 --->  | P4-to-EBPF | ---> C ----> | BCC | --> EBPF
         --------------              -------
```

The P4 program only describes the packet processing *data plane*, that
runs in the Linux kernel.  The *control plane* must be separately
implemented by the user.  The BCC tools simplify this task
considerably, by generating C and/or Python APIs that expose the
dataplane/control-plane APIs.

### Dependencies

EBPF programs require a Linux kernel with version 4.2 or newer.

In order to use the P4 to EBPF compiler the following software must be installed:

* The compiler itself is written in the Python (v2.x) programming
  language.

* the P4 compiler front-end: (https://github.com/p4lang/p4-hlir).
  This is required for parsing the P4 programs.  

* the BCC compiler collection tools: (https://github.com/iovisor/bcc).
  This is required for compiling the generated code.  Also, BCC comes
  with a set of Python utilities which can be used to implement
  control-plane programs that operate in concert with the kernel EBPF
  datapath.

The P4 to EBPF compiler generates code that is designed for being used
as a classifier using the Linux TC subsystem.

Furthermore, the test code provided is written using the Python (v3.x)
programming language and requires several Python packages to be
installed.

### Supported capabilities

The current version of the P4 to EBPF compiler supports a relatively
narrow subset of the P4 language, but still powerful enough to write
very complex packet filters and simple packet forwarding engines.  In
the spirit of open-source "release early, release often", we expect
that the compiler's capabilities will improve gradually.

* Packet filtering is performed using the `drop()` action.  Packets
  that are not dropped will be forwarded.

* Packet forwarding is performed by setting the
  `standard_metadata.egress_port` to the index of the destination
  network interface

Here are some limitations imposed on the P4 programs:

* Currently both the ingress and the egress P4 pipelines are executed
  at the same hook (wherever the user chooses to insert the generated
  EBPF program).  In the future the compiler should probably generate
  two separate EBPF programs.

* arbitrary parsers can be compiled, but the BCC compiler will reject
  parsers that contain cycles

* arithmetic on data wider than 32 bits is not supported

* checksum computations are not implemented.  In consequence, programs
  that IP/TCP/UDP headers will produce incorrect packet headers.

* EBPF does not offer support for ternary or LPM tables

* P4 cloning and recirculation and not supported

* meters and registers are not supported; only direct counters are
  currently supported.  EBPF can potentially support registers and
  arbitrary counters, so these may appear in the future.

* learning (i.e. `generate_digest`) is not implemented

### Translating P4 to C

To simplify the translation, the P4 programmer should refrain using
identifiers whose name starts with `ebpf_`.

The following table provides a brief summary of how each P4 construct
is mapped to a corresponding C construct:

#### Translating parsers

P4 Construct | C Translation
----------|------------
`header_type` | `struct` type
`header`      | `struct` instance with an additional `valid` bit
`metadata`    | `struct` instance
parser state  | code block
state transition | `goto` statement
`extract` | load/shift/mask data from packet buffer

#### Translating match-action pipelines

P4 Construct | C Translation
----------|------------
table  | 2 EBPF tables: second one used just for the default action
table key | `struct` type
table `actions` block | tagged `union` with all possible actions
`action` arguments | `struct`
table `reads` | EBPF table access
`action` body | code block
table `apply` | `switch` statement
counters | additional EBPF table

### Code organization

The compiler code is organized in two folders:

* `compiler`: the complete compiler source code, in Python v2.x
  The compiler entry point is `p4toEbpf.py`.

* `test`: testing code and data.  There are two testing programs:
  * `testP4toEbpf.py`: which compiles all P4 files in the testprograms folder

  * `endToEndTest.py`: which compiles and executes the simple.p4
  program, and includes a simple control plane

Currently the compiler contains no installation capabilities.

### Invoking the compiler

Invoking the compiler is just a matter of invoking the python program
with a suitable input P4 file:

```
p4toEbpf.py file.p4 -o file.c
```

#### Compiler options

The P4 compiler first runs the C preprocessor on the input P4 file.
Some of the command-line options are passed directly to the
preprocessor.

The following compiler options are available:

Option | Meaning
-------|--------
`-D macro` | Option passed to C preprocessor
`-I path`  | Option passed to C preprocessor
`-U macro` | Option passed to C preprocessor
`-g [router|filter]` | Controls whether the generated code behaves like a router or a filter.
`-o outoutFile` | writes the generated C code to the specified output file.

The `-g` option controls the nature of the generated code:

* `-g filter` generates a filter; the only P4 action that has an
  effect is the `drop()` action.  Setting metadata in P4 (e.g.,
  `egress_port`) has no effect.

* `-g router` generates a simple router; both `drop()` and
  `egress_port` impact packet processing.

#### Using the generated code

The resulting file contains the complete data structures, tables, and
a C function named `ebpf_filter` that implements the P4-specified
data-plane.  This C file can be manipulated using the BCC tools;
please refer to the BCC project documentation and sample test files of
the P4 to EBPF source code for an in-depth understanding.  A minimal
Python program that compiles and loads into the kernel the generated
file into EBPF is:

```
#!/usr/bin/env python3
from bcc import BPF

b = BPF(src_file="file.c", debug=0)
fn = b.load_func("ebpf_filter", BPF.SCHED_CLS)
```

##### Connecting the generated program with the TC

The EBPF code that is generated is intended to be used as a classifier
attached to the ingress packet path using the Linux TC subsystem.  The
same EBPF code should be attached to all interfaces.  Note however
that all EBPF code instances share a single set of tables, which are
used to control the program behavior.

The following code fragment illustrates how the EBPF code can be
hooked up to the `eth0` interface using a Python program.  (The `fn`
variable is the one produced by the previous code fragment).

```
from pyroute2 import IPRoute

ipr = IPRoute()
interface_name="eth0"
if_index = ipr.link_lookup(ifname=interface_name)[0]
ipr.tc("add", "ingress", if_index, "ffff:")
ipr.tc("add-filter", "bpf", if_index, ":1", fd=fn.fd,
       name=fn.name, parent="ffff:", action="ok", classid=1)
```
