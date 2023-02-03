# Kernel Configuration for BPF Features

## BPF Related Kernel Configurations

| Functionalities | Kernel Configuration | Description |
|:----------------|:---------------------|:------------|
| **Basic** | CONFIG_BPF_SYSCALL | Enable the bpf() system call |
|  | CONFIG_BPF_JIT | BPF programs are normally handled by a BPF interpreter. This option allows the kernel to generate native code when a program is loaded into the kernel. This will significantly speed-up processing of BPF programs |
|  | CONFIG_HAVE_BPF_JIT | Enable BPF Just In Time compiler |
|  | CONFIG_HAVE_EBPF_JIT | Extended BPF JIT (eBPF) |
|  | CONFIG_HAVE_CBPF_JIT | Classic BPF JIT (cBPF) |
|  | CONFIG_MODULES | Enable to build loadable kernel modules |
|  | CONFIG_BPF | BPF VM interpreter |
|  | CONFIG_BPF_EVENTS | Allow the user to attach BPF programs to kprobe, uprobe, and tracepoint events |
|  | CONFIG_PERF_EVENTS | Kernel performance events and counters |
|  | CONFIG_HAVE_PERF_EVENTS | Enable perf events |
|  | CONFIG_PROFILING | Enable the extended profiling support mechanisms used by profilers |
| **BTF** | CONFIG_DEBUG_INFO_BTF | Generate deduplicated BTF type information from DWARF debug info |
| | CONFIG_PAHOLE_HAS_SPLIT_BTF | Generate BTF for each selected kernel module |
| | CONFIG_DEBUG_INFO_BTF_MODULES | Generate compact split BTF type information for kernel modules |
| **Security** | CONFIG_BPF_JIT_ALWAYS_ON | Enable BPF JIT and removes BPF interpreter to avoid speculative execution |
| | CONFIG_BPF_UNPRIV_DEFAULT_OFF | Disable unprivileged BPF by default by setting |
| **Cgroup** | CONFIG_CGROUP_BPF | Support for BPF programs attached to cgroups |
| **Network** | CONFIG_BPFILTER | BPF based packet filtering framework (BPFILTER) |
| | CONFIG_BPFILTER_UMH | This builds bpfilter kernel module with embedded user mode helper |
| | CONFIG_NET_CLS_BPF | BPF-based classifier - to classify packets based on programmable BPF (JIT'ed) filters as an alternative to ematches |
| | CONFIG_NET_ACT_BPF | Execute BPF code on packets. The BPF code will decide if the packet should be dropped or not |
| | CONFIG_BPF_STREAM_PARSER | Enable this to allow a TCP stream parser to be used with BPF_MAP_TYPE_SOCKMAP |
| | CONFIG_LWTUNNEL_BPF | Allow to run BPF programs as a nexthop action following a route lookup for incoming and outgoing packets |
| | CONFIG_NETFILTER_XT_MATCH_BPF | BPF matching applies a linux socket filter to each packet and accepts those for which the filter returns non-zero |
| | CONFIG_IPV6_SEG6_BPF | To support  BPF seg6local hook. bpf: Add IPv6 Segment Routing helpersy. [Reference](https://github.com/torvalds/linux/commit/fe94cc290f535709d3c5ebd1e472dfd0aec7ee7) |
| **kprobes** | CONFIG_KPROBE_EVENTS | This allows the user to add tracing events (similar to tracepoints) on the fly via the ftrace interface |
|  | CONFIG_KPROBES | Enable kprobes-based dynamic events |
|  | CONFIG_HAVE_KPROBES | Check if krpobes enabled |
|  | CONFIG_HAVE_REGS_AND_STACK_ACCESS_API | This symbol should be selected by an architecture if it supports the API needed to access registers and stack entries from pt_regs. For example the kprobes-based event tracer needs this API. |
|  | CONFIG_KPROBES_ON_FTRACE | Have kprobes on function tracer if arch supports full passing of pt_regs to function tracing |
| **kprobe multi** | CONFIG_FPROBE | Enable fprobe to attach the probe on multiple functions at once |
| **kprobe override** | CONFIG_BPF_KPROBE_OVERRIDE | Enable BPF programs to override a kprobed function |
| **uprobes** | CONFIG_UPROBE_EVENTS | Enable uprobes-based dynamic events |
|  | CONFIG_ARCH_SUPPORTS_UPROBES | Arch specific uprobes support |
|  | CONFIG_UPROBES | Uprobes is the user-space counterpart to kprobes: they enable instrumentation applications (such as 'perf probe') to establish unintrusive probes in user-space binaries and libraries, by executing handler functions when the probes are hit by user-space applications. |
|  | CONFIG_MMU | MMU-based virtualised addressing space support by paged memory management |
| **Tracepoints** | CONFIG_TRACEPOINTS | Enable inserting tracepoints in the kernel and connect to proble functions |
|  | CONFIG_HAVE_SYSCALL_TRACEPOINTS | Enable syscall enter/exit tracing |
| **Raw Tracepoints** | Same as Tracepoints | |
| **LSM** | CONFIG_BPF_LSM | Enable instrumentation of the security hooks with BPF programs for implementing dynamic MAC and Audit Policies |
| **LIRC** | CONFIG_BPF_LIRC_MODE2 | Allow attaching BPF programs to a lirc device |

