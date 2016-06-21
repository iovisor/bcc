# BPF Features by Linux Kernel Version

Major milestone releases: 4.1, 4.4.

## 3.18

- bpf syscall.

## 3.19

- socket support: bpf can attach to sockets.

## 4.1

- kprobe support: BPF programs can now instrument any kernel function via kernel dynamic tracing.

## 4.3

- debug string support: bpf_trace_printk() supports strings.

## 4.4

- bpf_perf_event_output: used by many tools that print per-event output. Eg, opensnoop.
- unprivileged BPF for sockets: non-root usage for socket-based programs.

## 4.6

- stack traces (BPF_MAP_TYPE_STACK_TRACE): for capturing stack traces as keys in maps. Eg, stackcount.

## 4.7

- tracepoint support (BPF_PROG_TYPE_TRACEPOINT): BPF programs can now use static kernel tracepoints.
