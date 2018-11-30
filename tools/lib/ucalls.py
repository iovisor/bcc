#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# ucalls  Summarize method calls in high-level languages and/or system calls.
#         For Linux, uses BCC, eBPF.
#
# USAGE: ucalls [-l {java,perl,php,python,ruby,tcl}] [-h] [-T TOP] [-L] [-S] [-v] [-m]
#        pid [interval]
#
# Copyright 2016 Sasha Goldshtein
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 19-Oct-2016   Sasha Goldshtein   Created this.

from __future__ import print_function
import argparse
from bcc import BPF, USDT, utils
from time import sleep
import os
import subprocess
import platform

#
# Syscall table for Linux x86_64, not very recent.
# Automatically generated from strace/linux/x86_64/syscallent.h using the
# following command:
#
#  cat syscallent.h | awk -F, '{ gsub(/[ \t"}]/, "", $4);
#                                gsub(/[ \t/*]/, "", $5);
#                                print "    "$5": \""$4"\","; }
#                              BEGIN { print "syscalls = {" }
#                              END { print "}" }'
#
syscalls = {
    0: b"read",
    1: b"write",
    2: b"open",
    3: b"close",
    4: b"stat",
    5: b"fstat",
    6: b"lstat",
    7: b"poll",
    8: b"lseek",
    9: b"mmap",
    10: b"mprotect",
    11: b"munmap",
    12: b"brk",
    13: b"rt_sigaction",
    14: b"rt_sigprocmask",
    15: b"rt_sigreturn",
    16: b"ioctl",
    17: b"pread",
    18: b"pwrite",
    19: b"readv",
    20: b"writev",
    21: b"access",
    22: b"pipe",
    23: b"select",
    24: b"sched_yield",
    25: b"mremap",
    26: b"msync",
    27: b"mincore",
    28: b"madvise",
    29: b"shmget",
    30: b"shmat",
    31: b"shmctl",
    32: b"dup",
    33: b"dup2",
    34: b"pause",
    35: b"nanosleep",
    36: b"getitimer",
    37: b"alarm",
    38: b"setitimer",
    39: b"getpid",
    40: b"sendfile",
    41: b"socket",
    42: b"connect",
    43: b"accept",
    44: b"sendto",
    45: b"recvfrom",
    46: b"sendmsg",
    47: b"recvmsg",
    48: b"shutdown",
    49: b"bind",
    50: b"listen",
    51: b"getsockname",
    52: b"getpeername",
    53: b"socketpair",
    54: b"setsockopt",
    55: b"getsockopt",
    56: b"clone",
    57: b"fork",
    58: b"vfork",
    59: b"execve",
    60: b"_exit",
    61: b"wait4",
    62: b"kill",
    63: b"uname",
    64: b"semget",
    65: b"semop",
    66: b"semctl",
    67: b"shmdt",
    68: b"msgget",
    69: b"msgsnd",
    70: b"msgrcv",
    71: b"msgctl",
    72: b"fcntl",
    73: b"flock",
    74: b"fsync",
    75: b"fdatasync",
    76: b"truncate",
    77: b"ftruncate",
    78: b"getdents",
    79: b"getcwd",
    80: b"chdir",
    81: b"fchdir",
    82: b"rename",
    83: b"mkdir",
    84: b"rmdir",
    85: b"creat",
    86: b"link",
    87: b"unlink",
    88: b"symlink",
    89: b"readlink",
    90: b"chmod",
    91: b"fchmod",
    92: b"chown",
    93: b"fchown",
    94: b"lchown",
    95: b"umask",
    96: b"gettimeofday",
    97: b"getrlimit",
    98: b"getrusage",
    99: b"sysinfo",
    100: b"times",
    101: b"ptrace",
    102: b"getuid",
    103: b"syslog",
    104: b"getgid",
    105: b"setuid",
    106: b"setgid",
    107: b"geteuid",
    108: b"getegid",
    109: b"setpgid",
    110: b"getppid",
    111: b"getpgrp",
    112: b"setsid",
    113: b"setreuid",
    114: b"setregid",
    115: b"getgroups",
    116: b"setgroups",
    117: b"setresuid",
    118: b"getresuid",
    119: b"setresgid",
    120: b"getresgid",
    121: b"getpgid",
    122: b"setfsuid",
    123: b"setfsgid",
    124: b"getsid",
    125: b"capget",
    126: b"capset",
    127: b"rt_sigpending",
    128: b"rt_sigtimedwait",
    129: b"rt_sigqueueinfo",
    130: b"rt_sigsuspend",
    131: b"sigaltstack",
    132: b"utime",
    133: b"mknod",
    134: b"uselib",
    135: b"personality",
    136: b"ustat",
    137: b"statfs",
    138: b"fstatfs",
    139: b"sysfs",
    140: b"getpriority",
    141: b"setpriority",
    142: b"sched_setparam",
    143: b"sched_getparam",
    144: b"sched_setscheduler",
    145: b"sched_getscheduler",
    146: b"sched_get_priority_max",
    147: b"sched_get_priority_min",
    148: b"sched_rr_get_interval",
    149: b"mlock",
    150: b"munlock",
    151: b"mlockall",
    152: b"munlockall",
    153: b"vhangup",
    154: b"modify_ldt",
    155: b"pivot_root",
    156: b"_sysctl",
    157: b"prctl",
    158: b"arch_prctl",
    159: b"adjtimex",
    160: b"setrlimit",
    161: b"chroot",
    162: b"sync",
    163: b"acct",
    164: b"settimeofday",
    165: b"mount",
    166: b"umount",
    167: b"swapon",
    168: b"swapoff",
    169: b"reboot",
    170: b"sethostname",
    171: b"setdomainname",
    172: b"iopl",
    173: b"ioperm",
    174: b"create_module",
    175: b"init_module",
    176: b"delete_module",
    177: b"get_kernel_syms",
    178: b"query_module",
    179: b"quotactl",
    180: b"nfsservctl",
    181: b"getpmsg",
    182: b"putpmsg",
    183: b"afs_syscall",
    184: b"tuxcall",
    185: b"security",
    186: b"gettid",
    187: b"readahead",
    188: b"setxattr",
    189: b"lsetxattr",
    190: b"fsetxattr",
    191: b"getxattr",
    192: b"lgetxattr",
    193: b"fgetxattr",
    194: b"listxattr",
    195: b"llistxattr",
    196: b"flistxattr",
    197: b"removexattr",
    198: b"lremovexattr",
    199: b"fremovexattr",
    200: b"tkill",
    201: b"time",
    202: b"futex",
    203: b"sched_setaffinity",
    204: b"sched_getaffinity",
    205: b"set_thread_area",
    206: b"io_setup",
    207: b"io_destroy",
    208: b"io_getevents",
    209: b"io_submit",
    210: b"io_cancel",
    211: b"get_thread_area",
    212: b"lookup_dcookie",
    213: b"epoll_create",
    214: b"epoll_ctl_old",
    215: b"epoll_wait_old",
    216: b"remap_file_pages",
    217: b"getdents64",
    218: b"set_tid_address",
    219: b"restart_syscall",
    220: b"semtimedop",
    221: b"fadvise64",
    222: b"timer_create",
    223: b"timer_settime",
    224: b"timer_gettime",
    225: b"timer_getoverrun",
    226: b"timer_delete",
    227: b"clock_settime",
    228: b"clock_gettime",
    229: b"clock_getres",
    230: b"clock_nanosleep",
    231: b"exit_group",
    232: b"epoll_wait",
    233: b"epoll_ctl",
    234: b"tgkill",
    235: b"utimes",
    236: b"vserver",
    237: b"mbind",
    238: b"set_mempolicy",
    239: b"get_mempolicy",
    240: b"mq_open",
    241: b"mq_unlink",
    242: b"mq_timedsend",
    243: b"mq_timedreceive",
    244: b"mq_notify",
    245: b"mq_getsetattr",
    246: b"kexec_load",
    247: b"waitid",
    248: b"add_key",
    249: b"request_key",
    250: b"keyctl",
    251: b"ioprio_set",
    252: b"ioprio_get",
    253: b"inotify_init",
    254: b"inotify_add_watch",
    255: b"inotify_rm_watch",
    256: b"migrate_pages",
    257: b"openat",
    258: b"mkdirat",
    259: b"mknodat",
    260: b"fchownat",
    261: b"futimesat",
    262: b"newfstatat",
    263: b"unlinkat",
    264: b"renameat",
    265: b"linkat",
    266: b"symlinkat",
    267: b"readlinkat",
    268: b"fchmodat",
    269: b"faccessat",
    270: b"pselect6",
    271: b"ppoll",
    272: b"unshare",
    273: b"set_robust_list",
    274: b"get_robust_list",
    275: b"splice",
    276: b"tee",
    277: b"sync_file_range",
    278: b"vmsplice",
    279: b"move_pages",
    280: b"utimensat",
    281: b"epoll_pwait",
    282: b"signalfd",
    283: b"timerfd_create",
    284: b"eventfd",
    285: b"fallocate",
    286: b"timerfd_settime",
    287: b"timerfd_gettime",
    288: b"accept4",
    289: b"signalfd4",
    290: b"eventfd2",
    291: b"epoll_create1",
    292: b"dup3",
    293: b"pipe2",
    294: b"inotify_init1",
    295: b"preadv",
    296: b"pwritev",
    297: b"rt_tgsigqueueinfo",
    298: b"perf_event_open",
    299: b"recvmmsg",
    300: b"fanotify_init",
    301: b"fanotify_mark",
    302: b"prlimit64",
    303: b"name_to_handle_at",
    304: b"open_by_handle_at",
    305: b"clock_adjtime",
    306: b"syncfs",
    307: b"sendmmsg",
    308: b"setns",
    309: b"getcpu",
    310: b"process_vm_readv",
    311: b"process_vm_writev",
    312: b"kcmp",
    313: b"finit_module",
}

# Try to use ausyscall if it is available, because it can give us an up-to-date
# list of syscalls for various architectures, rather than the x86-64 hardcoded
# list above.
def parse_syscall(line):
    parts = line.split()
    return (int(parts[0]), parts[1].strip())

try:
    # Skip the first line, which is a header. The rest of the lines are simply
    # SYSCALL_NUM\tSYSCALL_NAME pairs.
    out = subprocess.check_output('ausyscall --dump | tail -n +2', shell=True)
    syscalls = dict(map(parse_syscall, out.strip().split(b'\n')))
except Exception as e:
    if platform.machine() == "x86_64":
        pass
    else:
        raise Exception("ausyscall: command not found")

def syscall_name(value):
    return syscalls.get(value, b"[unknown: %d]" % value)

languages = ["java", "perl", "php", "python", "ruby", "tcl"]

examples = """examples:
    ./ucalls -l java 185        # trace Java calls and print statistics on ^C
    ./ucalls -l python 2020 1   # trace Python calls and print every second
    ./ucalls -l java 185 -S     # trace Java calls and syscalls
    ./ucalls 6712 -S            # trace only syscall counts
    ./ucalls -l ruby 1344 -T 10 # trace top 10 Ruby method calls
    ./ucalls -l ruby 1344 -L    # trace Ruby calls including latency
    ./ucalls -l php 443 -LS     # trace PHP calls and syscalls with latency
    ./ucalls -l python 2020 -mL # trace Python calls including latency in ms
"""
parser = argparse.ArgumentParser(
    description="Summarize method calls in high-level languages.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("pid", type=int, help="process id to attach to")
parser.add_argument("interval", type=int, nargs='?',
    help="print every specified number of seconds")
parser.add_argument("-l", "--language", choices=languages + ["none"],
    help="language to trace (if none, trace syscalls only)")
parser.add_argument("-T", "--top", type=int,
    help="number of most frequent/slow calls to print")
parser.add_argument("-L", "--latency", action="store_true",
    help="record method latency from enter to exit (except recursive calls)")
parser.add_argument("-S", "--syscalls", action="store_true",
    help="record syscall latency (adds overhead)")
parser.add_argument("-v", "--verbose", action="store_true",
    help="verbose mode: print the BPF program (for debugging purposes)")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="report times in milliseconds (default is microseconds)")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()

language = args.language
if not language:
    language = utils.detect_language(languages, args.pid)

# We assume that the entry and return probes have the same arguments. This is
# the case for Java, Python, Ruby, and PHP. If there's a language where it's
# not the case, we will need to build a custom correlator from entry to exit.
extra_message = ""
if language == "java":
    # TODO for JVM entries, we actually have the real length of the class
    #      and method strings in arg3 and arg5 respectively, so we can insert
    #      the null terminator in its proper position.
    entry_probe = "method__entry"
    return_probe = "method__return"
    read_class = "bpf_usdt_readarg(2, ctx, &clazz);"
    read_method = "bpf_usdt_readarg(4, ctx, &method);"
    extra_message = ("If you do not see any results, make sure you ran java"
                     " with option -XX:+ExtendedDTraceProbes")
elif language == "perl":
    entry_probe = "sub__entry"
    return_probe = "sub__return"
    read_class = "bpf_usdt_readarg(2, ctx, &clazz);"    # filename really
    read_method = "bpf_usdt_readarg(1, ctx, &method);"
elif language == "php":
    entry_probe = "function__entry"
    return_probe = "function__return"
    read_class = "bpf_usdt_readarg(4, ctx, &clazz);"
    read_method = "bpf_usdt_readarg(1, ctx, &method);"
    extra_message = ("If you do not see any results, make sure the environment"
                     " variable USE_ZEND_DTRACE is set to 1")
elif language == "python":
    entry_probe = "function__entry"
    return_probe = "function__return"
    read_class = "bpf_usdt_readarg(1, ctx, &clazz);"    # filename really
    read_method = "bpf_usdt_readarg(2, ctx, &method);"
elif language == "ruby":
    # TODO Also probe cmethod__entry and cmethod__return with same arguments
    entry_probe = "method__entry"
    return_probe = "method__return"
    read_class = "bpf_usdt_readarg(1, ctx, &clazz);"
    read_method = "bpf_usdt_readarg(2, ctx, &method);"
elif language == "tcl":
    # TODO Also consider probe cmd__entry and cmd__return with same arguments
    entry_probe = "proc__entry"
    return_probe = "proc__return"
    read_class = ""  # no class/file info available
    read_method = "bpf_usdt_readarg(1, ctx, &method);"
elif not language or language == "none":
    if not args.syscalls:
        print("Nothing to do; use -S to trace syscalls.")
        exit(1)
    entry_probe, return_probe, read_class, read_method = ("", "", "", "")
    if language:
        language = None

program = """
#include <linux/ptrace.h>

#define MAX_STRING_LENGTH 80
DEFINE_NOLANG
DEFINE_LATENCY
DEFINE_SYSCALLS

struct method_t {
    char clazz[MAX_STRING_LENGTH];
    char method[MAX_STRING_LENGTH];
};
struct entry_t {
    u64 pid;
    struct method_t method;
};
struct info_t {
    u64 num_calls;
    u64 total_ns;
};
struct syscall_entry_t {
    u64 timestamp;
    u64 id;
};

#ifndef LATENCY
  BPF_HASH(counts, struct method_t, u64);            // number of calls
  #ifdef SYSCALLS
    BPF_HASH(syscounts, u64, u64);                   // number of calls per IP
  #endif  // SYSCALLS
#else
  BPF_HASH(times, struct method_t, struct info_t);
  BPF_HASH(entry, struct entry_t, u64);              // timestamp at entry
  #ifdef SYSCALLS
    BPF_HASH(systimes, u64, struct info_t);          // latency per IP
    BPF_HASH(sysentry, u64, struct syscall_entry_t); // ts + IP at entry
  #endif  // SYSCALLS
#endif

#ifndef NOLANG
int trace_entry(struct pt_regs *ctx) {
    u64 clazz = 0, method = 0, val = 0;
    u64 *valp;
    struct entry_t data = {0};
#ifdef LATENCY
    u64 timestamp = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid();
#endif
    READ_CLASS
    READ_METHOD
    bpf_probe_read(&data.method.clazz, sizeof(data.method.clazz),
                   (void *)clazz);
    bpf_probe_read(&data.method.method, sizeof(data.method.method),
                   (void *)method);
#ifndef LATENCY
    valp = counts.lookup_or_init(&data.method, &val);
    ++(*valp);
#endif
#ifdef LATENCY
    entry.update(&data, &timestamp);
#endif
    return 0;
}

#ifdef LATENCY
int trace_return(struct pt_regs *ctx) {
    u64 *entry_timestamp, clazz = 0, method = 0;
    struct info_t *info, zero = {};
    struct entry_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    READ_CLASS
    READ_METHOD
    bpf_probe_read(&data.method.clazz, sizeof(data.method.clazz),
                   (void *)clazz);
    bpf_probe_read(&data.method.method, sizeof(data.method.method),
                   (void *)method);
    entry_timestamp = entry.lookup(&data);
    if (!entry_timestamp) {
        return 0;   // missed the entry event
    }
    info = times.lookup_or_init(&data.method, &zero);
    info->num_calls += 1;
    info->total_ns += bpf_ktime_get_ns() - *entry_timestamp;
    entry.delete(&data);
    return 0;
}
#endif  // LATENCY
#endif  // NOLANG

#ifdef SYSCALLS
TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 *valp, id = args->id, val = 0;
    PID_FILTER
#ifdef LATENCY
    struct syscall_entry_t data = {};
    data.timestamp = bpf_ktime_get_ns();
    data.id = id;
    sysentry.update(&pid, &data);
#endif
#ifndef LATENCY
    valp = syscounts.lookup_or_init(&id, &val);
    ++(*valp);
#endif
    return 0;
}

#ifdef LATENCY
TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    struct syscall_entry_t *e;
    struct info_t *info, zero = {};
    u64 pid = bpf_get_current_pid_tgid(), id;
    PID_FILTER
    e = sysentry.lookup(&pid);
    if (!e) {
        return 0;   // missed the entry event
    }
    id = e->id;
    info = systimes.lookup_or_init(&id, &zero);
    info->num_calls += 1;
    info->total_ns += bpf_ktime_get_ns() - e->timestamp;
    sysentry.delete(&pid);
    return 0;
}
#endif  // LATENCY
#endif  // SYSCALLS
""".replace("READ_CLASS", read_class) \
   .replace("READ_METHOD", read_method) \
   .replace("PID_FILTER", "if ((pid >> 32) != %d) { return 0; }" % args.pid) \
   .replace("DEFINE_NOLANG", "#define NOLANG" if not language else "") \
   .replace("DEFINE_LATENCY", "#define LATENCY" if args.latency else "") \
   .replace("DEFINE_SYSCALLS", "#define SYSCALLS" if args.syscalls else "")

if language:
    usdt = USDT(pid=args.pid)
    usdt.enable_probe_or_bail(entry_probe, "trace_entry")
    if args.latency:
        usdt.enable_probe_or_bail(return_probe, "trace_return")
else:
    usdt = None

if args.ebpf or args.verbose:
    if args.verbose and usdt:
        print(usdt.get_text())
    print(program)
    if args.ebpf:
        exit()

bpf = BPF(text=program, usdt_contexts=[usdt] if usdt else [])
if args.syscalls:
    print("Attached kernel tracepoints for syscall tracing.")

def get_data():
    # Will be empty when no language was specified for tracing
    if args.latency:
        data = list(map(lambda kv: (kv[0].clazz.decode('utf-8', 'replace') \
                                    + "." + \
                                    kv[0].method.decode('utf-8', 'replace'),
                                   (kv[1].num_calls, kv[1].total_ns)),
                   bpf["times"].items()))
    else:
        data = list(map(lambda kv: (kv[0].clazz.decode('utf-8', 'replace') \
                                    + "." + \
                                    kv[0].method.decode('utf-8', 'replace'),
                                   (kv[1].value, 0)),
                   bpf["counts"].items()))

    if args.syscalls:
        if args.latency:
            syscalls = map(lambda kv: (syscall_name(kv[0].value),
                                       (kv[1].num_calls, kv[1].total_ns)),
                           bpf["systimes"].items())
            data.extend(syscalls)
        else:
            syscalls = map(lambda kv: (syscall_name(kv[0].value),
                                       (kv[1].value, 0)),
                           bpf["syscounts"].items())
            data.extend(syscalls)

    return sorted(data, key=lambda kv: kv[1][1 if args.latency else 0])

def clear_data():
    if args.latency:
        bpf["times"].clear()
    else:
        bpf["counts"].clear()

    if args.syscalls:
        if args.latency:
            bpf["systimes"].clear()
        else:
            bpf["syscounts"].clear()

exit_signaled = False
print("Tracing calls in process %d (language: %s)... Ctrl-C to quit." %
      (args.pid, language or "none"))
if extra_message:
    print(extra_message)
while True:
    try:
        sleep(args.interval or 99999999)
    except KeyboardInterrupt:
        exit_signaled = True
    print()
    data = get_data()   # [(function, (num calls, latency in ns))]
    if args.latency:
        time_col = "TIME (ms)" if args.milliseconds else "TIME (us)"
        print("%-50s %8s %8s" % ("METHOD", "# CALLS", time_col))
    else:
        print("%-50s %8s" % ("METHOD", "# CALLS"))
    if args.top:
        data = data[-args.top:]
    for key, value in data:
        if args.latency:
            time = value[1] / 1000000.0 if args.milliseconds else \
                   value[1] / 1000.0
            print("%-50s %8d %6.2f" % (key, value[0], time))
        else:
            print("%-50s %8d" % (key, value[0]))
    if args.interval and not exit_signaled:
        clear_data()
    else:
        if args.syscalls:
            print("Detaching kernel probes, please wait...")
        exit()
