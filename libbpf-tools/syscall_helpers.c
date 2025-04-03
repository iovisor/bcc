// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Anton Protopopov
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>

static const char **syscall_names;
static size_t syscall_names_size;

#define warn(...) fprintf(stderr, __VA_ARGS__)
#define MAX(x, y) (((x) > (y)) ? (x) : (y))

static const char *parse_syscall(const char *buf, int *number)
{
	char *end;
	long x;

	errno = 0;
	x = strtol(buf, &end, 10);
	if (errno) {
		warn("strtol(%s): %s\n", buf, strerror(errno));
		return NULL;
	} else if (end == buf) {
		warn("strtol(%s): no digits found\n", buf);
		return NULL;
	} else if (x < 0 || x > INT_MAX) {
		warn("strtol(%s): bad syscall number: %ld\n", buf, x);
		return NULL;
	}
	if (*end != '\t') {
		warn("bad input: %s (expected <num>\t<name>)\n", buf);
		return NULL;
	}

	*number = x;
	return ++end;
}

void init_syscall_names(void)
{
	size_t old_size, size = 1024;
	const char *name;
	char buf[64];
	int number;
	int err;
	FILE *f;

	f = popen("ausyscall --dump 2>/dev/null", "r");
	if (!f) {
		warn("popen: ausyscall --dump: %s\n", strerror(errno));
		return;
	}

	syscall_names = calloc(size, sizeof(char *));
	if (!syscall_names) {
		warn("calloc: %s\n", strerror(errno));
		goto close;
	}

	/* skip the header, ignore the result of fgets, outwit the comiler */
	(void) !!fgets(buf, sizeof(buf), f);

	while (fgets(buf, sizeof(buf), f)) {
		if (buf[strlen(buf) - 1] == '\n')
			buf[strlen(buf) - 1] = '\0';

		name = parse_syscall(buf, &number);
		if (!name || !name[0])
			goto close;

		/* In a rare case when syscall number is > than initial 1024 */
		if (number >= size) {
			old_size = size;
			size = 1024 * (1 + number / 1024);
			syscall_names = realloc(syscall_names,
						size * sizeof(char *));
			if (!syscall_names) {
				warn("realloc: %s\n", strerror(errno));
				goto close;
			}
			memset(syscall_names+old_size, 0,
			       (size - old_size) * sizeof(char *));
		}

		if (syscall_names[number]) {
			warn("duplicate number: %d (stored: %s)",
				number, syscall_names[number]);
			goto close;
		}

		syscall_names[number] = strdup(name);
		if (!syscall_names[number]) {
			warn("strdup: %s\n", strerror(errno));
			goto close;
		}
		syscall_names_size = MAX(number+1, syscall_names_size);
	}

	if (ferror(f))
		warn("fgets: %s\n", strerror(errno));
close:
	err = pclose(f);
	if (err < 0)
		warn("pclose: %s\n", strerror(errno));
#if !defined(__x86_64__) && !defined(__aarch64__) && !defined(__riscv) && !defined(__loongarch64)
	/* Ignore the error for x86_64/arm64/riscv/loongarch64 where we have a table compiled in */
	else if (err && WEXITSTATUS(err) == 127) {
		warn("ausyscall required for syscalls number/name mapping\n");
	} else if (err) {
		warn("ausyscall exit status (see wait(2)): 0x%x\n", err);
	}
#endif
}

void free_syscall_names(void)
{
	size_t i;

	for (i = 0; i < syscall_names_size; i++)
		free((void *) syscall_names[i]);
	free(syscall_names);
}

/*
 * Syscall table for Linux x86_64.
 *
 * Semi-automatically generated from strace/linux/x86_64/syscallent.h and
 * linux/syscallent-common.h using the following commands:
 *
 *  awk -F\" '/SEN/{printf("%d %s\n", substr($0,2,3), $(NF-1));}' syscallent.h
 *  awk '/SEN/ { printf("%d %s\n", $3, $9); }' syscallent-common.h
 *
 * (The idea is taken from src/python/bcc/syscall.py.)
 */
#ifdef __x86_64__
static const char *syscall_names_x86_64[] = {
	[0] = "read",
	[1] = "write",
	[2] = "open",
	[3] = "close",
	[4] = "stat",
	[5] = "fstat",
	[6] = "lstat",
	[7] = "poll",
	[8] = "lseek",
	[9] = "mmap",
	[10] = "mprotect",
	[11] = "munmap",
	[12] = "brk",
	[13] = "rt_sigaction",
	[14] = "rt_sigprocmask",
	[15] = "rt_sigreturn",
	[16] = "ioctl",
	[17] = "pread64",
	[18] = "pwrite64",
	[19] = "readv",
	[20] = "writev",
	[21] = "access",
	[22] = "pipe",
	[23] = "select",
	[24] = "sched_yield",
	[25] = "mremap",
	[26] = "msync",
	[27] = "mincore",
	[28] = "madvise",
	[29] = "shmget",
	[30] = "shmat",
	[31] = "shmctl",
	[32] = "dup",
	[33] = "dup2",
	[34] = "pause",
	[35] = "nanosleep",
	[36] = "getitimer",
	[37] = "alarm",
	[38] = "setitimer",
	[39] = "getpid",
	[40] = "sendfile",
	[41] = "socket",
	[42] = "connect",
	[43] = "accept",
	[44] = "sendto",
	[45] = "recvfrom",
	[46] = "sendmsg",
	[47] = "recvmsg",
	[48] = "shutdown",
	[49] = "bind",
	[50] = "listen",
	[51] = "getsockname",
	[52] = "getpeername",
	[53] = "socketpair",
	[54] = "setsockopt",
	[55] = "getsockopt",
	[56] = "clone",
	[57] = "fork",
	[58] = "vfork",
	[59] = "execve",
	[60] = "exit",
	[61] = "wait4",
	[62] = "kill",
	[63] = "uname",
	[64] = "semget",
	[65] = "semop",
	[66] = "semctl",
	[67] = "shmdt",
	[68] = "msgget",
	[69] = "msgsnd",
	[70] = "msgrcv",
	[71] = "msgctl",
	[72] = "fcntl",
	[73] = "flock",
	[74] = "fsync",
	[75] = "fdatasync",
	[76] = "truncate",
	[77] = "ftruncate",
	[78] = "getdents",
	[79] = "getcwd",
	[80] = "chdir",
	[81] = "fchdir",
	[82] = "rename",
	[83] = "mkdir",
	[84] = "rmdir",
	[85] = "creat",
	[86] = "link",
	[87] = "unlink",
	[88] = "symlink",
	[89] = "readlink",
	[90] = "chmod",
	[91] = "fchmod",
	[92] = "chown",
	[93] = "fchown",
	[94] = "lchown",
	[95] = "umask",
	[96] = "gettimeofday",
	[97] = "getrlimit",
	[98] = "getrusage",
	[99] = "sysinfo",
	[100] = "times",
	[101] = "ptrace",
	[102] = "getuid",
	[103] = "syslog",
	[104] = "getgid",
	[105] = "setuid",
	[106] = "setgid",
	[107] = "geteuid",
	[108] = "getegid",
	[109] = "setpgid",
	[110] = "getppid",
	[111] = "getpgrp",
	[112] = "setsid",
	[113] = "setreuid",
	[114] = "setregid",
	[115] = "getgroups",
	[116] = "setgroups",
	[117] = "setresuid",
	[118] = "getresuid",
	[119] = "setresgid",
	[120] = "getresgid",
	[121] = "getpgid",
	[122] = "setfsuid",
	[123] = "setfsgid",
	[124] = "getsid",
	[125] = "capget",
	[126] = "capset",
	[127] = "rt_sigpending",
	[128] = "rt_sigtimedwait",
	[129] = "rt_sigqueueinfo",
	[130] = "rt_sigsuspend",
	[131] = "sigaltstack",
	[132] = "utime",
	[133] = "mknod",
	[134] = "uselib",
	[135] = "personality",
	[136] = "ustat",
	[137] = "statfs",
	[138] = "fstatfs",
	[139] = "sysfs",
	[140] = "getpriority",
	[141] = "setpriority",
	[142] = "sched_setparam",
	[143] = "sched_getparam",
	[144] = "sched_setscheduler",
	[145] = "sched_getscheduler",
	[146] = "sched_get_priority_max",
	[147] = "sched_get_priority_min",
	[148] = "sched_rr_get_interval",
	[149] = "mlock",
	[150] = "munlock",
	[151] = "mlockall",
	[152] = "munlockall",
	[153] = "vhangup",
	[154] = "modify_ldt",
	[155] = "pivot_root",
	[156] = "_sysctl",
	[157] = "prctl",
	[158] = "arch_prctl",
	[159] = "adjtimex",
	[160] = "setrlimit",
	[161] = "chroot",
	[162] = "sync",
	[163] = "acct",
	[164] = "settimeofday",
	[165] = "mount",
	[166] = "umount2",
	[167] = "swapon",
	[168] = "swapoff",
	[169] = "reboot",
	[170] = "sethostname",
	[171] = "setdomainname",
	[172] = "iopl",
	[173] = "ioperm",
	[174] = "create_module",
	[175] = "init_module",
	[176] = "delete_module",
	[177] = "get_kernel_syms",
	[178] = "query_module",
	[179] = "quotactl",
	[180] = "nfsservctl",
	[181] = "getpmsg",
	[182] = "putpmsg",
	[183] = "afs_syscall",
	[184] = "tuxcall",
	[185] = "security",
	[186] = "gettid",
	[187] = "readahead",
	[188] = "setxattr",
	[189] = "lsetxattr",
	[190] = "fsetxattr",
	[191] = "getxattr",
	[192] = "lgetxattr",
	[193] = "fgetxattr",
	[194] = "listxattr",
	[195] = "llistxattr",
	[196] = "flistxattr",
	[197] = "removexattr",
	[198] = "lremovexattr",
	[199] = "fremovexattr",
	[200] = "tkill",
	[201] = "time",
	[202] = "futex",
	[203] = "sched_setaffinity",
	[204] = "sched_getaffinity",
	[205] = "set_thread_area",
	[206] = "io_setup",
	[207] = "io_destroy",
	[208] = "io_getevents",
	[209] = "io_submit",
	[210] = "io_cancel",
	[211] = "get_thread_area",
	[212] = "lookup_dcookie",
	[213] = "epoll_create",
	[214] = "epoll_ctl_old",
	[215] = "epoll_wait_old",
	[216] = "remap_file_pages",
	[217] = "getdents64",
	[218] = "set_tid_address",
	[219] = "restart_syscall",
	[220] = "semtimedop",
	[221] = "fadvise64",
	[222] = "timer_create",
	[223] = "timer_settime",
	[224] = "timer_gettime",
	[225] = "timer_getoverrun",
	[226] = "timer_delete",
	[227] = "clock_settime",
	[228] = "clock_gettime",
	[229] = "clock_getres",
	[230] = "clock_nanosleep",
	[231] = "exit_group",
	[232] = "epoll_wait",
	[233] = "epoll_ctl",
	[234] = "tgkill",
	[235] = "utimes",
	[236] = "vserver",
	[237] = "mbind",
	[238] = "set_mempolicy",
	[239] = "get_mempolicy",
	[240] = "mq_open",
	[241] = "mq_unlink",
	[242] = "mq_timedsend",
	[243] = "mq_timedreceive",
	[244] = "mq_notify",
	[245] = "mq_getsetattr",
	[246] = "kexec_load",
	[247] = "waitid",
	[248] = "add_key",
	[249] = "request_key",
	[250] = "keyctl",
	[251] = "ioprio_set",
	[252] = "ioprio_get",
	[253] = "inotify_init",
	[254] = "inotify_add_watch",
	[255] = "inotify_rm_watch",
	[256] = "migrate_pages",
	[257] = "openat",
	[258] = "mkdirat",
	[259] = "mknodat",
	[260] = "fchownat",
	[261] = "futimesat",
	[262] = "newfstatat",
	[263] = "unlinkat",
	[264] = "renameat",
	[265] = "linkat",
	[266] = "symlinkat",
	[267] = "readlinkat",
	[268] = "fchmodat",
	[269] = "faccessat",
	[270] = "pselect6",
	[271] = "ppoll",
	[272] = "unshare",
	[273] = "set_robust_list",
	[274] = "get_robust_list",
	[275] = "splice",
	[276] = "tee",
	[277] = "sync_file_range",
	[278] = "vmsplice",
	[279] = "move_pages",
	[280] = "utimensat",
	[281] = "epoll_pwait",
	[282] = "signalfd",
	[283] = "timerfd_create",
	[284] = "eventfd",
	[285] = "fallocate",
	[286] = "timerfd_settime",
	[287] = "timerfd_gettime",
	[288] = "accept4",
	[289] = "signalfd4",
	[290] = "eventfd2",
	[291] = "epoll_create1",
	[292] = "dup3",
	[293] = "pipe2",
	[294] = "inotify_init1",
	[295] = "preadv",
	[296] = "pwritev",
	[297] = "rt_tgsigqueueinfo",
	[298] = "perf_event_open",
	[299] = "recvmmsg",
	[300] = "fanotify_init",
	[301] = "fanotify_mark",
	[302] = "prlimit64",
	[303] = "name_to_handle_at",
	[304] = "open_by_handle_at",
	[305] = "clock_adjtime",
	[306] = "syncfs",
	[307] = "sendmmsg",
	[308] = "setns",
	[309] = "getcpu",
	[310] = "process_vm_readv",
	[311] = "process_vm_writev",
	[312] = "kcmp",
	[313] = "finit_module",
	[314] = "sched_setattr",
	[315] = "sched_getattr",
	[316] = "renameat2",
	[317] = "seccomp",
	[318] = "getrandom",
	[319] = "memfd_create",
	[320] = "kexec_file_load",
	[321] = "bpf",
	[322] = "execveat",
	[323] = "userfaultfd",
	[324] = "membarrier",
	[325] = "mlock2",
	[326] = "copy_file_range",
	[327] = "preadv2",
	[328] = "pwritev2",
	[329] = "pkey_mprotect",
	[330] = "pkey_alloc",
	[331] = "pkey_free",
	[332] = "statx",
	[333] = "io_pgetevents",
	[334] = "rseq",
	[424] = "pidfd_send_signal",
	[425] = "io_uring_setup",
	[426] = "io_uring_enter",
	[427] = "io_uring_register",
	[428] = "open_tree",
	[429] = "move_mount",
	[430] = "fsopen",
	[431] = "fsconfig",
	[432] = "fsmount",
	[433] = "fspick",
	[434] = "pidfd_open",
	[435] = "clone3",
	[437] = "openat2",
	[438] = "pidfd_getfd",
};
size_t syscall_names_x86_64_size = sizeof(syscall_names_x86_64)/sizeof(char*);
#elif defined(__aarch64__) || defined(__riscv) || defined(__loongarch64)
static const char *syscall_names_generic[] = {
	[0] = "io_setup",
	[1] = "io_destroy",
	[2] = "io_submit",
	[3] = "io_cancel",
	[4] = "io_getevents",
	[5] = "setxattr",
	[6] = "lsetxattr",
	[7] = "fsetxattr",
	[8] = "getxattr",
	[9] = "lgetxattr",
	[10] = "fgetxattr",
	[11] = "listxattr",
	[12] = "llistxattr",
	[13] = "flistxattr",
	[14] = "removexattr",
	[15] = "lremovexattr",
	[16] = "fremovexattr",
	[17] = "getcwd",
	[18] = "lookup_dcookie",
	[19] = "eventfd2",
	[20] = "epoll_create1",
	[21] = "epoll_ctl",
	[22] = "epoll_pwait",
	[23] = "dup",
	[24] = "dup3",
	[25] = "fcntl",
	[26] = "inotify_init1",
	[27] = "inotify_add_watch",
	[28] = "inotify_rm_watch",
	[29] = "ioctl",
	[30] = "ioprio_set",
	[31] = "ioprio_get",
	[32] = "flock",
	[33] = "mknodat",
	[34] = "mkdirat",
	[35] = "unlinkat",
	[36] = "symlinkat",
	[37] = "linkat",
	[38] = "renameat",
	[39] = "umount2",
	[40] = "mount",
	[41] = "pivot_root",
	[42] = "nfsservctl",
	[43] = "statfs",
	[44] = "fstatfs",
	[45] = "truncate",
	[46] = "ftruncate",
	[47] = "fallocate",
	[48] = "faccessat",
	[49] = "chdir",
	[50] = "fchdir",
	[51] = "chroot",
	[52] = "fchmod",
	[53] = "fchmodat",
	[54] = "fchownat",
	[55] = "fchown",
	[56] = "openat",
	[57] = "close",
	[58] = "vhangup",
	[59] = "pipe2",
	[60] = "quotactl",
	[61] = "getdents64",
	[62] = "lseek",
	[63] = "read",
	[64] = "write",
	[65] = "readv",
	[66] = "writev",
	[67] = "pread64",
	[68] = "pwrite64",
	[69] = "preadv",
	[70] = "pwritev",
	[71] = "sendfile",
	[72] = "pselect6",
	[73] = "ppoll",
	[74] = "signalfd4",
	[75] = "vmsplice",
	[76] = "splice",
	[77] = "tee",
	[78] = "readlinkat",
	[79] = "newfstatat",
	[80] = "fstat",
	[81] = "sync",
	[82] = "fsync",
	[83] = "fdatasync",
	[84] = "sync_file_range",
	[85] = "timerfd_create",
	[86] = "timerfd_settime",
	[87] = "timerfd_gettime",
	[88] = "utimensat",
	[89] = "acct",
	[90] = "capget",
	[91] = "capset",
	[92] = "personality",
	[93] = "exit",
	[94] = "exit_group",
	[95] = "waitid",
	[96] = "set_tid_address",
	[97] = "unshare",
	[98] = "futex",
	[99] = "set_robust_list",
	[100] = "get_robust_list",
	[101] = "nanosleep",
	[102] = "getitimer",
	[103] = "setitimer",
	[104] = "kexec_load",
	[105] = "init_module",
	[106] = "delete_module",
	[107] = "timer_create",
	[108] = "timer_gettime",
	[109] = "timer_getoverrun",
	[110] = "timer_settime",
	[111] = "timer_delete",
	[112] = "clock_settime",
	[113] = "clock_gettime",
	[114] = "clock_getres",
	[115] = "clock_nanosleep",
	[116] = "syslog",
	[117] = "ptrace",
	[118] = "sched_setparam",
	[119] = "sched_setscheduler",
	[120] = "sched_getscheduler",
	[121] = "sched_getparam",
	[122] = "sched_setaffinity",
	[123] = "sched_getaffinity",
	[124] = "sched_yield",
	[125] = "sched_get_priority_max",
	[126] = "sched_get_priority_min",
	[127] = "sched_rr_get_interval",
	[128] = "restart_syscall",
	[129] = "kill",
	[130] = "tkill",
	[131] = "tgkill",
	[132] = "sigaltstack",
	[133] = "rt_sigsuspend",
	[134] = "rt_sigaction",
	[135] = "rt_sigprocmask",
	[136] = "rt_sigpending",
	[137] = "rt_sigtimedwait",
	[138] = "rt_sigqueueinfo",
	[139] = "rt_sigreturn",
	[140] = "setpriority",
	[141] = "getpriority",
	[142] = "reboot",
	[143] = "setregid",
	[144] = "setgid",
	[145] = "setreuid",
	[146] = "setuid",
	[147] = "setresuid",
	[148] = "getresuid",
	[149] = "setresgid",
	[150] = "getresgid",
	[151] = "setfsuid",
	[152] = "setfsgid",
	[153] = "times",
	[154] = "setpgid",
	[155] = "getpgid",
	[156] = "getsid",
	[157] = "setsid",
	[158] = "getgroups",
	[159] = "setgroups",
	[160] = "uname",
	[161] = "sethostname",
	[162] = "setdomainname",
	[163] = "getrlimit",
	[164] = "setrlimit",
	[165] = "getrusage",
	[166] = "umask",
	[167] = "prctl",
	[168] = "getcpu",
	[169] = "gettimeofday",
	[170] = "settimeofday",
	[171] = "adjtimex",
	[172] = "getpid",
	[173] = "getppid",
	[174] = "getuid",
	[175] = "geteuid",
	[176] = "getgid",
	[177] = "getegid",
	[178] = "gettid",
	[179] = "sysinfo",
	[180] = "mq_open",
	[181] = "mq_unlink",
	[182] = "mq_timedsend",
	[183] = "mq_timedreceive",
	[184] = "mq_notify",
	[185] = "mq_getsetattr",
	[186] = "msgget",
	[187] = "msgctl",
	[188] = "msgrcv",
	[189] = "msgsnd",
	[190] = "semget",
	[191] = "semctl",
	[192] = "semtimedop",
	[193] = "semop",
	[194] = "shmget",
	[195] = "shmctl",
	[196] = "shmat",
	[197] = "shmdt",
	[198] = "socket",
	[199] = "socketpair",
	[200] = "bind",
	[201] = "listen",
	[202] = "accept",
	[203] = "connect",
	[204] = "getsockname",
	[205] = "getpeername",
	[206] = "sendto",
	[207] = "recvfrom",
	[208] = "setsockopt",
	[209] = "getsockopt",
	[210] = "shutdown",
	[211] = "sendmsg",
	[212] = "recvmsg",
	[213] = "readahead",
	[214] = "brk",
	[215] = "munmap",
	[216] = "mremap",
	[217] = "add_key",
	[218] = "request_key",
	[219] = "keyctl",
	[220] = "clone",
	[221] = "execve",
	[222] = "mmap",
	[223] = "fadvise64",
	[224] = "swapon",
	[225] = "swapoff",
	[226] = "mprotect",
	[227] = "msync",
	[228] = "mlock",
	[229] = "munlock",
	[230] = "mlockall",
	[231] = "munlockall",
	[232] = "mincore",
	[233] = "madvise",
	[234] = "remap_file_pages",
	[235] = "mbind",
	[236] = "get_mempolicy",
	[237] = "set_mempolicy",
	[238] = "migrate_pages",
	[239] = "move_pages",
	[240] = "rt_tgsigqueueinfo",
	[241] = "perf_event_open",
	[242] = "accept4",
	[243] = "recvmmsg",
	[244] = "arch_specific_syscall",
#if defined(__riscv)
	[258] = "riscv_hwprobe",
	[259] = "riscv_flush_icache",
#endif
	[260] = "wait4",
	[261] = "prlimit64",
	[262] = "fanotify_init",
	[263] = "fanotify_mark",
	[264] = "name_to_handle_at",
	[265] = "open_by_handle_at",
	[266] = "clock_adjtime",
	[267] = "syncfs",
	[268] = "setns",
	[269] = "sendmmsg",
	[270] = "process_vm_readv",
	[271] = "process_vm_writev",
	[272] = "kcmp",
	[273] = "finit_module",
	[274] = "sched_setattr",
	[275] = "sched_getattr",
	[276] = "renameat2",
	[277] = "seccomp",
	[278] = "getrandom",
	[279] = "memfd_create",
	[280] = "bpf",
	[281] = "execveat",
	[282] = "userfaultfd",
	[283] = "membarrier",
	[284] = "mlock2",
	[285] = "copy_file_range",
	[286] = "preadv2",
	[287] = "pwritev2",
	[288] = "pkey_mprotect",
	[289] = "pkey_alloc",
	[290] = "pkey_free",
	[291] = "statx",
	[292] = "io_pgetevents",
	[293] = "rseq",
	[294] = "kexec_file_load",
	[424] = "pidfd_send_signal",
	[425] = "io_uring_setup",
	[426] = "io_uring_enter",
	[427] = "io_uring_register",
	[428] = "open_tree",
	[429] = "move_mount",
	[430] = "fsopen",
	[431] = "fsconfig",
	[432] = "fsmount",
	[433] = "fspick",
	[434] = "pidfd_open",
	[435] = "clone3",
	[436] = "close_range",
	[437] = "openat2",
	[438] = "pidfd_getfd",
	[439] = "faccessat2",
	[440] = "process_madvise",
	[441] = "epoll_pwait2",
	[442] = "mount_setattr",
	[443] = "quotactl_fd",
	[444] = "landlock_create_ruleset",
	[445] = "landlock_add_rule",
	[446] = "landlock_restrict_self",
	[447] = "memfd_secret",
	[448] = "process_mrelease",
	[449] = "futex_waitv",
	[450] = "set_mempolicy_home_node",
	[451] = "cachestat",
	[452] = "fchmodat2",
	[453] = "map_shadow_stack",
	[454] = "futex_wake",
	[455] = "futex_wait",
	[456] = "futex_requeue",
};
size_t syscall_names_generic_size = sizeof(syscall_names_generic)/sizeof(char*);
#endif

void syscall_name(unsigned n, char *buf, size_t size)
{
	const char *name = NULL;

	if (n < syscall_names_size)
		name = syscall_names[n];
#ifdef __x86_64__
	else if (n < syscall_names_x86_64_size)
		name = syscall_names_x86_64[n];
#elif defined(__aarch64__) || defined(__riscv) || defined(__loongarch64)
	else if (n < syscall_names_generic_size)
		name = syscall_names_generic[n];
#endif

	if (name)
		strncpy(buf, name, size-1);
	else
		snprintf(buf, size, "[unknown: %u]", n);
}

int list_syscalls(void)
{
	const char **list = syscall_names;
	size_t i, size = syscall_names_size;

#ifdef __x86_64__
	if (!size) {
		size = syscall_names_x86_64_size;
		list = syscall_names_x86_64;
	}
#elif defined(__aarch64__) || defined(__riscv) || defined(__loongarch64)
	if (!size) {
		size = syscall_names_generic_size;
		list = syscall_names_generic;
	}
#endif

	for (i = 0; i < size; i++) {
		if (list[i])
			printf("%3zd: %s\n", i, list[i]);
	}

	return (!list || !size);
}

