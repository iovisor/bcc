// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2021 Hengqi Chen
//
// Based on statsnoop(8) from BCC by Brendan Gregg.
// 09-May-2021   Hengqi Chen   Created this.
// 15-Mar-2025   Rong Tao      Support fd and dirfd.
#include <argp.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "statsnoop.h"
#include "statsnoop.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES       16
#define PERF_POLL_TIMEOUT_MS    100
#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;

static pid_t target_pid = 0;
static bool trace_failed_only = false;
static bool emit_timestamp = false;
static bool emit_sysname = false;
static bool verbose = false;

const char *argp_program_version = "statsnoop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace stat syscalls.\n"
"\n"
"USAGE: statsnoop [-h] [-t] [-s] [-x] [-p PID]\n"
"\n"
"EXAMPLES:\n"
"    statsnoop             # trace all stat syscalls\n"
"    statsnoop -t          # include timestamps\n"
"    statsnoop -s          # include syscall name\n"
"    statsnoop -x          # only show failed stats\n"
"    statsnoop -p 1216     # only trace PID 1216\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace", 0 },
	{ "failed", 'x', NULL, 0, "Only show failed stats", 0 },
	{ "timestamp", 't', NULL, 0, "Include timestamp on output", 0 },
	{ "sysname", 's', NULL, 0, "Include syscall name on output", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static char *sys_names[] = {
	[0] = "N/A",
	[SYS_STATFS] = "statfs",
	[SYS_NEWSTAT] = "newstat",
	[SYS_STATX] = "statx",
	[SYS_NEWFSTAT] = "newfstat",
	[SYS_NEWFSTATAT] = "newfstatat",
	[SYS_NEWLSTAT] = "newlstat",
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long pid;

	switch (key) {
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			warn("Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		target_pid = pid;
		break;
	case 'x':
		trace_failed_only = true;
		break;
	case 't':
		emit_timestamp = true;
		break;
	case 's':
		emit_sysname = true;
		break;
	case 'v':
		verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

char *proc_fd_pathname(pid_t pid, int fd, int is_dir, char *buf, size_t buf_len)
{
	int err, n;
	char fdpath[PATH_MAX];

	if (fd == INVALID_FD)
		goto skip;
	else if (fd == AT_FDCWD)
		snprintf(fdpath, PATH_MAX - 1, "/proc/%d/cwd", pid);
	else
		snprintf(fdpath, PATH_MAX - 1, "/proc/%d/fd/%d", pid, fd);

	err = readlink(fdpath, buf, buf_len);
	if (err == -1)
		goto skip;

	if (is_dir) {
		/* Add '/' in the end of string */
		n = strlen(buf);
		buf[n] = '/';
		buf[n + 1] = '\0';
	}

	return buf;

skip:
	/* maybe process already exit or fd already be closed, just ignore cwd
	 * or skip no-exist pathname */
	return "";
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	static __u64 start_timestamp = 0;
	struct event e;
	int fd, err;
	double ts = 0.0;
	char fdpath[PATH_MAX] = {0}, dirfdpath[PATH_MAX] = {0};

	if (data_sz < sizeof(e)) {
		printf("Error: packet too small\n");
		return;
	}
	/* Copy data as alignment in the perf buffer isn't guaranteed. */
	memcpy(&e, data, sizeof(e));

	if (e.ret >= 0) {
		fd = e.ret;
		err = 0;
	} else {
		fd = -1;
		err = -e.ret;
	}
	if (!start_timestamp)
		start_timestamp = e.ts_ns;
	if (emit_timestamp) {
		ts = (double)(e.ts_ns - start_timestamp) / 1000000000;
		printf("%-14.9f ", ts);
	}
	printf("%-7d %-20s %-4d %-4d", e.pid, e.comm, fd, err);
	if (emit_sysname)
		printf(" %-10s", sys_names[e.type]);

	printf(" %s%s%-s\n",
		e.pathname[0] == '/' ? "" : proc_fd_pathname(e.pid, e.fd, 0, fdpath, PATH_MAX),
		e.pathname[0] == '/' ? "" : proc_fd_pathname(e.pid, e.dirfd, 1, dirfdpath, PATH_MAX),
		e.pathname);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct perf_buffer *pb = NULL;
	struct statsnoop_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	obj = statsnoop_bpf__open_opts(&open_opts);
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->target_pid = target_pid;
	obj->rodata->trace_failed_only = trace_failed_only;

	if (!tracepoint_exists("syscalls", "sys_enter_statfs")) {
		bpf_program__set_autoload(obj->progs.handle_statfs_entry, false);
		bpf_program__set_autoload(obj->progs.handle_statfs_return, false);
	}
	if (!tracepoint_exists("syscalls", "sys_enter_statx")) {
		bpf_program__set_autoload(obj->progs.handle_statx_entry, false);
		bpf_program__set_autoload(obj->progs.handle_statx_return, false);
	}
	if (!tracepoint_exists("syscalls", "sys_enter_newstat")) {
		bpf_program__set_autoload(obj->progs.handle_newstat_entry, false);
		bpf_program__set_autoload(obj->progs.handle_newstat_return, false);
	}
	if (!tracepoint_exists("syscalls", "sys_enter_newfstatat")) {
		bpf_program__set_autoload(obj->progs.handle_newfstatat_entry, false);
		bpf_program__set_autoload(obj->progs.handle_newfstatat_return, false);
	}
	if (!tracepoint_exists("syscalls", "sys_enter_newfstat")) {
		bpf_program__set_autoload(obj->progs.handle_newfstat_entry, false);
		bpf_program__set_autoload(obj->progs.handle_newfstat_return, false);
	}
	if (!tracepoint_exists("syscalls", "sys_enter_newlstat")) {
		bpf_program__set_autoload(obj->progs.handle_newlstat_entry, false);
		bpf_program__set_autoload(obj->progs.handle_newlstat_return, false);
	}

	err = statsnoop_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = statsnoop_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		warn("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	if (emit_timestamp)
		printf("%-14s ", "TIME(s)");
	printf("%-7s %-20s %-4s %-4s",
	       "PID", "COMM", "RET", "ERR");
	if (emit_sysname)
		printf(" %-10s", "SYSCALL");
	printf(" %-s\n", "PATH");

	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warn("error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	statsnoop_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
