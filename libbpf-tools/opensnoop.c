// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2019 Facebook
// Copyright (c) 2020 Netflix
//
// Based on opensnoop(8) from BCC by Brendan Gregg and others.
// 14-Feb-2020   Brendan Gregg   Created this.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <argp.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "compat.h"
#include "opensnoop.h"
#include "opensnoop.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#ifdef USE_BLAZESYM
#include "blazesym.h"
#endif

#define NSEC_PER_SEC		1000000000ULL

static volatile sig_atomic_t exiting = 0;

#ifdef USE_BLAZESYM
static blazesym *symbolizer;
#endif

static struct env {
	pid_t pid;
	pid_t tid;
	uid_t uid;
	int duration;
	bool verbose;
	bool timestamp;
	bool print_uid;
	bool extended;
	bool failed;
	char *name;
#ifdef USE_BLAZESYM
	bool callers;
#endif
	bool full_path;
} env = {
	.uid = INVALID_UID
};

const char *argp_program_version = "opensnoop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace open family syscalls\n"
"\n"
"USAGE: opensnoop [-h] [-T] [-U] [-x] [-p PID] [-t TID] [-u UID] [-d DURATION]\n"
#ifdef USE_BLAZESYM
"                 [-n NAME] [-e] [-c]\n"
#else
"                 [-n NAME] [-e]\n"
#endif
"\n"
"EXAMPLES:\n"
"    ./opensnoop           # trace all open() syscalls\n"
"    ./opensnoop -T        # include timestamps\n"
"    ./opensnoop -U        # include UID\n"
"    ./opensnoop -x        # only show failed opens\n"
"    ./opensnoop -p 181    # only trace PID 181\n"
"    ./opensnoop -t 123    # only trace TID 123\n"
"    ./opensnoop -u 1000   # only trace UID 1000\n"
"    ./opensnoop -d 10     # trace for 10 seconds only\n"
"    ./opensnoop -n main   # only print process names containing \"main\"\n"
"    ./opensnoop -e        # show extended fields\n"
#ifdef USE_BLAZESYM
"    ./opensnoop -c        # show calling functions\n"
#endif
"    ./opensnoop -F        # show full path for an open file\n"
"";

static const struct argp_option opts[] = {
	{ "duration", 'd', "DURATION", 0, "Duration to trace", 0 },
	{ "extended-fields", 'e', NULL, 0, "Print extended fields", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{ "name", 'n', "NAME", 0, "Trace process names containing this", 0 },
	{ "pid", 'p', "PID", 0, "Process ID to trace", 0 },
	{ "tid", 't', "TID", 0, "Thread ID to trace", 0 },
	{ "timestamp", 'T', NULL, 0, "Print timestamp", 0 },
	{ "uid", 'u', "UID", 0, "User ID to trace", 0 },
	{ "print-uid", 'U', NULL, 0, "Print UID", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "failed", 'x', NULL, 0, "Failed opens only", 0 },
#ifdef USE_BLAZESYM
	{ "callers", 'c', NULL, 0, "Show calling functions", 0 },
#endif
	{ "full-path", 'F', NULL, 0, "Show full path", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;
	long int pid, uid, duration;

	switch (key) {
	case 'e':
		env.extended = true;
		break;
	case 'h':
		argp_usage(state);
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'U':
		env.print_uid = true;
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'x':
		env.failed = true;
		break;
	case 'd':
		errno = 0;
		duration = strtol(arg, NULL, 10);
		if (errno || duration <= 0) {
			fprintf(stderr, "Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		env.duration = duration;
		break;
	case 'n':
		errno = 0;
		env.name = arg;
		break;
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			fprintf(stderr, "Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		env.pid = pid;
		break;
	case 't':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			fprintf(stderr, "Invalid TID: %s\n", arg);
			argp_usage(state);
		}
		env.tid = pid;
		break;
	case 'u':
		errno = 0;
		uid = strtol(arg, NULL, 10);
		if (errno || uid < 0 || uid >= INVALID_UID) {
			fprintf(stderr, "Invalid UID %s\n", arg);
			argp_usage(state);
		}
		env.uid = uid;
		break;
#ifdef USE_BLAZESYM
	case 'c':
		env.callers = true;
		break;
#endif
	case 'F':
		env.full_path = true;
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			fprintf(stderr,
				"Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct event e;
	struct tm *tm;
#ifdef USE_BLAZESYM
	const blazesym_result *result = NULL;
	const blazesym_csym *sym;
	int i, j;
#endif
	int sps_cnt;
	char ts[32];
	time_t t;
	int fd, err;

	if (data_sz < sizeof(struct event)) {
		printf("Error: packet too small\n");
		return -1;
	}

	/* Copy data as alignment in the perf buffer isn't guaranteed. */
	memcpy(&e, data, sizeof(e));

	/* name filtering is currently done in user space */
	if (env.name && strstr(e.comm, env.name) == NULL)
		return -1;

	/* prepare fields */
	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	if (e.ret >= 0) {
		fd = e.ret;
		err = 0;
	} else {
		fd = -1;
		err = - e.ret;
	}

#ifdef USE_BLAZESYM
	sym_src_cfg cfgs[] = {
		{ .src_type = SRC_T_PROCESS, .params = { .process = { .pid = e.pid }}},
	};
	if (env.callers)
		result = blazesym_symbolize(symbolizer, cfgs, 1, (const uint64_t *)&e.callers, 2);
#endif

	/* print output */
	sps_cnt = 0;
	if (env.timestamp) {
		printf("%-8s ", ts);
		sps_cnt += 9;
	}
	if (env.print_uid) {
		printf("%-7d ", e.uid);
		sps_cnt += 8;
	}
	printf("%-6d %-16s %3d %3d ", e.pid, e.comm, fd, err);
	sps_cnt += 7 + 17 + 4 + 4;
	if (env.extended) {
		if (e.mode == 0 && (e.flags & O_CREAT) == 0 &&
		    (e.flags & O_TMPFILE) != O_TMPFILE)
			printf("%08o n/a  ", e.flags);
		else
			printf("%08o %04o ", e.flags, e.mode);
		sps_cnt += 9;
	}
	if (env.full_path) {
		for (int depth = e.path_depth; depth >= 0; depth--) {
			char *fname = (char *)&e.fname[NAME_MAX * depth];

			/**
			 * If it is a mount point, there will be a '/', because
			 * the '/' will be added below, so just skip this '/'.
			 */
			if (fname[0] == '/' && fname[1] == '\0')
				continue;

			/**
			 * 1. If the file/path name starts with '/', do not
			 *    print the '/' prefix.
			 * 2. If bpf_probe_read_kernel_str() fails, or the
			 *    directory depth reaches the upper limit
			 *    MAX_PATH_DEPTH, the top-level directory
			 *    is printed without the prefix '/'.
			 */
			printf("%s%s",
				"/\0" + (e.fname[NAME_MAX * depth] == '/' ||
					 ((e.get_path_failed || e.path_depth == MAX_PATH_DEPTH - 1) &&
					  depth == e.path_depth)),
				fname);
		}
		printf("\n");
	} else
		printf("%s\n", e.fname);

#ifdef USE_BLAZESYM
	for (i = 0; result && i < result->size; i++) {
		if (result->entries[i].size == 0)
			continue;
		sym = &result->entries[i].syms[0];

		for (j = 0; j < sps_cnt; j++)
			printf(" ");
		if (sym->line_no)
			printf("%s:%ld\n", sym->symbol, sym->line_no);
		else
			printf("%s\n", sym->symbol);
	}

	blazesym_result_free(result);
#endif
	return 0;
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct bpf_buffer *buf = NULL;
	struct opensnoop_bpf *obj;
	__u64 time_end = 0;
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

	obj = opensnoop_bpf__open_opts(&open_opts);
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		err = -errno;
		fprintf(stderr, "failed to create ring/perf buffer: %d", err);
		goto cleanup;
	}

	/* initialize global data (filtering options) */
	obj->rodata->targ_tgid = env.pid;
	obj->rodata->targ_pid = env.tid;
	obj->rodata->targ_uid = env.uid;
	obj->rodata->targ_failed = env.failed;
	obj->rodata->full_path = env.full_path;

	/* aarch64 and riscv64 don't have open syscall */
	if (!tracepoint_exists("syscalls", "sys_enter_open")) {
		bpf_program__set_autoload(obj->progs.tracepoint__syscalls__sys_enter_open, false);
		bpf_program__set_autoload(obj->progs.tracepoint__syscalls__sys_exit_open, false);
	}

	/**
	 * linux since v5.5 support openat2(2), commit fddb5d430ad9 ("open:
	 * introduce openat2(2) syscall").
	 */
	if (!tracepoint_exists("syscalls", "sys_enter_openat2")) {
		bpf_program__set_autoload(obj->progs.tracepoint__syscalls__sys_enter_openat2, false);
		bpf_program__set_autoload(obj->progs.tracepoint__syscalls__sys_exit_openat2, false);
	}

	err = opensnoop_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = opensnoop_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

#ifdef USE_BLAZESYM
	if (env.callers)
		symbolizer = blazesym_new();
#endif

	/* print headers */
	if (env.timestamp)
		printf("%-8s ", "TIME");
	if (env.print_uid)
		printf("%-7s ", "UID");
	printf("%-6s %-16s %3s %3s ", "PID", "COMM", "FD", "ERR");
	if (env.extended)
		printf("%-8s %-5s ", "FLAGS", "MODE");
	printf("%s", "PATH");
#ifdef USE_BLAZESYM
	if (env.callers)
		printf("/CALLER");
#endif
	printf("\n");

	/* setup event callbacks */
	err = bpf_buffer__open(buf, handle_event, handle_lost_events, NULL);
	if (err) {
		err = -errno;
		fprintf(stderr, "failed to open ring/perf buffer: %d\n", err);
		goto cleanup;
	}

	/* setup duration */
	if (env.duration)
		time_end = get_ktime_ns() + env.duration * NSEC_PER_SEC;

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* main: poll */
	while (!exiting) {
		err = bpf_buffer__poll(buf, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling ring/perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		if (env.duration && get_ktime_ns() > time_end)
			goto cleanup;
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	bpf_buffer__free(buf);
	opensnoop_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);
#ifdef USE_BLAZESYM
	blazesym_free(symbolizer);
#endif

	return err != 0;
}
