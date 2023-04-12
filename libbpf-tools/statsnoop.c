// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2021 Hengqi Chen
//
// Based on statsnoop(8) from BCC by Brendan Gregg.
// 09-May-2021   Hengqi Chen   Created this.
#include <argp.h>
#include <errno.h>
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
static bool verbose = false;

const char *argp_program_version = "statsnoop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace stat syscalls.\n"
"\n"
"USAGE: statsnoop [-h] [-t] [-x] [-p PID]\n"
"\n"
"EXAMPLES:\n"
"    statsnoop             # trace all stat syscalls\n"
"    statsnoop -t          # include timestamps\n"
"    statsnoop -x          # only show failed stats\n"
"    statsnoop -p 1216     # only trace PID 1216\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "failed", 'x', NULL, 0, "Only show failed stats" },
	{ "timestamp", 't', NULL, 0, "Include timestamp on output" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
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

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	static __u64 start_timestamp = 0;
	const struct event *e = data;
	int fd, err;
	double ts = 0.0;

	if (e->ret >= 0) {
		fd = e->ret;
		err = 0;
	} else {
		fd = -1;
		err = -e->ret;
	}
	if (!start_timestamp)
		start_timestamp = e->ts_ns;
	if (emit_timestamp) {
		ts = (double)(e->ts_ns - start_timestamp) / 1000000000;
		printf("%-14.9f ", ts);
	}
	printf("%-7d %-20s %-4d %-4d %-s\n", e->pid, e->comm, fd, err, e->pathname);
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
	printf("%-7s %-20s %-4s %-4s %-s\n",
	       "PID", "COMM", "RET", "ERR", "PATH");

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
