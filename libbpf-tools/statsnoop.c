// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2021 Hengqi Chen
//
// Based on statsnoop(8) from BCC by Brendan Gregg.
// 09-May-2021   Hengqi Chen   Created this.
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <time.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "statsnoop.h"
#include "statsnoop.skel.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES       16
#define PERF_POLL_TIMEOUT_MS    100
#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;

static pid_t target_pid = 0;
static bool trace_failed_only = false;
static bool emit_timestamp = false;

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
	{"pid", 'p', "PID", 0, "Process ID to trace"},
	{"failed", 'x', NULL, 0, "Only show failed stats"},
	{"timestamp", 't', NULL, 0, "Include timestamp on output"},
	{NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
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
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
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
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct perf_buffer_opts pb_opts;
	struct perf_buffer *pb = NULL;
	struct statsnoop_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	err = bump_memlock_rlimit();
	if (err) {
		warn("failed to increase rlimit: %d\n", err);
		return 1;
	}

	obj = statsnoop_bpf__open();
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->target_pid = target_pid;
	obj->rodata->trace_failed_only = trace_failed_only;

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

	pb_opts.sample_cb = handle_event;
	pb_opts.lost_cb = handle_lost_events;
	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      &pb_opts);
	err = libbpf_get_error(pb);
	if (err) {
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
		if (err < 0 && errno != EINTR) {
			warn("error polling perf buffer: %s\n", strerror(errno));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	statsnoop_bpf__destroy(obj);

	return err != 0;
}
