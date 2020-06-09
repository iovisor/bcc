// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2019 Facebook
// Copyright (c) 2020 Netflix
//
// Based on opensnoop(8) from BCC by Brendan Gregg and others.
// 14-Feb-2020   Brendan Gregg   Created this.
#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "opensnoop.h"
#include "opensnoop.skel.h"
#include "trace_helpers.h"

/* Tune the buffer size and wakeup rate. These settings cope with roughly
 * 50k opens/sec.
 */
#define PERF_BUFFER_PAGES	64
#define PERF_BUFFER_TIME_MS	10

/* Set the poll timeout when no events occur. This can affect -d accuracy. */
#define PERF_POLL_TIMEOUT_MS	100

#define NSEC_PER_SEC		1000000000ULL

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
} env = {
	.uid = INVALID_UID
};

const char *argp_program_version = "opensnoop 0.1";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
"Trace open family syscalls\n"
"\n"
"USAGE: opensnoop [-h] [-T] [-U] [-x] [-p PID] [-t TID] [-u UID] [-d DURATION]\n"
"                 [-n NAME] [-e]\n"
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
"    ./opensnoop -e        # show extended fields\n";

static const struct argp_option opts[] = {
	{ "duration", 'd', "DURATION", 0, "Duration to trace"},
	{ "extended-fields", 'e', NULL, 0, "Print extended fields"},
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
	{ "name", 'n', "NAME", 0, "Trace process names containing this"},
	{ "pid", 'p', "PID", 0, "Process ID to trace"},
	{ "tid", 't', "TID", 0, "Thread ID to trace"},
	{ "timestamp", 'T', NULL, 0, "Print timestamp"},
	{ "uid", 'u', "UID", 0, "User ID to trace"},
	{ "print-uid", 'U', NULL, 0, "Print UID"},
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "failed", 'x', NULL, 0, "Failed opens only"},
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

int libbpf_print_fn(enum libbpf_print_level level,
		    const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;
	int fd, err;

	/* name filtering is currently done in user space */
	if (env.name && strstr(e->comm, env.name) == NULL)
		return;

	/* prepare fields */
	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	if (e->ret >= 0) {
		fd = e->ret;
		err = 0;
	} else {
		fd = -1;
		err = - e->ret;
	}

	/* print output */
	if (env.timestamp)
		printf("%-8s ", ts);
	if (env.print_uid)
		printf("%-6d ", e->uid);
	printf("%-6d %-16s %3d %3d ", e->pid, e->comm, fd, err);
	if (env.extended)
		printf("%08o ", e->flags);
	printf("%s\n", e->fname);
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
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
	struct opensnoop_bpf *obj;
	__u64 time_end = 0;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	err = bump_memlock_rlimit();
	if (err) {
		fprintf(stderr, "failed to increase rlimit: %d\n", err);
		return 1;
	}

	obj = opensnoop_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	obj->rodata->targ_tgid = env.pid;
	obj->rodata->targ_pid = env.tid;
	obj->rodata->targ_uid = env.uid;
	obj->rodata->targ_failed = env.failed;

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

	/* print headers */
	if (env.timestamp)
		printf("%-8s ", "TIME");
	if (env.print_uid)
		printf("%-6s ", "UID");
	printf("%-6s %-16s %3s %3s ", "PID", "COMM", "FD", "ERR");
	if (env.extended)
		printf("%-8s ", "FLAGS");
	printf("%s\n", "PATH");

	/* setup event callbacks */
	pb_opts.sample_cb = handle_event;
	pb_opts.lost_cb = handle_lost_events;
	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      &pb_opts);
	err = libbpf_get_error(pb);
	if (err) {
		pb = NULL;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	/* setup duration */
	if (env.duration)
		time_end = get_ktime_ns() + env.duration * NSEC_PER_SEC;

	/* main: poll */
	while (1) {
		usleep(PERF_BUFFER_TIME_MS * 1000);
		if ((err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS)) < 0)
			break;
		if (env.duration && get_ktime_ns() > time_end)
			goto cleanup;
	}
	printf("Error polling perf buffer: %d\n", err);

cleanup:
	perf_buffer__free(pb);
	opensnoop_bpf__destroy(obj);

	return err != 0;
}
