// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// Based on runqlat(8) from BCC by Bredan Gregg.
// 10-Aug-2020   Wenbo Zhang   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "runqlat.h"
#include "runqlat.skel.h"
#include "trace_helpers.h"

struct env {
	time_t interval;
	pid_t pid;
	int times;
	bool milliseconds;
	bool per_process;
	bool per_thread;
	bool per_pidns;
	bool timestamp;
	bool verbose;
} env = {
	.interval = 99999999,
	.times = 99999999,
};

static volatile bool exiting;

const char *argp_program_version = "runqlat 0.1";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
"Summarize run queue (scheduler) latency as a histogram.\n"
"\n"
"USAGE: runqlat [--help] [-T] [-m] [--pidnss] [-L] [-P] [-p PID] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    runqlat         # summarize run queue latency as a histogram\n"
"    runqlat 1 10    # print 1 second summaries, 10 times\n"
"    runqlat -mT 1   # 1s summaries, milliseconds, and timestamps\n"
"    runqlat -P      # show each PID separately\n"
"    runqlat -p 185  # trace PID 185 only\n";

#define OPT_PIDNSS	1	/* --pidnss */

static const struct argp_option opts[] = {
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output" },
	{ "milliseconds", 'm', NULL, 0, "Millisecond histogram" },
	{ "pidnss", OPT_PIDNSS, NULL, 0, "Print a histogram per PID namespace" },
	{ "pids", 'P', NULL, 0, "Print a histogram per process ID" },
	{ "tids", 'L', NULL, 0, "Print a histogram per thread ID" },
	{ "pid", 'p', "PID", 0, "Trace this PID only" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'm':
		env.milliseconds = true;
		break;
	case 'p':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'L':
		env.per_thread = true;
		break;
	case 'P':
		env.per_process = true;
		break;
	case OPT_PIDNSS:
		env.per_pidns = true;
		break;
	case 'T':
		env.timestamp = true;
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0) {
			env.interval = strtol(arg, NULL, 10);
			if (errno) {
				fprintf(stderr, "invalid internal\n");
				argp_usage(state);
			}
		} else if (pos_args == 1) {
			env.times = strtol(arg, NULL, 10);
			if (errno) {
				fprintf(stderr, "invalid times\n");
				argp_usage(state);
			}
		} else {
			fprintf(stderr,
				"unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		pos_args++;
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

static void sig_handler(int sig)
{
	exiting = true;
}

static int print_log2_hists(struct bpf_map *hists)
{
	const char *units = env.milliseconds ? "msecs" : "usecs";
	int err, fd = bpf_map__fd(hists);
	__u32 lookup_key = -2, next_key;
	struct hist hist;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &hist);
		if (err < 0) {
			fprintf(stderr, "failed to lookup hist: %d\n", err);
			return -1;
		}
		if (env.per_process)
			printf("\npid = %d %s\n", next_key, hist.comm);
		else if (env.per_thread)
			printf("\ntid = %d %s\n", next_key, hist.comm);
		else if (env.per_pidns)
			printf("\npidns = %u %s\n", next_key, hist.comm);
		print_log2_hist(hist.slots, MAX_SLOTS, units);
		lookup_key = next_key;
	}

	lookup_key = -2;
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0) {
			fprintf(stderr, "failed to cleanup hist : %d\n", err);
			return -1;
		}
		lookup_key = next_key;
	}
	return 0;
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct runqlat_bpf *obj;
	struct tm *tm;
	char ts[32];
	time_t t;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if ((env.per_thread && (env.per_process || env.per_pidns)) ||
		(env.per_process && env.per_pidns)) {
		fprintf(stderr, "pidnss, pids, tids cann't be used together.\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	err = bump_memlock_rlimit();
	if (err) {
		fprintf(stderr, "failed to increase rlimit: %d\n", err);
		return 1;
	}

	obj = runqlat_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	obj->rodata->targ_per_process = env.per_process;
	obj->rodata->targ_per_thread = env.per_thread;
	obj->rodata->targ_per_pidns = env.per_pidns;
	obj->rodata->targ_ms = env.milliseconds;
	obj->rodata->targ_tgid = env.pid;

	err = runqlat_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = runqlat_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	printf("Tracing run queue latency... Hit Ctrl-C to end.\n");

	signal(SIGINT, sig_handler);

	/* main: poll */
	while (1) {
		sleep(env.interval);
		printf("\n");

		if (env.timestamp) {
			time(&t);
			tm = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);
			printf("%-8s\n", ts);
		}

		err = print_log2_hists(obj->maps.hists);
		if (err)
			break;

		if (exiting || --env.times == 0)
			break;
	}

cleanup:
	runqlat_bpf__destroy(obj);

	return err != 0;
}
