// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// Based on xfsslower(8) from BCC by Brendan Gregg & Dina Goldshtein.
// 9-Mar-2020   Wenbo Zhang   Created this.
#include <argp.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "xfsslower.h"
#include "xfsslower.skel.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	64
#define PERF_BUFFER_TIME_MS	10
#define PERF_POLL_TIMEOUT_MS	100


static struct env {
	pid_t pid;
	time_t duration;
	__u64 min_lat;
	bool csv;
	bool verbose;
} env = {
	.min_lat = 10000,
};

const char *argp_program_version = "xfsslower 0.1";
const char *argp_program_bug_address = "<ethercflow@gmail.com>";
const char argp_program_doc[] =
"Trace common XFS file operations slower than a threshold.\n"
"\n"
"Usage: xfslower [--help] [-p PID] [-m MIN] [-d DURATION] [-c]\n"
"\n"
"EXAMPLES:\n"
"    xfsslower          # trace operations slower than 10 ms (default)"
"    xfsslower 0        # trace all operations (warning: verbose)\n"
"    xfsslower -p 123   # trace pid 123\n"
"    xfsslower -c -d 1  # ... 1s, parsable output (csv)";

static const struct argp_option opts[] = {
	{ "csv", 'c', NULL, 0, "Output as csv" },
	{ "duration", 'd', "DURATION", 0, "Total duration of trace in seconds" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
	{ "pid", 'p', "PID", 0, "Process PID to trace" },
	{ "min", 'm', "MIN", 0, "Min latency of trace in ms (default 10)" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long long min_lat;
	time_t duration;
	int pid;

	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'h':
		argp_usage(state);
		break;
	case 'c':
		env.csv = true;
		break;
	case 'd':
		errno = 0;
		duration = strtol(arg, NULL, 10);
		if (errno || duration <= 0) {
			fprintf(stderr, "invalid DURATION: %s\n", arg);
			argp_usage(state);
		}
		env.duration = duration;
		break;
	case 'm':
		errno = 0;
		min_lat = strtoll(arg, NULL, 10);
		if (errno || min_lat < 0) {
			fprintf(stderr, "invalid delay (in ms): %s\n", arg);
		}
		env.min_lat = min_lat;
		break;
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		env.pid = pid;
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

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	if (env.csv) {
		printf("%lld,%s,%d,%c,", e->end_ns, e->task, e->tgid, e->type);
		if (e->size == LLONG_MAX)
			printf("LL_MAX,");
		else
			printf("%ld,", e->size);
		printf("%lld,%lld,%s\n", e->offset, e->delta_us, e->file);
	} else {
		printf("%-8s %-14.14s %-6d %c ", ts, e->task, e->tgid, e->type);
		if (e->size == LLONG_MAX)
			printf("%-7s ", "LL_MAX");
		else
			printf("%-7ld ", e->size);
		printf("%-8lld %7.2f %s\n", e->offset / 1024,
		       (double)e->delta_us / 1000, e->file);
	}
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
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
	struct xfsslower_bpf *obj;
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

	obj = xfsslower_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	obj->rodata->min_lat = env.min_lat;
	obj->rodata->targ_tgid = env.pid;

	err = xfsslower_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = xfsslower_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	if (env.csv)
		printf("ENDTIME_us,TASK,PID,TYPE,BYTES,OFFSET_b,LATENCY_us,FILE");
	else {
		if (env.min_lat)
			printf("Tracing XFS operations slower than %llu ms",
				env.min_lat);
		else
			printf("Tracing XFS operations");
		if (env.duration)
			printf(" for %ld secs.\n", env.duration);
		else
			printf("... Hit Ctrl-C to end.\n");
		printf("%-8s %-14s %-6s %1s %-7s %-8s %7s %s",
			"TIME", "COMM", "PID", "T", "BYTES", "OFF_KB", "LAT(ms)",
			"FILENAME\n");
	}

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
	fprintf(stderr, "failed with polling perf buffer: %d\n", err);

cleanup:
	perf_buffer__free(pb);
	xfsslower_bpf__destroy(obj);

	return err != 0;
}
