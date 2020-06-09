// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// Based on filelife(8) from BCC by Brendan Gregg & Allan McAleavy.
// 20-Mar-2020   Wenbo Zhang   Created this.
#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "filelife.h"
#include "filelife.skel.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100

static struct env {
	pid_t pid;
	bool verbose;
} env = { };

const char *argp_program_version = "filelife 0.1";
const char *argp_program_bug_address = "<ethercflow@gmail.com>";
const char argp_program_doc[] =
"Trace the lifespan of short-lived files.\n"
"\n"
"USAGE: filelife [-p PID]\n"
"\n"
"EXAMPLES:\n"
"    filelife         # trace all events\n"
"    filelife -p 123  # trace pid 123\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process PID to trace" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	int pid;

	switch (key) {
	case 'v':
		env.verbose = true;
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
	printf("%-8s %-6d %-16s %-7.2f %s\n",
	       ts, e->tgid, e->task, (double)e->delta_ns / 1000000000,
	       e->file);
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
	struct filelife_bpf *obj;
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

	obj = filelife_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	obj->rodata->targ_tgid = env.pid;

	err = filelife_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = filelife_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	printf("Tracing the lifespan of short-lived files ... Hit Ctrl-C to end.\n");
	printf("%-8s %-6s %-16s %-7s %s\n", "TIME", "PID", "COMM", "AGE(s)", "FILE");

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

	while ((err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS)) >= 0)
		;
	fprintf(stderr, "error polling perf buffer: %d\n", err);

cleanup:
	perf_buffer__free(pb);
	filelife_bpf__destroy(obj);

	return err != 0;
}
