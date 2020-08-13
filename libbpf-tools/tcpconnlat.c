// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// Based on tcpconnlat(8) from BCC by Brendan Gregg.
// 11-Jul-2020   Wenbo Zhang   Created this.
#include <argp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tcpconnlat.h"
#include "tcpconnlat.skel.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100

static struct env {
	__u64 min_us;
	pid_t pid;
	bool timestamp;
	bool verbose;
} env;

const char *argp_program_version = "tcpconnlat 0.1";
const char *argp_program_bug_address = "<ethercflow@gmail.com>";
const char argp_program_doc[] =
"\nTrace TCP connects and show connection latency.\n"
"\n"
"USAGE: tcpconnlat [-h] [-t] [-p PID]\n"
"\n"
"EXAMPLES:\n"
"    tcpconnlat              # summarize on-CPU time as a histogram"
"    tcpconnlat 1            # trace connection latency slower than 1 ms"
"    tcpconnlat 0.1          # trace connection latency slower than 100 us"
"    tcpconnlat -t           # 1s summaries, milliseconds, and timestamps"
"    tcpconnlat -p 185       # trace PID 185 only";

static const struct argp_option opts[] = {
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{ "timestamp", 't', NULL, 0, "Include timestamp on output" },
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
	case 'h':
		argp_usage(state);
		break;
	case 'p':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 't':
		env.timestamp = true;
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			fprintf(stderr,
				"Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		env.min_us = strtod(arg, NULL) * 1000;
		if (errno || env.min_us <= 0) {
			fprintf(stderr, "Invalid delay (in us): %s\n", arg);
			argp_usage(state);
		}
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
	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];
	union {
		struct in_addr  x4;
		struct in6_addr x6;
	} s, d;
	static __u64 start_ts;

	if (env.timestamp) {
		if (start_ts == 0)
			start_ts = e->ts_us;
		printf("%-9.3f ", (e->ts_us - start_ts) / 1000000.0);
	}
	if (e->af == AF_INET) {
		s.x4.s_addr = e->saddr_v4;
		d.x4.s_addr = e->daddr_v4;
	} else if (e->af == AF_INET6) {
		memcpy(&s.x6.s6_addr, e->saddr_v6, sizeof(s.x6.s6_addr));
		memcpy(&d.x6.s6_addr, e->daddr_v6, sizeof(d.x6.s6_addr));
	} else {
		fprintf(stderr, "broken event: event->af=%d", e->af);
		return;
	}

	printf("%-6d %-12.12s %-2d %-16s %-16s %-5d %.2f\n", e->tgid, e->comm,
		e->af == AF_INET ? 4 : 6, inet_ntop(e->af, &s, src, sizeof(src)),
		inet_ntop(e->af, &d, dst, sizeof(dst)), ntohs(e->dport),
		e->delta_us / 1000.0);
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
	struct tcpconnlat_bpf *obj;
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

	obj = tcpconnlat_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF ojbect\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	obj->rodata->targ_min_us = env.min_us;
	obj->rodata->targ_tgid = env.pid;

	err = tcpconnlat_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = tcpconnlat_bpf__attach(obj);
	if (err) {
		goto cleanup;
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

	if (env.timestamp)
		printf("%-9s ", ("TIME(s)"));
	printf("%-6s %-12s %-2s %-16s %-16s %-5s %s\n",
		"PID", "COMM", "IP", "SADDR", "DADDR", "DPORT", "LAT(ms)");

	/* main: poll */
	while (1) {
		if ((err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS)) < 0)
			break;
	}
	printf("error polling perf buffer: %d\n", err);

cleanup:
	tcpconnlat_bpf__destroy(obj);

	return err != 0;
}
