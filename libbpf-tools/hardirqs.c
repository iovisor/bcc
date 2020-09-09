// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// Based on hardirq(8) from BCC by Brendan Gregg.
// 31-Aug-2020   Wenbo Zhang   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "hardirqs.h"
#include "hardirqs.skel.h"
#include "trace_helpers.h"

struct env {
	bool count;
	bool distributed;
	bool nanoseconds;
	time_t interval;
	int times;
	bool timestamp;
	bool verbose;
} env = {
	.interval = 99999999,
	.times = 99999999,
};

static volatile bool exiting;

const char *argp_program_version = "hardirqs 0.1";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
"Summarize hard irq event time as histograms.\n"
"\n"
"USAGE: hardirqs [--help] [-T] [-N] [-d] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    hardirqs            # sum hard irq event time\n"
"    hardirqs -d         # show hard irq event time as histograms\n"
"    hardirqs 1 10       # print 1 second summaries, 10 times\n"
"    hardirqs -NT 1      # 1s summaries, nanoseconds, and timestamps\n";

static const struct argp_option opts[] = {
	{ "count", 'C', NULL, 0, "Show event counts instead of timing" },
	{ "distributed", 'd', NULL, 0, "Show distributions as histograms" },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output" },
	{ "nanoseconds", 'N', NULL, 0, "Output in nanoseconds" },
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
	case 'd':
		env.distributed = true;
		break;
	case 'C':
		env.count = true;
		break;
	case 'N':
		env.nanoseconds = true;
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

static int print_map(struct bpf_map *map)
{
	struct irq_key lookup_key = {}, next_key;
	struct info info;
	int fd, err;

	if (env.count) {
		printf("%-26s %11s\n", "HARDIRQ", "TOTAL_count");
	} else if (!env.distributed) {
		const char *units = env.nanoseconds ? "nsecs" : "usecs";

		printf("%-26s %6s%5s\n", "HARDIRQ", "TOTAL_", units);
	}

	fd = bpf_map__fd(map);
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &info);
		if (err < 0) {
			fprintf(stderr, "failed to lookup infos: %d\n", err);
			return -1;
		}
		if (!env.distributed)
			printf("%-26s %11llu\n", next_key.name, info.count);
		else {
			const char *units = env.nanoseconds ? "nsecs" : "usecs";

			printf("hardirq = %s\n", next_key.name);
			print_log2_hist(info.slots, MAX_SLOTS, units);
		}
		lookup_key = next_key;
	}

	memset(&lookup_key, 0, sizeof(lookup_key));

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0) {
			fprintf(stderr, "failed to cleanup infos: %d\n", err);
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
	struct hardirqs_bpf *obj;
	struct tm *tm;
	char ts[32];
	time_t t;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.count && env.distributed) {
		fprintf(stderr, "count, distributed cann't be used together.\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	err = bump_memlock_rlimit();
	if (err) {
		fprintf(stderr, "failed to increase rlimit: %d\n", err);
		return 1;
	}

	obj = hardirqs_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	if (!env.count) {
		obj->rodata->targ_dist = env.distributed;
		obj->rodata->targ_ns = env.nanoseconds;
	}

	err = hardirqs_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	if (env.count) {
		obj->links.handle__irq_handler =
			bpf_program__attach(obj->progs.handle__irq_handler);
		err = libbpf_get_error(obj->links.handle__irq_handler);
		if (err) {
			fprintf(stderr,
				"failed to attach irq/irq_handler_entry: %s\n",
				strerror(err));
		}
	} else {
		obj->links.irq_handler_entry =
			bpf_program__attach(obj->progs.irq_handler_entry);
		err = libbpf_get_error(obj->links.irq_handler_entry);
		if (err) {
			fprintf(stderr,
				"failed to attach irq_handler_entry: %s\n",
				strerror(err));
		}
		obj->links.irq_handler_exit_exit =
			bpf_program__attach(obj->progs.irq_handler_exit_exit);
		err = libbpf_get_error(obj->links.irq_handler_exit_exit);
		if (err) {
			fprintf(stderr,
				"failed to attach irq_handler_exit: %s\n",
				strerror(err));
		}
	}

	signal(SIGINT, sig_handler);

	if (env.count)
		printf("Tracing hard irq events... Hit Ctrl-C to end.\n");
	else
		printf("Tracing hard irq event time... Hit Ctrl-C to end.\n");

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

		err = print_map(obj->maps.infos);
		if (err)
			break;

		if (exiting || --env.times == 0)
			break;
	}

cleanup:
	hardirqs_bpf__destroy(obj);

	return err != 0;
}
