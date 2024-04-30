// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// Based on runqlen(8) from BCC by Brendan Gregg.
// 11-Sep-2020   Wenbo Zhang   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "runqlen.h"
#include "runqlen.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define max(x, y) ({				 \
	typeof(x) _max1 = (x);			 \
	typeof(y) _max2 = (y);			 \
	(void) (&_max1 == &_max2);		 \
	_max1 > _max2 ? _max1 : _max2; })

struct env {
	bool per_cpu;
	bool runqocc;
	bool timestamp;
	bool host;
	time_t interval;
	int freq;
	int times;
	bool verbose;
} env = {
	.interval = 99999999,
	.times = 99999999,
	.freq = 99,
};

static volatile bool exiting;

const char *argp_program_version = "runqlen 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Summarize scheduler run queue length as a histogram.\n"
"\n"
"USAGE: runqlen [--help] [-C] [-O] [-T] [-f FREQUENCY] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    runqlen         # summarize run queue length as a histogram\n"
"    runqlen 1 10    # print 1 second summaries, 10 times\n"
"    runqlen -T 1    # 1s summaries and timestamps\n"
"    runqlen -O      # report run queue occupancy\n"
"    runqlen -C      # show each CPU separately\n"
"    runqlen -H      # show nr_running from host's rq instead of cfs_rq\n"
"    runqlen -f 199  # sample at 199HZ\n";

static const struct argp_option opts[] = {
	{ "cpus", 'C', NULL, 0, "Print output for each CPU separately", 0 },
	{ "frequency", 'f', "FREQUENCY", 0, "Sample with a certain frequency", 0 },
	{ "runqocc", 'O', NULL, 0, "Report run queue occupancy", 0 },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "host", 'H', NULL, 0, "Report nr_running from host's rq", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'C':
		env.per_cpu = true;
		break;
	case 'O':
		env.runqocc = true;
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'H':
		env.host = true;
		break;
	case 'f':
		errno = 0;
		env.freq = strtol(arg, NULL, 10);
		if (errno || env.freq <= 0) {
			fprintf(stderr, "Invalid freq (in hz): %s\n", arg);
			argp_usage(state);
		}
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

static int nr_cpus;

static int open_and_attach_perf_event(int freq, struct bpf_program *prog,
				struct bpf_link *links[])
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.freq = 1,
		.sample_period = freq,
		.config = PERF_COUNT_SW_CPU_CLOCK,
	};
	int i, fd;

	for (i = 0; i < nr_cpus; i++) {
		fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
		if (fd < 0) {
			/* Ignore CPU that is offline */
			if (errno == ENODEV)
				continue;
			fprintf(stderr, "failed to init perf sampling: %s\n",
				strerror(errno));
			return -1;
		}
		links[i] = bpf_program__attach_perf_event(prog, fd);
		if (!links[i]) {
			fprintf(stderr, "failed to attach perf event on cpu: %d\n", i);
			close(fd);
			return -1;
		}
	}

	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = true;
}

static struct hist zero;

static void print_runq_occupancy(struct runqlen_bpf__bss *bss)
{
	struct hist hist;
	int slot, i = 0;
	float runqocc;

	do {
		__u64 samples, idle = 0, queued = 0;

		hist = bss->hists[i];
		bss->hists[i] = zero;
		for (slot = 0; slot < MAX_SLOTS; slot++) {
			__u64 val = hist.slots[slot];

			if (slot == 0)
				idle += val;
			else
				queued += val;
		}
		samples = idle + queued;
		runqocc = queued * 1.0 / max(1ULL, samples);
		if (env.per_cpu)
			printf("runqocc, CPU %-3d %6.2f%%\n", i,
				100 * runqocc);
		else
			printf("runqocc: %0.2f%%\n", 100 * runqocc);
	} while (env.per_cpu && ++i < nr_cpus);
}

static void print_linear_hists(struct runqlen_bpf__bss *bss)
{
	struct hist hist;
	int i = 0;

	do {
		hist = bss->hists[i];
		bss->hists[i] = zero;
		if (env.per_cpu)
			printf("cpu = %d\n", i);
		print_linear_hist(hist.slots, MAX_SLOTS, 0, 1, "runqlen");
	} while (env.per_cpu && ++i < nr_cpus);
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct bpf_link *links[MAX_CPU_NR] = {};
	struct runqlen_bpf *obj;
	struct tm *tm;
	char ts[32];
	int err, i;
	time_t t;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	nr_cpus = libbpf_num_possible_cpus();
	if (nr_cpus < 0) {
		printf("failed to get # of possible cpus: '%s'!\n",
		       strerror(-nr_cpus));
		return 1;
	}
	if (nr_cpus > MAX_CPU_NR) {
		fprintf(stderr, "the number of cpu cores is too big, please "
			"increase MAX_CPU_NR's value and recompile");
		return 1;
	}

	err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	obj = runqlen_bpf__open_opts(&open_opts);
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	obj->rodata->targ_per_cpu = env.per_cpu;
	obj->rodata->targ_host = env.host;

	err = runqlen_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	if (!obj->bss) {
		fprintf(stderr, "Memory-mapping BPF maps is supported starting from Linux 5.7, please upgrade.\n");
		goto cleanup;
	}

	err = open_and_attach_perf_event(env.freq, obj->progs.do_sample, links);
	if (err)
		goto cleanup;

	printf("Sampling run queue length... Hit Ctrl-C to end.\n");

	signal(SIGINT, sig_handler);

	while (1) {
		sleep(env.interval);
		printf("\n");

		if (env.timestamp) {
			time(&t);
			tm = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);
			printf("%-8s\n", ts);
		}

		if (env.runqocc)
			print_runq_occupancy(obj->bss);
		else
			print_linear_hists(obj->bss);

		if (exiting || --env.times == 0)
			break;
	}

cleanup:
	for (i = 0; i < nr_cpus; i++)
		bpf_link__destroy(links[i]);
	runqlen_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
