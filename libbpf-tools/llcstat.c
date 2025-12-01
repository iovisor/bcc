// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// Based on llcstat(8) from BCC by Teng Qin.
// 29-Sep-2020   Wenbo Zhang   Created this.
// 20-Jun-2022   YeZhengMao    Added tid info.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "llcstat.h"
#include "llcstat.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

struct env {
	int sample_period;
	time_t duration;
	bool verbose;
	bool per_thread;
} env = {
	.sample_period = 100,
	.duration = 10,
};

static volatile bool exiting;

const char *argp_program_version = "llcstat 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Summarize cache references and misses by PID.\n"
"\n"
"USAGE: llcstat [--help] [-c SAMPLE_PERIOD] [duration]\n";

static const struct argp_option opts[] = {
	{ "sample_period", 'c', "SAMPLE_PERIOD", 0, "Sample one in this many "
	  "number of cache reference / miss events", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "tid", 't', NULL, 0,
	  "Summarize cache references and misses by PID/TID", 0 },
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
	case 't':
		env.per_thread = true;
		break;
	case 'c':
		errno = 0;
		env.sample_period = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid sample period\n");
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			fprintf(stderr,
				"unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		env.duration = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid duration\n");
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int nr_cpus;

static int open_and_attach_perf_event(__u64 config, int period,
				struct bpf_program *prog,
				struct bpf_link *links[])
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_HARDWARE,
		.freq = 0,
		.sample_period = period,
		.config = config,
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

static void print_map(struct bpf_map *map)
{
	__u64 total_ref = 0, total_miss = 0, total_hit, hit;
	__u32 pid, cpu, tid;
	struct llcstat_key_info lookup_key = { .cpu = -1 }, next_key;
	int err, fd = bpf_map__fd(map);
	struct llcstat_value_info info;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &info);
		if (err < 0) {
			fprintf(stderr, "failed to lookup infos: %d\n", err);
			return;
		}
		hit = info.ref > info.miss ? info.ref - info.miss : 0;
		cpu = next_key.cpu;
		pid = next_key.pid;
		tid = next_key.tid;
		printf("%-8u ", pid);
		if (env.per_thread) {
			printf("%-8u ", tid);
		}
		printf("%-16s %-4u %12llu %12llu %6.2f%%\n",
			info.comm, cpu, info.ref, info.miss,
			info.ref > 0 ? hit * 1.0 / info.ref * 100 : 0);
		total_miss += info.miss;
		total_ref += info.ref;
		lookup_key = next_key;
	}
	total_hit = total_ref > total_miss ? total_ref - total_miss : 0;
	printf("Total References: %llu Total Misses: %llu Hit Rate: %.2f%%\n",
		total_ref, total_miss, total_ref > 0 ?
		total_hit * 1.0 / total_ref * 100 : 0);

	lookup_key.cpu = -1;
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0) {
			fprintf(stderr, "failed to cleanup infos: %d\n", err);
			return;
		}
		lookup_key = next_key;
	}
}

int main(int argc, char **argv)
{
	struct bpf_link **rlinks = NULL, **mlinks = NULL;
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct llcstat_bpf *obj;
	int err, i;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	nr_cpus = libbpf_num_possible_cpus();
	if (nr_cpus < 0) {
		fprintf(stderr, "failed to get # of possible cpus: '%s'!\n",
			strerror(-nr_cpus));
		return 1;
	}
	mlinks = calloc(nr_cpus, sizeof(*mlinks));
	rlinks = calloc(nr_cpus, sizeof(*rlinks));
	if (!mlinks || !rlinks) {
		fprintf(stderr, "failed to alloc mlinks or rlinks\n");
		return 1;
	}

	err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	obj = llcstat_bpf__open_opts(&open_opts);
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		goto cleanup;
	}

	obj->rodata->targ_per_thread = env.per_thread;

	err = llcstat_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	if (open_and_attach_perf_event(PERF_COUNT_HW_CACHE_MISSES,
					env.sample_period,
					obj->progs.on_cache_miss, mlinks))
		goto cleanup;
	if (open_and_attach_perf_event(PERF_COUNT_HW_CACHE_REFERENCES,
					env.sample_period,
					obj->progs.on_cache_ref, rlinks))
		goto cleanup;

	printf("Running for %ld seconds or Hit Ctrl-C to end.\n", env.duration);

	signal(SIGINT, sig_handler);

	sleep(env.duration);

	printf("%-8s ", "PID");
	if (env.per_thread) {
		printf("%-8s ", "TID");
	}
	printf("%-16s %-4s %12s %12s %7s\n",
		"NAME", "CPU", "REFERENCE", "MISS", "HIT%");

	print_map(obj->maps.infos);

cleanup:
	for (i = 0; i < nr_cpus; i++) {
		bpf_link__destroy(mlinks[i]);
		bpf_link__destroy(rlinks[i]);
	}
	free(mlinks);
	free(rlinks);
	llcstat_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
