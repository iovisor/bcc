// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// Based on biopattern(8) from BPF-Perf-Tools-Book by Brendan Gregg.
// 17-Jun-2020   Wenbo Zhang   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "biopattern.h"
#include "biopattern.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

static struct env {
	char *disk;
	time_t interval;
	bool timestamp;
	bool verbose;
	int times;
} env = {
	.interval = 99999999,
	.times = 99999999,
};

static volatile bool exiting;

const char *argp_program_version = "biopattern 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Show block device I/O pattern.\n"
"\n"
"USAGE: biopattern [--help] [-T] [-d DISK] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    biopattern              # show block I/O pattern\n"
"    biopattern 1 10         # print 1 second summaries, 10 times\n"
"    biopattern -T 1         # 1s summaries with timestamps\n"
"    biopattern -d sdc       # trace sdc only\n";

static const struct argp_option opts[] = {
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output", 0 },
	{ "disk",  'd', "DISK",  0, "Trace this disk only", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
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
	case 'd':
		env.disk = arg;
		if (strlen(arg) + 1 > DISK_NAME_LEN) {
			fprintf(stderr, "invaild disk name: too long\n");
			argp_usage(state);
		}
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

static int print_map(struct bpf_map *counters, struct partitions *partitions)
{
	__u32 total, lookup_key = -1, next_key;
	int err, fd = bpf_map__fd(counters);
	const struct partition *partition;
	struct counter counter;
	struct tm *tm;
	char ts[32];
	time_t t;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &counter);
		if (err < 0) {
			fprintf(stderr, "failed to lookup counters: %d\n", err);
			return -1;
		}
		lookup_key = next_key;
		total = counter.sequential + counter.random;
		if (!total)
			continue;
		if (env.timestamp) {
			time(&t);
			tm = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);
			printf("%-9s ", ts);
		}
		partition = partitions__get_by_dev(partitions, next_key);
		printf("%-7s %5ld %5ld %8d %10lld\n",
			partition ? partition->name : "Unknown",
			counter.random * 100L / total,
			counter.sequential * 100L / total, total,
			counter.bytes / 1024);
	}

	lookup_key = -1;
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0) {
			fprintf(stderr, "failed to cleanup counters: %d\n", err);
			return -1;
		}
		lookup_key = next_key;
	}

	return 0;
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	struct partitions *partitions = NULL;
	const struct partition *partition;
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct biopattern_bpf *obj;
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

	obj = biopattern_bpf__open_opts(&open_opts);
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	partitions = partitions__load();
	if (!partitions) {
		fprintf(stderr, "failed to load partitions info\n");
		goto cleanup;
	}

	/* initialize global data (filtering options) */
	if (env.disk) {
		partition = partitions__get_by_name(partitions, env.disk);
		if (!partition) {
			fprintf(stderr, "invaild partition name: not exist\n");
			goto cleanup;
		}
		obj->rodata->filter_dev = true;
		obj->rodata->targ_dev = partition->dev;
	}

	err = biopattern_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = biopattern_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	printf("Tracing block device I/O requested seeks... Hit Ctrl-C to "
		"end.\n");
	if (env.timestamp)
		printf("%-9s ", "TIME");
	printf("%-7s %5s %5s %8s %10s\n", "DISK", "%RND", "%SEQ",
		"COUNT", "KBYTES");

	/* main: poll */
	while (1) {
		sleep(env.interval);

		err = print_map(obj->maps.counters, partitions);
		if (err)
			break;

		if (exiting || --env.times == 0)
			break;
	}

cleanup:
	biopattern_bpf__destroy(obj);
	partitions__free(partitions);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
