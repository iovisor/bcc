// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// Based on bitesize(8) from BCC by Brendan Gregg.
// 16-Jun-2020   Wenbo Zhang   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "bitesize.h"
#include "bitesize.skel.h"
#include "trace_helpers.h"

static struct env {
	char *comm;
	int comm_len;
	time_t interval;
	bool timestamp;
	bool verbose;
	int times;
} env = {
	.interval = 99999999,
	.times = 99999999,
};

static volatile bool exiting;

const char *argp_program_version = "bitesize 0.1";
const char *argp_program_bug_address = "<ethercflow@gmail.com>";
const char argp_program_doc[] =
"Summarize block device I/O size as a histogram.\n"
"\n"
"USAGE: bitesize [-h] [-T] [-m] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    bitesize              # summarize block I/O latency as a histogram\n"
"    bitesize 1 10         # print 1 second summaries, 10 times\n"
"    bitesize -T 1         # 1s summaries with timestamps\n"
"    bitesize -c fio       # trace fio only\n";

static const struct argp_option opts[] = {
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output" },
	{ "comm",  'c', "COMM",  0, "Trace this comm only" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args, len;

	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'h':
		argp_usage(state);
		break;
	case 'c':
		env.comm = arg;
		len = strlen(arg) + 1;
		env.comm_len = len > TASK_COMM_LEN ? TASK_COMM_LEN : len;
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

static int print_log2_hists(int fd)
{
	struct hist_key lookup_key, next_key;
	struct hist hist;
	int err;

	memset(lookup_key.comm, '?', sizeof(lookup_key.comm));
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &hist);
		if (err < 0) {
			fprintf(stderr, "failed to lookup hist: %d\n", err);
			return -1;
		}
		printf("\nProcess Name = %s\n", next_key.comm);
		print_log2_hist(hist.slots, MAX_SLOTS, "Kbytes");
		lookup_key = next_key;
	}

	memset(lookup_key.comm, '?', sizeof(lookup_key.comm));
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
	struct bitesize_bpf *obj;
	struct tm *tm;
	char ts[32];
	int fd, err;
	time_t t;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	err = bump_memlock_rlimit();
	if (err) {
		fprintf(stderr, "failed to increase rlimit: %d\n", err);
		return 1;
	}

	obj = bitesize_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF ojbect\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	if (env.comm)
		strncpy((char*)obj->rodata->targ_comm, env.comm, env.comm_len);

	err = bitesize_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = bitesize_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	fd = bpf_map__fd(obj->maps.hists);

	signal(SIGINT, sig_handler);

	printf("Tracing block device I/O... Hit Ctrl-C to end.\n");

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

		err = print_log2_hists(fd);
		if (err)
			break;

		if (exiting || --env.times == 0)
			break;
	}

cleanup:
	bitesize_bpf__destroy(obj);

	return err != 0;
}
