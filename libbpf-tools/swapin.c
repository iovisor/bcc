/* swapin */
/* Count swapins by process. */
/* For Linux, uses BCC, eBPF. Embedded C. */
/* TODO: add -s for total swapin time column (sum) */

/* Copyright (c) 2019 Brendan Gregg. */
/* Licensed under the Apache License, Version 2.0 (the "License"). */
/* This was originally created for the BPF Performance Tools book */
/* published by Addison Wesley. ISBN-13: 9780136554820 */
/* When copying or porting, include this comment. */

/* 03-Jul-2019   Brendan Gregg   Ported from bpftrace to BCC. */
/* 06-Apr-2023   Ben Olson       Ported from BCC to libbpf. */

#include "swapin.h"

#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "swapin.skel.h"
#include "trace_helpers.h"

struct env {
	time_t interval;
	pid_t pid;
	int count;
	bool timestamp;
	bool verbose;
} env = {
	.interval = 1,
	.count = 99999999,
};

static volatile bool exiting;

const char *argp_program_version = "swapin 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
	"Count swapins by process.\n"
	"\n"
	"USAGE: swapin [--help] [--timestamp] [--interval INT] [--count CNT] "
	"[--pid PID] [--verbose]\n"
	"\n"
	"EXAMPLES:\n"
	"    swapin          # Print swapins per-process\n";

static const struct argp_option opts[] = {
	{"timestamp", 'T', NULL, 0, "Include timestamp in output."},
	{"interval", 'i', "INT", 0, "Output interval, in seconds. Defaults to 1."},
	{"count", 'c', "CNT", 0, "The number of outputs."},
	{"pid", 'p', "PID", 0, "Trace this PID only."},
	{"verbose", 'v', NULL, 0, "Verbose output."},
	{NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help."},
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'p':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'i':
		env.interval = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid interval\n");
			argp_usage(state);
		}
		break;
	case 'c':
		env.count = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid count\n");
			argp_usage(state);
		}
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'v':
		env.verbose = true;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig) { exiting = true; }

int main(int argc, char **argv) {
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct swapin_bpf *obj;
	char ts[32];
	struct tm *tm;
	time_t t;
	int err, countdown;
	struct key_t lookup_key = {}, next_key;
	int counts_fd;
	__u64 val;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = swapin_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	obj->rodata->target_pid = env.pid;

	err = swapin_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = swapin_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	printf("Count swap ins. Ctrl-C to end.\n");

	signal(SIGINT, sig_handler);

	countdown = env.count;
	counts_fd = bpf_map__fd(obj->maps.counts);
	while (1) {
		sleep(env.interval);
		printf("\n");

		if (env.timestamp) {
			time(&t);
			tm = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);
			printf("%-8s\n", ts);
		}

		printf("%-16s %-7s %s\n", "COMM", "PID", "COUNT");

		while (!bpf_map_get_next_key(counts_fd, &lookup_key, &next_key)) {
			err = bpf_map_lookup_elem(counts_fd, &next_key, &val);
			if (err < 0) {
				fprintf(stderr, "failed to lookup info: %d\n", err);
				goto cleanup;
			}
			printf("%-16s %-7d %lld\n", next_key.comm, next_key.pid, val);
			lookup_key = next_key;
		}
		printf("\n");

		/* Clear the map */
		memset(&lookup_key, 0, sizeof(lookup_key));
		while (!bpf_map_get_next_key(counts_fd, &lookup_key, &next_key)) {
			err = bpf_map_delete_elem(counts_fd, &next_key);
			if (err < 0) {
				fprintf(stderr, "failed to cleanup info: %d\n", err);
				return -1;
			}
			lookup_key = next_key;
		}

		countdown -= 1;

		if (exiting || (countdown == 0)) {
			break;
		}
	}

cleanup:
	swapin_bpf__destroy(obj);

	return err != 0;
}
