// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2021 Wenbo Zhang
//
// Based on ext4dist(8) from BCC by Brendan Gregg.
// 9-Feb-2021   Wenbo Zhang   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "ext4dist.h"
#include "ext4dist.skel.h"
#include "trace_helpers.h"

static struct env {
	bool timestamp;
	bool milliseconds;
	pid_t pid;
	time_t interval;
	int times;
	bool verbose;
} env = {
	.interval = 99999999,
	.times = 99999999,
};

static volatile bool exiting;

const char *argp_program_version = "ext4dist 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Summarize ext4 operation latency.\n"
"\n"
"Usage: ext4dist [-h] [-T] [-m] [-p PID] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    ext4dist          # show operation latency as a histogram\n"
"    ext4dist -p 181   # trace PID 181 only\n"
"    ext4dist 1 10     # print 1 second summaries, 10 times\n"
"    ext4dist -m 5     # 5s summaries, milliseconds\n";

static const struct argp_option opts[] = {
	{ "timestamp", 'T', NULL, 0, "Print timestamp" },
	{ "milliseconds", 'm', NULL, 0, "Millisecond histogram" },
	{ "pid", 'p', "PID", 0, "Process PID to trace" },
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
	case 'T':
		env.timestamp = true;
		break;
	case 'm':
		env.milliseconds = true;
		break;
	case 'p':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno || env.pid <= 0) {
			fprintf(stderr, "invalid PID: %s\n", arg);
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

static char *fop_names[] = {
	[READ_ITER] = "read_iter",
	[WRITE_ITER] = "write_iter",
	[OPEN] = "open",
	[FSYNC] = "fsync",
};

static struct hist zero;

static int print_hists(struct ext4dist_bpf__bss *bss)
{
	const char *units = env.milliseconds ? "msecs" : "usecs";
	enum ext4_fop_type type;

	for (type = READ_ITER; type < __MAX_FOP_TYPE; type++) {
		struct hist hist = bss->hists[type];

		bss->hists[type] = zero;
		if (!memcmp(&zero, &hist, sizeof(hist)))
			continue;
		printf("operation = '%s'\n", fop_names[type]);
		print_log2_hist(hist.slots, MAX_SLOTS, units);
		printf("\n");
	}

	return 0;
}

static bool should_fallback(void)
{
	/*
	 * Check whether EXT4 is compiled into a kernel module and whether
	 * the kernel supports module BTF.
	 *
	 * The purpose of this check is if the kernel supports module BTF,
	 * we can use fentry to get better performance, otherwise we need
	 * to fall back to use kprobe to be compatible with the old kernel.
	 */
	if (is_kernel_module("ext4") && access("/sys/kernel/btf/ext4", R_OK))
		return true;
	return false;
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct ext4dist_bpf *skel;
	struct tm *tm;
	char ts[32];
	time_t t;
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

	skel = ext4dist_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF skelect\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	skel->rodata->targ_ms = env.milliseconds;
	skel->rodata->targ_tgid = env.pid;

	if (should_fallback()) {
		bpf_program__set_autoload(skel->progs.fentry1, false);
		bpf_program__set_autoload(skel->progs.fentry2, false);
		bpf_program__set_autoload(skel->progs.fentry3, false);
		bpf_program__set_autoload(skel->progs.fentry4, false);
		bpf_program__set_autoload(skel->progs.fexit1, false);
		bpf_program__set_autoload(skel->progs.fexit2, false);
		bpf_program__set_autoload(skel->progs.fexit3, false);
		bpf_program__set_autoload(skel->progs.fexit4, false);
	} else {
		bpf_program__set_autoload(skel->progs.kprobe1, false);
		bpf_program__set_autoload(skel->progs.kprobe2, false);
		bpf_program__set_autoload(skel->progs.kprobe3, false);
		bpf_program__set_autoload(skel->progs.kprobe4, false);
		bpf_program__set_autoload(skel->progs.kretprobe1, false);
		bpf_program__set_autoload(skel->progs.kretprobe2, false);
		bpf_program__set_autoload(skel->progs.kretprobe3, false);
		bpf_program__set_autoload(skel->progs.kretprobe4, false);
	}

	err = ext4dist_bpf__load(skel);
	if (err) {
		fprintf(stderr, "failed to load BPF skelect: %d\n", err);
		goto cleanup;
	}

	err = ext4dist_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	printf("Tracing ext4 operation latency... Hit Ctrl-C to end.\n");

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

		err = print_hists(skel->bss);
		if (err)
			break;

		if (exiting || --env.times == 0)
			break;
	}

cleanup:
	ext4dist_bpf__destroy(skel);

	return err != 0;
}
