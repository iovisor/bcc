// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2021 Hengqi Chen
//
// Based on nfsdist(8) from BCC by Samuel Nair.
// 16-May-2021   Hengqi Chen   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "nfsdist.h"
#include "nfsdist.skel.h"
#include "trace_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting;

static bool emit_timestamp = false;
static bool timestamp_in_ms = false;
static pid_t target_pid = 0;
static int interval = 99999999;
static int count = 99999999;
static bool verbose = false;

const char *argp_program_version = "nfsdist 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Summarize nfs operation latency.\n"
"\n"
"Usage: nfsdist [-h] [-T] [-m] [-p PID] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    nfsdist            # show operation latency as a histogram\n"
"    nfsdist -p 1216    # trace PID 1216 only\n"
"    nfsdist 1 10       # print 1 second summaries, 10 times\n"
"    nfsdist -m 5       # 5s summaries, milliseconds\n";

static const struct argp_option opts[] = {
	{"timestamp", 'T', NULL, 0, "Print timestamp"},
	{"milliseconds", 'm', NULL, 0, "Millisecond histogram"},
	{"pid", 'p', "PID", 0, "Process PID to trace"},
	{"verbose", 'v', NULL, 0, "Verbose debug output"},
	{NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'v':
		verbose = true;
		break;
	case 'T':
		emit_timestamp = true;
		break;
	case 'm':
		timestamp_in_ms = true;
		break;
	case 'p':
		errno = 0;
		target_pid = strtol(arg, NULL, 10);
		if (errno || target_pid <= 0) {
			warn("invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0) {
			interval = strtol(arg, NULL, 10);
			if (errno) {
				warn("invalid internal\n");
				argp_usage(state);
			}
		} else if (pos_args == 1) {
			count = strtol(arg, NULL, 10);
			if (errno) {
				warn("invalid count\n");
				argp_usage(state);
			}
		} else {
			warn("unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		pos_args++;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level,
		    const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = 1;
}

static char *file_op_names[] = {
	[READ] = "read",
	[WRITE] = "write",
	[OPEN] = "open",
	[FSYNC] = "fsync",
	[GETATTR] = "getattr",
};

static struct hist zero;

static int print_hists(struct nfsdist_bpf__bss *bss)
{
	const char *units = timestamp_in_ms ? "msecs" : "usecs";
	enum nfs_file_op op;

	for (op = READ; op < MAX_OP; op++) {
		struct hist hist = bss->hists[op];

		bss->hists[op] = zero;
		if (!memcmp(&zero, &hist, sizeof(hist)))
			continue;
		printf("operation = '%s'\n", file_op_names[op]);
		print_log2_hist(hist.slots, MAX_SLOTS, units);
		printf("\n");
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
	struct nfsdist_bpf *skel;
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
		warn("failed to increase rlimit: %d\n", err);
		return 1;
	}

	skel = nfsdist_bpf__open();
	if (!skel) {
		warn("failed to open BPF object\n");
		return 1;
	}

	skel->rodata->target_pid = target_pid;
	skel->rodata->in_ms = timestamp_in_ms;

	if (!fentry_exists("nfs_file_read", "nfs")) {
		bpf_program__set_autoload(skel->progs.nfs_file_read_fentry, false);
		bpf_program__set_autoload(skel->progs.nfs_file_read_fexit, false);
		bpf_program__set_autoload(skel->progs.nfs_file_write_fentry, false);
		bpf_program__set_autoload(skel->progs.nfs_file_write_fexit, false);
		bpf_program__set_autoload(skel->progs.nfs_file_open_fentry, false);
		bpf_program__set_autoload(skel->progs.nfs_file_open_fexit, false);
		bpf_program__set_autoload(skel->progs.nfs_file_fsync_fentry, false);
		bpf_program__set_autoload(skel->progs.nfs_file_fsync_fexit, false);
		bpf_program__set_autoload(skel->progs.nfs_getattr_fentry, false);
		bpf_program__set_autoload(skel->progs.nfs_getattr_fexit, false);
	} else {
		bpf_program__set_autoload(skel->progs.nfs_file_read_entry, false);
		bpf_program__set_autoload(skel->progs.nfs_file_read_return, false);
		bpf_program__set_autoload(skel->progs.nfs_file_write_entry, false);
		bpf_program__set_autoload(skel->progs.nfs_file_write_return, false);
		bpf_program__set_autoload(skel->progs.nfs_file_open_entry, false);
		bpf_program__set_autoload(skel->progs.nfs_file_open_return, false);
		bpf_program__set_autoload(skel->progs.nfs_file_fsync_entry, false);
		bpf_program__set_autoload(skel->progs.nfs_file_fsync_return, false);
		bpf_program__set_autoload(skel->progs.nfs_getattr_entry, false);
		bpf_program__set_autoload(skel->progs.nfs_getattr_return, false);
	}

	err = nfsdist_bpf__load(skel);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = nfsdist_bpf__attach(skel);
	if (err) {
		warn("failed to attach BPF programs\n");
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	printf("Tracing NFS operation latency... Hit Ctrl-C to end.\n");

	while (1) {
		sleep(interval);
		printf("\n");

		if (emit_timestamp) {
			time(&t);
			tm = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);
			printf("%-8s\n", ts);
		}

		err = print_hists(skel->bss);
		if (err)
			break;

		if (exiting || --count == 0)
			break;
	}

cleanup:
	nfsdist_bpf__destroy(skel);

	return err != 0;
}
