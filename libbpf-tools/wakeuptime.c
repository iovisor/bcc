// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2022 Nicolas Sterchele
//
// Based on wakeuptime(8) from BCC by Brendan Gregg
// XX-Jul-2022 Nicolas Sterchele created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "wakeuptime.h"
#include "wakeuptime.skel.h"
#include "trace_helpers.h"
#include <unistd.h>

struct env {
	pid_t pid;
	bool user_threads_only;
	bool verbose;
	int stack_storage_size;
	int perf_max_stack_depth;
	__u64 min_block_time;
	__u64 max_block_time;
	int duration;
} env = {
	.verbose = false,
	.stack_storage_size = 1024,
	.perf_max_stack_depth = 127,
	.min_block_time = 1,
	.max_block_time = -1,
	.duration = 99999999,
};

const char *argp_program_version = "wakeuptime 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Summarize sleep to wakeup time by waker kernel stack.\n"
"\n"
"USAGE: wakeuptime [-h] [-p PID | -u] [-v] [-m MIN-BLOCK-TIME] "
"[-M MAX-BLOCK-TIME] ]--perf-max-stack-depth] [--stack-storage-size] [duration]\n"
"EXAMPLES:\n"
"	wakeuptime		# trace blocked time with waker stacks\n"
"	wakeuptime 5		# trace for 5 seconds only\n"
"	wakeuptime -u		# don't include kernel threads (user only)\n"
"	wakeuptime -p 185	# trace for PID 185 only\n";

#define OPT_PERF_MAX_STACK_DEPTH	1 /* --pef-max-stack-depth */
#define OPT_STACK_STORAGE_SIZE		2 /* --stack-storage-size */

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "trace this PID only", 0 },
	{ "verbose", 'v', NULL, 0, "show raw addresses", 0 },
	{ "user-threads-only", 'u', NULL, 0, "user threads only (no kernel threads)", 0 },
	{ "perf-max-stack-depth", OPT_PERF_MAX_STACK_DEPTH,
		"PERF-MAX-STACK-DEPTH", 0, "the limit for both kernel and user stack traces (default 127)", 0 },
	{ "stack-storage-size", OPT_STACK_STORAGE_SIZE, "STACK-STORAGE-SIZE", 0,
		"the number of unique stack traces that can be stored and displayed (default 1024)", 0 },
	{ "min-block-time", 'm', "MIN-BLOCK-TIME", 0,
		"the amount of time in microseconds over which we store traces (default 1)", 0 },
	{ "max-block-time", 'M', "MAX-BLOCK-TIME", 0,
		"the amount of time in microseconds under which we store traces (default U64_MAX)", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;
	int pid;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'u':
		env.user_threads_only = true;
		break;
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			fprintf(stderr, "Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		env.pid = pid;
		break;
	case OPT_PERF_MAX_STACK_DEPTH:
		errno = 0;
		env.perf_max_stack_depth = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid perf max stack depth: %s\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_STACK_STORAGE_SIZE:
		errno = 0;
		env.stack_storage_size = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid stack storage size: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'm':
		errno = 0;
		env.min_block_time = strtoll(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid min block time (in us): %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'M':
		errno = 0;
		env.max_block_time = strtoll(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid min block time (in us): %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0){
			env.duration = strtol(arg, NULL, 10);
			if (errno || env.duration <= 0) {
				fprintf(stderr, "invalid duration (in s)\n");
				argp_usage(state);
			}
		} else {
			fprintf(stderr, "Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
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

static void sig_int(int signo)
{
}

static void print_map(struct ksyms *ksyms, struct wakeuptime_bpf *obj)
{
	struct key_t lookup_key = {}, next_key;
	int err, i, counts_fd, stack_traces_fd;
	unsigned long *ip;
	const struct ksym *ksym;
	__u64 val;

	ip = calloc(env.perf_max_stack_depth, sizeof(*ip));
	if (!ip) {
		fprintf(stderr, "failed to alloc ip\n");
		return;
	}

	counts_fd = bpf_map__fd(obj->maps.counts);
	stack_traces_fd = bpf_map__fd(obj->maps.stackmap);

	while (!bpf_map_get_next_key(counts_fd, &lookup_key, &next_key)){
		err = bpf_map_lookup_elem(counts_fd, &next_key, &val);
		if (err < 0) {
			fprintf(stderr, "failed to lookup info: %d\n", err);
			free(ip);
			return;
		}
		printf("\n	%-16s %s\n", "target:", next_key.target);
		lookup_key = next_key;

		err = bpf_map_lookup_elem(stack_traces_fd, &next_key.w_k_stack_id, ip);
		if (err < 0) {
			fprintf(stderr, "missed kernel stack: %d\n", err);
		}
		for (i = 0; i < env.perf_max_stack_depth && ip[i]; i++) {
			ksym = ksyms__map_addr(ksyms, ip[i]);
			if (ksym)
				printf("	%-16lx %s+0x%lx\n", ip[i], ksym->name, ip[i] - ksym->addr);
			else
				printf("	%-16lx Unknown\n", ip[i]);
		}
		printf("	%16s %s\n","waker:", next_key.waker);
		/*to convert val in microseconds*/
		val /= 1000;
		printf("	%lld\n", val);
	}

	free(ip);
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct wakeuptime_bpf *obj;
	struct ksyms *ksyms = NULL;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.min_block_time >= env.max_block_time) {
		fprintf(stderr, "min_block_time should be smaller than max_block_time\n");
		return 1;
	}

	if (env.user_threads_only && env.pid > 0) {
		fprintf(stderr, "use either -u or -p");
	}

	libbpf_set_print(libbpf_print_fn);

	obj = wakeuptime_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	obj->rodata->targ_pid = env.pid;
	obj->rodata->min_block_ns = env.min_block_time * 1000;
	obj->rodata->max_block_ns = env.max_block_time * 1000;
	obj->rodata->user_threads_only = env.user_threads_only;

	bpf_map__set_value_size(obj->maps.stackmap,
				env.perf_max_stack_depth * sizeof(unsigned long));
	bpf_map__set_max_entries(obj->maps.stackmap, env.stack_storage_size);

	err = wakeuptime_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	ksyms = ksyms__load();
	if (!ksyms) {
		fprintf(stderr, "failed to load kallsyms\n");
		goto cleanup;
	}

	err = wakeuptime_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	printf("Tracing blocked time (us) by kernel stack\n");
	sleep(env.duration);
	print_map(ksyms, obj);

cleanup:
	wakeuptime_bpf__destroy(obj);
	ksyms__free(ksyms);
	return err != 0;
}
