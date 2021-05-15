// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2021 Wenbo Zhang
//
// Based on offcputime(8) from BCC by Brendan Gregg.
// 19-Mar-2021   Wenbo Zhang   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "offcputime.h"
#include "offcputime.skel.h"
#include "trace_helpers.h"

static struct env {
	pid_t pid;
	pid_t tid;
	bool user_threads_only;
	bool kernel_threads_only;
	int stack_storage_size;
	int perf_max_stack_depth;
	__u64 min_block_time;
	__u64 max_block_time;
	long state;
	int duration;
	bool verbose;
} env = {
	.pid = -1,
	.tid = -1,
	.stack_storage_size = 1024,
	.perf_max_stack_depth = 127,
	.min_block_time = 1,
	.max_block_time = -1,
	.state = -1,
	.duration = 99999999,
};

static volatile bool exiting;

const char *argp_program_version = "offcputime 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Summarize off-CPU time by stack trace.\n"
"\n"
"USAGE: offcputime [--help] [-p PID | -u | -k] [-m MIN-BLOCK-TIME] "
"[-M MAX-BLOCK-TIME] [--state] [--perf-max-stack-depth] [--stack-storage-size] "
"[duration]\n"
"EXAMPLES:\n"
"    offcputime             # trace off-CPU stack time until Ctrl-C\n"
"    offcputime 5           # trace for 5 seconds only\n"
"    offcputime -m 1000     # trace only events that last more than 1000 usec\n"
"    offcputime -M 10000    # trace only events that last less than 10000 usec\n"
"    offcputime -p 185      # only trace threads for PID 185\n"
"    offcputime -t 188      # only trace thread 188\n"
"    offcputime -u          # only trace user threads (no kernel)\n"
"    offcputime -k          # only trace kernel threads (no user)\n";

#define OPT_PERF_MAX_STACK_DEPTH	1 /* --pef-max-stack-depth */
#define OPT_STACK_STORAGE_SIZE		2 /* --stack-storage-size */
#define OPT_STATE			3 /* --state */

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Trace this PID only" },
	{ "tid", 't', "TID", 0, "Trace this TID only" },
	{ "user-threads-only", 'u', NULL, 0,
	  "User threads only (no kernel threads)" },
	{ "kernel-threads-only", 'k', NULL, 0,
	  "Kernel threads only (no user threads)" },
	{ "perf-max-stack-depth", OPT_PERF_MAX_STACK_DEPTH,
	  "PERF-MAX-STACK-DEPTH", 0, "the limit for both kernel and user stack traces (default 127)" },
	{ "stack-storage-size", OPT_STACK_STORAGE_SIZE, "STACK-STORAGE-SIZE", 0,
	  "the number of unique stack traces that can be stored and displayed (default 1024)" },
	{ "min-block-time", 'm', "MIN-BLOCK-TIME", 0,
	  "the amount of time in microseconds over which we store traces (default 1)" },
	{ "max-block-time", 'M', "MAX-BLOCK-TIME", 0,
	  "the amount of time in microseconds under which we store traces (default U64_MAX)" },
	{ "state", OPT_STATE, "STATE", 0, "filter on this thread state bitmask (eg, 2 == TASK_UNINTERRUPTIBLE) see include/linux/sched.h" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
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
	case 'p':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 't':
		errno = 0;
		env.tid = strtol(arg, NULL, 10);
		if (errno || env.tid <= 0) {
			fprintf(stderr, "Invalid TID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'u':
		env.user_threads_only = true;
		break;
	case 'k':
		env.kernel_threads_only = true;
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
	case OPT_STATE:
		errno = 0;
		env.state = strtol(arg, NULL, 10);
		if (errno || env.state < 0 || env.state > 2) {
			fprintf(stderr, "Invalid task state: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			fprintf(stderr,
				"Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		env.duration = strtol(arg, NULL, 10);
		if (errno || env.duration <= 0) {
			fprintf(stderr, "Invalid duration (in s): %s\n", arg);
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

static void sig_handler(int sig)
{
}

static void print_map(struct ksyms *ksyms, struct syms_cache *syms_cache,
		      struct offcputime_bpf *obj)
{
	struct key_t lookup_key = {}, next_key;
	const struct ksym *ksym;
	const struct syms *syms;
	const struct sym *sym;
	int err, i, ifd, sfd;
	unsigned long *ip;
	struct val_t val;

	ip = calloc(env.perf_max_stack_depth, sizeof(*ip));
	if (!ip) {
		fprintf(stderr, "failed to alloc ip\n");
		return;
	}

	ifd = bpf_map__fd(obj->maps.info);
	sfd = bpf_map__fd(obj->maps.stackmap);
	while (!bpf_map_get_next_key(ifd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(ifd, &next_key, &val);
		if (err < 0) {
			fprintf(stderr, "failed to lookup info: %d\n", err);
			goto cleanup;
		}
		lookup_key = next_key;
		if (val.delta == 0)
			continue;
		if (bpf_map_lookup_elem(sfd, &next_key.kern_stack_id, ip) != 0) {
			fprintf(stderr, "    [Missed Kernel Stack]\n");
			goto print_ustack;
		}
		for (i = 0; i < env.perf_max_stack_depth && ip[i]; i++) {
			ksym = ksyms__map_addr(ksyms, ip[i]);
			printf("    %s\n", ksym ? ksym->name : "Unknown");
		}

print_ustack:
		if (next_key.user_stack_id == -1)
			goto skip_ustack;

		if (bpf_map_lookup_elem(sfd, &next_key.user_stack_id, ip) != 0) {
			fprintf(stderr, "    [Missed User Stack]\n");
			continue;
		}

		syms = syms_cache__get_syms(syms_cache, next_key.tgid);
		if (!syms) {
			fprintf(stderr, "failed to get syms\n");
			goto skip_ustack;
		}
		for (i = 0; i < env.perf_max_stack_depth && ip[i]; i++) {
			sym = syms__map_addr(syms, ip[i]);
			if (sym)
				printf("    %s\n", sym->name);
			else
				printf("    [unknown]\n");
		}

skip_ustack:
		printf("    %-16s %s (%d)\n", "-", val.comm, next_key.pid);
		printf("        %lld\n\n", val.delta);
	}

cleanup:
	free(ip);
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct syms_cache *syms_cache = NULL;
	struct ksyms *ksyms = NULL;
	struct offcputime_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;
	if (env.user_threads_only && env.kernel_threads_only) {
		fprintf(stderr, "user_threads_only, kernel_threads_only cann't be used together.\n");
		return 1;
	}
	if (env.min_block_time >= env.max_block_time) {
		fprintf(stderr, "min_block_time should smaller than max_block_time\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	err = bump_memlock_rlimit();
	if (err) {
		fprintf(stderr, "failed to increase rlimit: %d\n", err);
		return 1;
	}

	obj = offcputime_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	obj->rodata->targ_tgid = env.pid;
	obj->rodata->targ_pid = env.tid;
	obj->rodata->user_threads_only = env.user_threads_only;
	obj->rodata->kernel_threads_only = env.kernel_threads_only;
	obj->rodata->state = env.state;
	obj->rodata->min_block_ns = env.min_block_time;
	obj->rodata->max_block_ns = env.max_block_time;

	bpf_map__set_value_size(obj->maps.stackmap,
				env.perf_max_stack_depth * sizeof(unsigned long));
	bpf_map__set_max_entries(obj->maps.stackmap, env.stack_storage_size);

	err = offcputime_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF programs\n");
		goto cleanup;
	}
	ksyms = ksyms__load();
	if (!ksyms) {
		fprintf(stderr, "failed to load kallsyms\n");
		goto cleanup;
	}
	syms_cache = syms_cache__new(0);
	if (!syms_cache) {
		fprintf(stderr, "failed to create syms_cache\n");
		goto cleanup;
	}
	err = offcputime_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	/*
	 * We'll get sleep interrupted when someone presses Ctrl-C (which will
	 * be "handled" with noop by sig_handler).
	 */
	sleep(env.duration);

	print_map(ksyms, syms_cache, obj);

cleanup:
	offcputime_bpf__destroy(obj);
	syms_cache__free(syms_cache);
	ksyms__free(ksyms);
	return err != 0;
}
