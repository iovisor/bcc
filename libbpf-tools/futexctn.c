// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2023 Wenbo Zhang
//
// Based on https://sourceware.org/systemtap/wiki/WSFutexContention
// 10-Jul-2023   Wenbo Zhang   Created this.
#include <argp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include "futexctn.h"
#include "futexctn.skel.h"
#include "trace_helpers.h"
#ifdef USE_BLAZESYM
#include "blazesym.h"
#endif

#ifdef USE_BLAZESYM
static blazesym *symbolizer;
#else
static struct syms_cache *syms_cache;
#endif

static struct env {
	pid_t pid;
	pid_t tid;
	__u64 lock;
	time_t interval;
	int times;
	int stack_storage_size;
	int perf_max_stack_depth;
	bool summary;
	bool timestamp;
	bool milliseconds;
	bool verbose;
} env = {
	.interval = 99999999,
	.times = 99999999,
	.stack_storage_size = 1024,
	.perf_max_stack_depth = 127,
};

static volatile sig_atomic_t exiting = 0;

const char *argp_program_version = "futexctn 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Summarize futex contention latency as a histogram.\n"
"\n"
"USAGE: futexctn [--help] [-T] [-m] [-s] [-p pid] [-t tid] [-l lock] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    futexctn              # summarize futex contention latency as a histogram\n"
"    futexctn 1 10         # print 1 second summaries, 10 times\n"
"    futexctn -mT 1        # 1s summaries, milliseconds, and timestamps\n"
"    futexctn -s 1         # 1s summaries, without stack traces\n"
"    futexctn -l 0x8187bb8 # only trace lock 0x8187bb8\n"
"    futexctn -p 123       # only trace threads for PID 123\n"
"    futexctn -t 125       # only trace thread 125\n";

#define OPT_PERF_MAX_STACK_DEPTH	1 /* --pef-max-stack-depth */
#define OPT_STACK_STORAGE_SIZE		2 /* --stack-storage-size */

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Trace this PID only", 0 },
	{ "tid", 't', "TID", 0, "Trace this TID only", 0 },
	{ "lock", 'l', "LOCK", 0, "Trace this lock only", 0 },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output", 0 },
	{ "milliseconds", 'm', NULL, 0, "Millisecond histogram", 0 },
	{ "perf-max-stack-depth", OPT_PERF_MAX_STACK_DEPTH,
	  "PERF-MAX-STACK-DEPTH", 0, "the limit for the stack traces (default 127)", 0 },
	{ "stack-storage-size", OPT_STACK_STORAGE_SIZE, "STACK-STORAGE-SIZE", 0,
	  "the number of unique stack traces that can be stored and displayed (default 1024)", 0 },
	{ "summary", 's', NULL, 0, "Summary futex contention latency", 0 },
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
	case 'm':
		env.milliseconds = true;
		break;
	case 's':
		env.summary = true;
		break;
	case 'T':
		env.timestamp = true;
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
	case 'l':
		errno = 0;
		env.lock = strtol(arg, NULL, 16);
		if (errno || env.lock <= 0) {
			fprintf(stderr, "Invalid lock: %s\n", arg);
			argp_usage(state);
		}
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

static int print_stack(struct futexctn_bpf *obj, struct hist_key *info)
{
#ifdef USE_BLAZESYM
	sym_src_cfg cfgs[] = {
		{ .src_type = SRC_T_PROCESS, .params = { .process = { .pid = info->pid_tgid >> 32 }}},
	};
	const blazesym_result *result = NULL;
	const blazesym_csym *sym;
#else
	const struct syms *syms;
	const struct sym *sym;
	struct sym_info sinfo;
	int idx = 0;
#endif
	int i, err = 0, fd;
	uint64_t *ip;

	ip = calloc(env.perf_max_stack_depth, sizeof(*ip));
	if (!ip) {
		fprintf(stderr, "failed to alloc ip\n");
		return -1;
	}

	fd = bpf_map__fd(obj->maps.stackmap);
	err = bpf_map_lookup_elem(fd, &info->user_stack_id, ip);
	if (err != 0) {
		fprintf(stderr, "    [Missed User Stack]\n");
		goto cleanup;
	}

#ifdef USE_BLAZESYM
	result = blazesym_symbolize(symbolizer, cfgs, 1, ip, env.perf_max_stack_depth);

	for (i = 0; result && i < result->size; i++) {
		if (result->entries[i].size == 0)
			continue;
		sym = &result->entries[i].syms[0];
		if (sym->line_no)
			printf("    %s:%lu\n", sym->symbol, sym->line_no);
		else
			printf("    %s\n", sym->symbol);
	}
#else
	syms = syms_cache__get_syms(syms_cache, info->pid_tgid >> 32);
	if (!syms) {
		if (!env.verbose) {
			fprintf(stderr, "failed to get syms\n");
		} else {
			for (i = 0; i < env.perf_max_stack_depth && ip[i]; i++)
				printf("    #%-2d 0x%016lx [unknown]\n", idx++, ip[i]);
		}
		goto cleanup;
	}
	for (i = 0; i < env.perf_max_stack_depth && ip[i]; i++) {
		if (!env.verbose) {
			sym = syms__map_addr(syms, ip[i]);
			if (sym)
				printf("    %s\n", sym->name);
			else
				printf("    [unknown]\n");
		} else {
			err = syms__map_addr_dso(syms, ip[i], &sinfo);
			printf("    #%-2d 0x%016lx", idx++, ip[i]);
			if (err == 0) {
				if (sinfo.sym_name)
					printf(" %s+0x%lx", sinfo.sym_name, sinfo.sym_offset);
				printf(" (%s+0x%lx)", sinfo.dso_name, sinfo.dso_offset);
			}
			printf("\n");
		}
	}
#endif

cleanup:
#ifdef USE_BLAZESYM
	blazesym_result_free(result);
#endif

	free(ip);

	return 0;
}

static int print_map(struct futexctn_bpf *obj)
{
	struct hist_key lookup_key = { .pid_tgid = -1 }, next_key;
	const char *units = env.milliseconds ? "msecs" : "usecs";
	int err,fd = bpf_map__fd(obj->maps.hists);
	struct hist hist;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &hist);
		if (err < 0) {
			fprintf(stderr, "failed to lookup hist: %d\n", err);
			return -1;
		}
		printf("\n\n");
		printf(
		    "%s[%u] lock 0x%llx contended %llu times, %llu avg %s "
		    "[max: %llu %s, min %llu %s]\n",
		    hist.comm, (__u32)next_key.pid_tgid, next_key.uaddr,
		    hist.contended, hist.total_elapsed / hist.contended, units,
		    hist.max, units, hist.min, units);
		if (!env.summary) {
			printf("    -\n");
			print_stack(obj, &next_key);
			printf("    -\n");
		}
		print_log2_hist(hist.slots, MAX_SLOTS, units);
		lookup_key = next_key;
	}

	lookup_key.pid_tgid = -1;
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
	struct futexctn_bpf *obj;
	struct tm *tm;
	char ts[32];
	time_t t;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = futexctn_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	obj->rodata->targ_pid = env.pid;
	obj->rodata->targ_tid = env.tid;
	obj->rodata->targ_lock = env.lock;
	obj->rodata->targ_ms = env.milliseconds;
	obj->rodata->targ_summary = env.summary;

	bpf_map__set_value_size(obj->maps.stackmap,
				env.perf_max_stack_depth * sizeof(unsigned long));
	bpf_map__set_max_entries(obj->maps.stackmap, env.stack_storage_size);

	err = futexctn_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF programs\n");
		goto cleanup;
	}
	err = futexctn_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

#ifdef USE_BLAZESYM
	symbolizer = blazesym_new();
#else
	syms_cache = syms_cache__new(0);
	if (!syms_cache) {
		fprintf(stderr, "failed to create syms_cache\n");
		goto cleanup;
	}
#endif

	signal(SIGINT, sig_handler);

	fprintf(stderr, "Summarize futex contention latency, hit ctrl-c to exit\n");

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

		print_map(obj);

		if (exiting || --env.times == 0)
			break;
	}

cleanup:
	futexctn_bpf__destroy(obj);
#ifdef USE_BLAZESYM
	blazesym_free(symbolizer);
#else
	syms_cache__free(syms_cache);
#endif
	return err != 0;
}
