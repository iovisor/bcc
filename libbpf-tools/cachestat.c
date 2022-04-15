// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2021 Wenbo Zhang
//
// Based on cachestat(8) from BCC by Brendan Gregg and Allan McAleavy.
// 8-Mar-2021   Wenbo Zhang   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "cachestat.skel.h"
#include "trace_helpers.h"

static struct env {
	time_t interval;
	int times;
	bool timestamp;
	bool verbose;
} env = {
	.interval = 1,
	.times = 99999999,
};

static volatile bool exiting;

const char *argp_program_version = "cachestat 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Count cache kernel function calls.\n"
"\n"
"USAGE: cachestat [--help] [-T] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    cachestat          # shows hits and misses to the file system page cache\n"
"    cachestat -T       # include timestamps\n"
"    cachestat 1 10     # print 1 second summaries, 10 times\n";

static const struct argp_option opts[] = {
	{ "timestamp", 'T', NULL, 0, "Print timestamp" },
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

static int get_meminfo(__u64 *buffers, __u64 *cached)
{
	FILE *f;

	f = fopen("/proc/meminfo", "r");
	if (!f)
		return -1;
	if (fscanf(f,
		   "MemTotal: %*u kB\n"
		   "MemFree: %*u kB\n"
		   "MemAvailable: %*u kB\n"
		   "Buffers: %llu kB\n"
		   "Cached: %llu kB\n",
		   buffers, cached) != 2) {
		fclose(f);
		return -1;
	}
	fclose(f);
	return 0;
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	__u64 buffers, cached, mbd;
	struct cachestat_bpf *obj;
	__s64 total, misses, hits;
	struct tm *tm;
	float ratio;
	char ts[32];
	time_t t;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	obj = cachestat_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	/**
	 * account_page_dirtied was renamed to folio_account_dirtied
	 * in kernel commit 203a31516616 ("mm/writeback: Add __folio_mark_dirty()")
	 */
	if (fentry_can_attach("folio_account_dirtied", NULL)) {
		err = bpf_program__set_attach_target(obj->progs.account_page_dirtied, 0,
						     "folio_account_dirtied");
		if (err) {
			fprintf(stderr, "failed to set attach target\n");
			goto cleanup;
		}
	}

	err = cachestat_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object\n");
		goto cleanup;
	}

	if (!obj->bss) {
		fprintf(stderr, "Memory-mapping BPF maps is supported starting from Linux 5.7, please upgrade.\n");
		goto cleanup;
	}

	err = cachestat_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	if (env.timestamp)
		printf("%-8s ", "TIME");
	printf("%8s %8s %8s %8s %12s %10s\n", "HITS", "MISSES", "DIRTIES",
		"HITRATIO", "BUFFERS_MB", "CACHED_MB");

	while (1) {
		sleep(env.interval);

		/* total = total cache accesses without counting dirties */
		total = __atomic_exchange_n(&obj->bss->total, 0, __ATOMIC_RELAXED);
		/* misses = total of add to lru because of read misses */
		misses = __atomic_exchange_n(&obj->bss->misses, 0, __ATOMIC_RELAXED);
		/* mbd = total of mark_buffer_dirty events */
		mbd = __atomic_exchange_n(&obj->bss->mbd, 0, __ATOMIC_RELAXED);

		if (total < 0)
			total = 0;
		if (misses < 0)
			misses = 0;
		hits = total - misses;
		/*
		 * If hits are < 0, then its possible misses are overestimated
		 * due to possibly page cache read ahead adding more pages than
		 * needed. In this case just assume misses as total and reset
		 * hits.
		 */
		if (hits < 0) {
			misses = total;
			hits = 0;
		}
		ratio = total > 0 ? hits * 1.0 / total : 0.0;
		err = get_meminfo(&buffers, &cached);
		if (err) {
			fprintf(stderr, "failed to get meminfo: %d\n", err);
			goto cleanup;
		}
		if (env.timestamp) {
			time(&t);
			tm = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);
			printf("%-8s ", ts);
		}
		printf("%8lld %8lld %8llu %7.2f%% %12llu %10llu\n",
			hits, misses, mbd, 100 * ratio,
			buffers / 1024, cached / 1024);

		if (exiting || --env.times == 0)
			break;
	}

cleanup:
	cachestat_bpf__destroy(obj);
	return err != 0;
}
