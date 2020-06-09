// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Anton Protopopov
//
// Based on vfsstat(8) from BCC by Brendan Gregg
#include <argp.h>
#include <unistd.h>
#include <time.h>
#include <bpf/bpf.h>
#include "vfsstat.h"
#include "vfsstat.skel.h"
#include "trace_helpers.h"

const char *argp_program_version = "vfsstat 0.1";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
static const char argp_program_doc[] =
	"\nvfsstat: Count some VFS calls\n"
	"\n"
	"EXAMPLES:\n"
	"    vfsstat      # interval one second\n"
	"    vfsstat 5 3  # interval five seconds, three output lines\n";
static char args_doc[] = "[interval [count]]";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{},
};

static struct env {
	bool verbose;
	int count;
	int interval;
} env = {
	.interval = 1,	/* once a second */
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long interval;
	long count;

	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case ARGP_KEY_ARG:
		switch (state->arg_num) {
		case 0:
			errno = 0;
			interval = strtol(arg, NULL, 10);
			if (errno || interval <= 0 || interval > INT_MAX) {
				fprintf(stderr, "invalid interval: %s\n", arg);
				argp_usage(state);
			}
			env.interval = interval;
			break;
		case 1:
			errno = 0;
			count = strtol(arg, NULL, 10);
			if (errno || count < 0 || count > INT_MAX) {
				fprintf(stderr, "invalid count: %s\n", arg);
				argp_usage(state);
			}
			env.count = count;
			break;
		default:
			argp_usage(state);
			break;
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level,
			   const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static const char *strftime_now(char *s, size_t max, const char *format)
{
	struct tm *tm;
	time_t t;

	t = time(NULL);
	tm = localtime(&t);
	if (tm == NULL) {
		fprintf(stderr, "localtime: %s\n", strerror(errno));
		return "<failed>";
	}
	if (strftime(s, max, format, tm) == 0) {
		fprintf(stderr, "strftime error\n");
		return "<failed>";
	}
	return s;
}

static const char *stat_types_names[] = {
	[S_READ] = "READ",
	[S_WRITE] = "WRITE",
	[S_FSYNC] = "FSYNC",
	[S_OPEN] = "OPEN",
	[S_CREATE] = "CREATE",
};

static void print_header(void)
{
	printf("%-8s  ", "TIME");
	for (int i = 0; i < S_MAXSTAT; i++)
		printf(" %6s/s", stat_types_names[i]);
	printf("\n");
}

static void print_and_reset_stats(__u64 stats[S_MAXSTAT])
{
	char s[16];
	__u64 val;

	printf("%-8s: ", strftime_now(s, sizeof(s), "%H:%M:%S"));
	for (int i = 0; i < S_MAXSTAT; i++) {
		val = __atomic_exchange_n(&stats[i], 0, __ATOMIC_RELAXED);
		printf(" %8llu", val / env.interval);
	}
	printf("\n");
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
		.args_doc = args_doc,
	};
	struct vfsstat_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	err = bump_memlock_rlimit();
	if (err) {
		fprintf(stderr, "failed to increase rlimit: %s\n",
				strerror(errno));
		return 1;
	}

	obj = vfsstat_bpf__open_and_load();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
	}

	err = vfsstat_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs: %s\n",
				strerror(-err));
		goto cleanup;
	}

	print_header();
	do {
		sleep(env.interval);
		print_and_reset_stats(obj->bss->stats);
	} while (!env.count || --env.count);

cleanup:
	vfsstat_bpf__destroy(obj);

	return err != 0;
}
