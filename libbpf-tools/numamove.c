// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// Based on numamove(8) from BPF-Perf-Tools-Book by Brendan Gregg.
//  8-Jun-2020   Wenbo Zhang   Created this.
// 30-Jan-2023   Rong Tao      Use fentry_can_attach() to decide use fentry/kprobe.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "numamove.skel.h"
#include "trace_helpers.h"

static struct env {
	bool verbose;
} env;

static volatile bool exiting;

const char *argp_program_version = "numamove 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Show page migrations of type NUMA misplaced per second.\n"
"\n"
"USAGE: numamove [--help]\n"
"\n"
"EXAMPLES:\n"
"    numamove              # Show page migrations' count and latency";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
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

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct numamove_bpf *obj;
	struct tm *tm;
	char ts[32];
	time_t t;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = numamove_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
	}

	if (!obj->bss) {
		fprintf(stderr, "Memory-mapping BPF maps is supported starting from Linux 5.7, please upgrade.\n");
		goto cleanup;
	}

	/* It fallbacks to kprobes when kernel does not support fentry. */
	if (fentry_can_attach("migrate_misplaced_page", NULL)) {
		bpf_program__set_autoload(obj->progs.kprobe_migrate_misplaced_page, false);
		bpf_program__set_autoload(obj->progs.kretprobe_migrate_misplaced_page_exit, false);
	} else {
		bpf_program__set_autoload(obj->progs.fentry_migrate_misplaced_page, false);
		bpf_program__set_autoload(obj->progs.fexit_migrate_misplaced_page_exit, false);
	}

	err = numamove_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF skelect: %d\n", err);
		goto cleanup;
	}

	err = numamove_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	printf("%-10s %18s %18s\n", "TIME", "NUMA_migrations", "NUMA_migrations_ms");
	while (!exiting) {
		sleep(1);
		time(&t);
		tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		printf("%-10s %18lld %18lld\n", ts,
			__atomic_exchange_n(&obj->bss->num, 0, __ATOMIC_RELAXED),
			__atomic_exchange_n(&obj->bss->latency, 0, __ATOMIC_RELAXED));
	}

cleanup:
	numamove_bpf__destroy(obj);
	return err != 0;
}
