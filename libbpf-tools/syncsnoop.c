// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 Tiago Ilieve
//
// Based on syncsnoop(8) from BCC by Brendan Gregg.
// 08-Feb-2024   Tiago Ilieve   Created this.
// 19-Jul-2024   Rong Tao       Support more sync syscalls
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <bpf/libbpf.h>
#include "syncsnoop.h"
#include "syncsnoop.skel.h"

#define PERF_BUFFER_PAGES       16
#define PERF_POLL_TIMEOUT_MS    100

static volatile sig_atomic_t exiting = 0;

struct env {
	bool verbose;
} env = {};

const char *argp_program_version = "syncsnoop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace sync syscalls.\n"
"\n"
"USAGE: syncsnoop [--help]\n"
"\n"
"EXAMPLES:\n"
"    syncsnoop  # trace sync syscalls\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
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

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct event e;

	if (data_sz < sizeof(e)) {
		printf("Error: packet too small\n");
		return;
	}
	/* Copy data as alignment in the perf buffer isn't guaranteed. */
	memcpy(&e, data, sizeof(e));

	printf("%-18.9f %-16s %-16s\n", (float) e.ts_us  / 1000000, e.comm,
	       sys_names[e.sys]);
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	printf("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static void sig_int(int signo)
{
	exiting = 1;
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct perf_buffer *pb = NULL;
	struct syncsnoop_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = syncsnoop_bpf__open_and_load();
	if (!obj) {
		fprintf(stderr, "failed to open and load BPF object\n");
		return 1;
	}

	err = syncsnoop_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF object\n");
		return 1;
	}

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* print header */
	printf("%-18s %-16s %s\n", "TIME(s)", "COMM", "CALL");

	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	syncsnoop_bpf__destroy(obj);

	return err != 0;
}
