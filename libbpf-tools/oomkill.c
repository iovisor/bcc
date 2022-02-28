// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2022 Jingxiang Zeng
//
// Based on oomkill(8) from BCC by Brendan Gregg.
// 13-Jan-2022   Jingxiang Zeng   Created this.
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "oomkill.skel.h"
#include "oomkill.h"
#include "trace_helpers.h"

#define PERF_POLL_TIMEOUT_MS	100

static volatile sig_atomic_t exiting = 0;

static bool verbose = false;

const char *argp_program_version = "oomkill 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace OOM kills.\n"
"\n"
"USAGE: oomkill [-h]\n"
"\n"
"EXAMPLES:\n"
"    oomkill               # trace OOM kills\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	FILE *f;
	char buf[256];
	int n = 0;
	struct tm *tm;
	char ts[32];
	time_t t;
	struct data_t *e = data;

	f = fopen("/proc/loadavg", "r");
	if (f) {
		memset(buf, 0, sizeof(buf));
		n = fread(buf, 1, sizeof(buf), f);
		fclose(f);
	}
	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	if (n)
		printf("%s Triggered by PID %d (\"%s\"), OOM kill of PID %d (\"%s\"), %lld pages, loadavg: %s\n",
			ts, e->fpid, e->fcomm, e->tpid, e->tcomm, e->pages, buf);
	else
		printf("%s Triggered by PID %d (\"%s\"), OOM kill of PID %d (\"%s\"), %lld pages\n",
                        ts, e->fpid, e->fcomm, e->tpid, e->tcomm, e->pages);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	printf("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static void sig_int(int signo)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct perf_buffer *pb = NULL;
	struct oomkill_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	obj = oomkill_bpf__open_and_load();
	if (!obj) {
		fprintf(stderr, "failed to load and open BPF object\n");
		return 1;
	}

	err = oomkill_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), 64,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %d\n", err);
		err = 1;
		goto cleanup;
	}

	printf("Tracing OOM kills... Ctrl-C to stop.\n");

	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %d\n", err);
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	oomkill_bpf__destroy(obj);

	return err != 0;
}
