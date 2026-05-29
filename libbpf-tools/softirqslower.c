// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2026 Ism Hong
//
// Based on softirqslower(8) from BCC by Chenyue Zhou.
// libbpf/CO-RE version.
// 27-May-2026   Ported to libbpf.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "softirqslower.h"
#include "softirqslower.skel.h"
#include "trace_helpers.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

static volatile sig_atomic_t exiting = 0;

struct env {
	__u64 min_us;
	int   targ_cpu;
	bool  verbose;
} env = {
	.min_us   = 10000,
	.targ_cpu = -1,
};

const char *argp_program_version = "softirqslower 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace slow soft IRQ (interrupt).\n"
"\n"
"USAGE: softirqslower [--help] [-c CPU] [min_us]\n"
"\n"
"EXAMPLES:\n"
"    softirqslower        # trace softirq latency higher than 10000 us (default)\n"
"    softirqslower 100000 # trace softirq latency higher than 100000 us\n"
"    softirqslower -c 1   # trace softirq latency on CPU 1 only\n";

static const struct argp_option opts[] = {
	{ "cpu",     'c', "CPU",  0, "Trace this CPU only", 0 },
	{ "verbose", 'v', NULL,   0, "Verbose debug output", 0 },
	{ NULL,      'h', NULL,   OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;
	long long val;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'c':
		errno = 0;
		val = strtol(arg, NULL, 10);
		if (errno || val < 0) {
			fprintf(stderr, "invalid cpu: %s\n", arg);
			argp_usage(state);
		}
		env.targ_cpu = (int)val;
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			fprintf(stderr,
				"Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		val = strtoll(arg, NULL, 10);
		if (errno || val <= 0) {
			fprintf(stderr,
				"Invalid min latency (in us): %s\n", arg);
			argp_usage(state);
		}
		env.min_us = (__u64)val;
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

static void sig_int(int signo)
{
	exiting = 1;
}

/* Softirq vector names – same order as the kernel enum */
static const char *vec_names[] = {
	[0] = "hi",
	[1] = "timer",
	[2] = "net_tx",
	[3] = "net_rx",
	[4] = "block",
	[5] = "irq_poll",
	[6] = "tasklet",
	[7] = "sched",
	[8] = "hrtimer",
	[9] = "rcu",
};

static const char *stage_names[] = {
	[SOFTIRQ_RAISE] = "irq(hard) to softirq",
	[SOFTIRQ_ENTRY] = "softirq runtime",
};

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct event e;
	char ts[32];

	if (data_sz < sizeof(e)) {
		printf("Error: packet too small\n");
		return;
	}
	memcpy(&e, data, sizeof(e));

	str_timestamp("%H:%M:%S", ts, sizeof(ts));

	printf("%-8s %-20s %-8s %-14llu %-6u %-16s\n",
			ts,
			e.stage < ARRAY_SIZE(stage_names) ? stage_names[e.stage] : "unknown",
			e.vec  < NR_SOFTIRQS ? vec_names[e.vec] : "unknown",
			e.delta_us,
			e.cpu,
			e.task);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	printf("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser  = parse_arg,
		.doc     = argp_program_doc,
	};
	struct perf_buffer       *pb  = NULL;
	struct softirqslower_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = softirqslower_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	/* Configure rodata constants before loading */
	obj->rodata->min_us   = env.min_us;
	obj->rodata->targ_cpu = env.targ_cpu;

	/* Choose between tp_btf (preferred) and raw_tp (fallback) */
	if (probe_tp_btf("softirq_raise")) {
		/* Kernel supports BTF tracepoints – disable raw_tp variants */
		bpf_program__set_autoload(obj->progs.softirq_raise_raw, false);
		bpf_program__set_autoload(obj->progs.softirq_entry_raw, false);
		bpf_program__set_autoload(obj->progs.softirq_exit_raw,  false);
	} else {
		/* Fall back to raw tracepoints – disable tp_btf variants */
		bpf_program__set_autoload(obj->progs.softirq_raise_btf, false);
		bpf_program__set_autoload(obj->progs.softirq_entry_btf, false);
		bpf_program__set_autoload(obj->progs.softirq_exit_btf,  false);
	}

	err = softirqslower_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = softirqslower_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	printf("Tracing softirq latency higher than %llu us... "
			"Hit Ctrl-C to end.\n", env.min_us);
	printf("%-8s %-20s %-8s %-14s %-6s %-16s\n",
			"TIME", "STAGE", "SOFTIRQ", "LAT(us)", "CPU", "COMM");

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), 64,
			handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n",
			strerror(errno));
		err = 1;
		goto cleanup;
	}

	while (!exiting) {
		err = perf_buffer__poll(pb, 100);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n",
				strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	softirqslower_bpf__destroy(obj);

	return err != 0;
}
