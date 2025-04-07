// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// Based on drsnoop(8) from BCC by Wenbo Zhang.
// 28-Feb-2020   Wenbo Zhang   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "drsnoop.h"
#include "drsnoop.skel.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100

static volatile sig_atomic_t exiting = 0;

static struct env {
	pid_t pid;
	pid_t tid;
	time_t duration;
	bool extended;
	bool verbose;
} env = { };

const char *argp_program_version = "drsnoop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace direct reclaim latency.\n"
"\n"
"USAGE: drsnoop [--help] [-p PID] [-t TID] [-d DURATION] [-e]\n"
"\n"
"EXAMPLES:\n"
"    drsnoop         # trace all direct reclaim events\n"
"    drsnoop -p 123  # trace pid 123\n"
"    drsnoop -t 123  # trace tid 123 (use for threads only)\n"
"    drsnoop -d 10   # trace for 10 seconds only\n"
"    drsnoop -e      # trace all direct reclaim events with extended fields\n";

static const struct argp_option opts[] = {
	{ "duration", 'd', "DURATION", 0, "Total duration of trace in seconds", 0 },
	{ "extended", 'e', NULL, 0, "Extended fields output", 0 },
	{ "pid", 'p', "PID", 0, "Process PID to trace", 0 },
	{ "tid", 't', "TID", 0, "Thread TID to trace", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static int page_size;

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	time_t duration;
	int pid;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		errno = 0;
		duration = strtol(arg, NULL, 10);
		if (errno || duration <= 0) {
			fprintf(stderr, "invalid DURATION: %s\n", arg);
			argp_usage(state);
		}
		env.duration = duration;
		break;
	case 'e':
		env.extended = true;
		break;
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		env.pid = pid;
		break;
	case 't':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			fprintf(stderr, "invalid TID: %s\n", arg);
			argp_usage(state);
		}
		env.tid = pid;
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
	exiting = 1;
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct event e;
	struct tm *tm;
	char ts[32];
	time_t t;

	if (data_sz < sizeof(e)) {
		printf("Error: packet too small\n");
		return;
	}
	/* Copy data as alignment in the perf buffer isn't guaranteed. */
	memcpy(&e, data, sizeof(e));

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	printf("%-8s %-16s %-6d %8.3f %5lld",
	       ts, e.task, e.pid, e.delta_ns / 1000000.0,
	       e.nr_reclaimed);
	if (env.extended)
		printf(" %8llu", e.nr_free_pages * page_size / 1024);
	printf("\n");
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct perf_buffer *pb = NULL;
	struct ksyms *ksyms = NULL;
	const struct ksym *ksym;
	struct drsnoop_bpf *obj;
	__u64 time_end = 0;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = drsnoop_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	obj->rodata->targ_tgid = env.pid;
	obj->rodata->targ_pid = env.tid;
	if (env.extended) {
		ksyms = ksyms__load();
		if (!ksyms) {
			fprintf(stderr, "failed to load kallsyms\n");
			goto cleanup;
		}
		ksym = ksyms__get_symbol(ksyms, "vm_zone_stat");
		if (!ksym) {
			fprintf(stderr, "failed to get vm_zone_stat's addr\n");
			goto cleanup;
		}
		obj->rodata->vm_zone_stat_kaddr = ksym->addr;
		page_size = sysconf(_SC_PAGESIZE);
	}

	if (probe_tp_btf("mm_vmscan_direct_reclaim_begin")) {
		bpf_program__set_autoload(obj->progs.direct_reclaim_begin, false);
		bpf_program__set_autoload(obj->progs.direct_reclaim_end, false);
	} else {
		bpf_program__set_autoload(obj->progs.direct_reclaim_begin_btf, false);
		bpf_program__set_autoload(obj->progs.direct_reclaim_end_btf, false);
	}

	err = drsnoop_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = drsnoop_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	printf("Tracing direct reclaim events");
	if (env.duration)
		printf(" for %ld secs.\n", env.duration);
	else
		printf("... Hit Ctrl-C to end.\n");
	printf("%-8s %-16s %-6s %8s %5s",
		"TIME", "COMM", "TID", "LAT(ms)", "PAGES");
	if (env.extended)
		printf(" %8s", "FREE(KB)");
	printf("\n");

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	/* setup duration */
	if (env.duration)
		time_end = get_ktime_ns() + env.duration * NSEC_PER_SEC;

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* main: poll */
	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		if (env.duration && get_ktime_ns() > time_end)
			goto cleanup;
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	drsnoop_bpf__destroy(obj);
	ksyms__free(ksyms);

	return err != 0;
}
