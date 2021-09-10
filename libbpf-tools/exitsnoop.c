/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * exitsnoop	Trace process termination.
 *
 * Copyright (c) 2021 Hengqi Chen
 *
 * Based on exitsnoop(8) from BCC by Arturo Martin-de-Nicolas & Jeroen Soeters.
 * 05-Aug-2021   Hengqi Chen   Created this.
 */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <time.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "exitsnoop.h"
#include "exitsnoop.skel.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100
#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;

static bool emit_timestamp = false;
static pid_t target_pid = 0;
static bool trace_failed_only = false;
static bool trace_by_process = true;

const char *argp_program_version = "exitsnoop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace process termination.\n"
"\n"
"USAGE: exitsnoop [-h] [-t] [-x] [-p PID] [-T]\n"
"\n"
"EXAMPLES:\n"
"    exitsnoop             # trace process exit events\n"
"    exitsnoop -t          # include timestamps\n"
"    exitsnoop -x          # trace error exits only\n"
"    exitsnoop -p 1216     # only trace PID 1216\n"
"    exitsnoop -T          # trace by thread\n";

static const struct argp_option opts[] = {
	{ "timestamp", 't', NULL, 0, "Include timestamp on output" },
	{ "failed", 'x', NULL, 0, "Trace error exits only." },
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "threaded", 'T', NULL, 0, "Trace by thread." },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long pid;

	switch (key) {
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			warn("Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		target_pid = pid;
		break;
	case 't':
		emit_timestamp = true;
		break;
	case 'x':
		trace_failed_only = true;
		break;
	case 'T':
		trace_by_process = false;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static void sig_int(int signo)
{
	exiting = 1;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct event *e = data;
	time_t t;
	struct tm *tm;
	char ts[32];
	double age;
	int sig, coredump;

	if (emit_timestamp) {
		time(&t);
		tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		printf("%8s ", ts);
	}

	age = (e->exit_time - e->start_time) / 1e9;
	printf("%-16s %-7d %-7d %-7d %-7.2f ",
	       e->comm, e->pid, e->ppid, e->tid, age);

	if (!e->sig) {
		if (!e->exit_code)
			printf("0\n");
		else
			printf("code %d\n", e->exit_code);
	} else {
		sig = e->sig & 0x7f;
		coredump = e->sig & 0x80;
		if (sig)
			printf("signal %d (%s)", sig, strsignal(sig));
		if (coredump)
			printf(", core dumped");
		printf("\n");
	}
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct perf_buffer_opts pb_opts;
	struct perf_buffer *pb = NULL;
	struct exitsnoop_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	err = bump_memlock_rlimit();
	if (err) {
		warn("failed to increase rlimit: %d\n", err);
		return 1;
	}

	obj = exitsnoop_bpf__open();
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->target_pid = target_pid;
	obj->rodata->trace_failed_only = trace_failed_only;
	obj->rodata->trace_by_process = trace_by_process;

	err = exitsnoop_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = exitsnoop_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	pb_opts.sample_cb = handle_event;
	pb_opts.lost_cb = handle_lost_events;
	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES, &pb_opts);
	err = libbpf_get_error(pb);
	if (err) {
		warn("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(-errno));
		goto cleanup;
	}

	if (emit_timestamp)
		printf("%-8s ", "TIME(s)");
	printf("%-16s %-7s %-7s %-7s %-7s %-s\n",
	       "PCOMM", "PID", "PPID", "TID", "AGE(s)", "EXIT_CODE");

	while (1) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err == -EINTR) {
 			err = 0;
 			goto cleanup;
 		}

		if (err < 0)
			break;
		if (exiting)
			goto cleanup;
	}
	warn("error polling perf buffer: %d\n", err);

cleanup:
	perf_buffer__free(pb);
	exitsnoop_bpf__destroy(obj);

	return err != 0;
}
