// SPDX-License-Identifier: GPL-2.0

/*
 * mysqld_qslower       MySQL server queries slower than a threshold.
 *
 * Copyright (c) 2022 Hengqi Chen
 *
 * Based on mysqld_qslower(8) from BCC by Brendan Gregg.
 * 27-May-2022   Hengqi Chen   Created this.
 */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "mysqld_qslower.h"
#include "mysqld_qslower.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "uprobe_helpers.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100

static volatile sig_atomic_t exiting = 0;

static pid_t target_pid = 0;
static int lat_ms = 1;
static bool verbose = false;

const char *argp_program_version = "mysqld_qslower 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Show MySQL server queries slower than a threshold.\n"
"\n"
"USAGE: mysqld_qslower [-h] [-p PID] [-l LAT]\n"
"\n"
"EXAMPLES:\n"
"    mysqld_qslower -p 1215             # only trace PID 1215\n"
"    mysqld_qslower -p 1215 -l 10       # trace query slower than 10ms\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "lat", 'l', "LAT", 0, "Min latency to trace, in ms (default 1)" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long n;

	switch (key) {
	case 'p':
		errno = 0;
		n = strtol(arg, NULL, 10);
		if (errno || n <= 0) {
			fprintf(stderr, "Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		target_pid = n;
		break;
	case 'l':
		errno = 0;
		n = strtol(arg, NULL, 10);
		if (errno || n < 0) {
			fprintf(stderr, "Invalid LAT: %s\n", arg);
			argp_usage(state);
		}
		lat_ms = n;
		break;
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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-8s %-7d %-8.3f %s\n", ts, e->pid, (double)e->lat_ns / 1000 / 1000, e->query);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

static int attach_usdt(struct mysqld_qslower_bpf *obj)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "/proc/%d/exe", target_pid);

	obj->links.query_start = bpf_program__attach_usdt(obj->progs.query_start, target_pid, path,
							  "mysql", "query__start", NULL);
	if (!obj->links.query_start)
		return -errno;

	obj->links.query_done = bpf_program__attach_usdt(obj->progs.query_done, target_pid, path,
							 "mysql", "query__done", NULL);
	if (!obj->links.query_done)
		return -errno;
	return 0;
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct mysqld_qslower_bpf *obj;
	struct perf_buffer *pb = NULL;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	obj = mysqld_qslower_bpf__open_opts(&open_opts);
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	obj->rodata->lat_ns = lat_ms * 1000 * 1000;

	err = mysqld_qslower_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = attach_usdt(obj);
	if (err)
		goto cleanup;

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

	printf("Tracing MySQL server queries for PID %d slower than %d ms...\n",
	       target_pid, lat_ms);
	printf("%-8s %-7s %-8s %s\n", "TIME(s)", "PID", "MS", "QUERY");

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
	mysqld_qslower_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);
	return err != 0;
}
