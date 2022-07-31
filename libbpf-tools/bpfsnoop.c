/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "bpfsnoop.h"
#include "bpfsnoop.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES   64
#define PERF_POLL_TIMEOUT_MS	100
#define MAX_ARGS_KEY 259

static volatile sig_atomic_t exiting = 0;

static struct env {
	bool time;
	bool timestamp;
	bool fails;
	const char *name;
	bool print_uid;
	bool verbose;
} env = {
};

static struct timespec start_time;

const char *argp_program_version = "bpfsnoop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace bpf BPF_PROG_LOAD\n"
"\n"
"USAGE: bpfsnoop [-h] [-T] [-t] [-n NAME] [-v] [-U]\n"
"\n"
"EXAMPLES:\n"
"   ./bpfsnoop           # trace all bpf program loads\n"
"   ./bpfsnoop -T        # include time (HH:MM:SS)\n";

static const struct argp_option opts[] = {
	{ "time", 'T', NULL, 0, "include time column on output (HH:MM:SS)" },
	{ "timestamp", 't', NULL, 0, "include timestamp on output" },
	{ "name", 'n', "NAME", 0, "only print commands matching this name, any arg" },
	{ "print-uid", 'U', NULL, 0, "print UID column" },
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
	case 'T':
		env.time = true;
		break;
	case 't':
		env.timestamp = true;
		break;
	case 'x':
		env.fails = true;
		break;
	case 'n':
		env.name = arg;
		break;
	case 'U':
		env.print_uid = true;
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

static void sig_int(int signo)
{
	exiting = 1;
}

static void time_since_start()
{
	long nsec, sec;
	static struct timespec cur_time;
	double time_diff;

	clock_gettime(CLOCK_MONOTONIC, &cur_time);
	nsec = cur_time.tv_nsec - start_time.tv_nsec;
	sec = cur_time.tv_sec - start_time.tv_sec;
	if (nsec < 0) {
		nsec += NSEC_PER_SEC;
		sec--;
	}
	time_diff = sec + (double)nsec / NSEC_PER_SEC;
	printf("%-8.3f", time_diff);
}


static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;
	time_t t;
	struct tm *tm;
	char ts[32];

	/* TODO: use pcre lib */
	if (env.name && strstr(e->comm, env.name) == NULL)
		return;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	if (env.time) {
		printf("%-8s ", ts);
	}
	if (env.timestamp) {
		time_since_start();
	}

	if (env.print_uid)
		printf("%-6d", e->uid);

	printf("%-16s %-6d %-6d %-16s", e->comm, e->pid, e->ppid, e->prog_name);
	putchar('\n');
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct perf_buffer *pb = NULL;
	struct bpfsnoop_bpf *obj;
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

	obj = bpfsnoop_bpf__open_opts(&open_opts);
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	obj->rodata->debug = env.verbose;

	err = bpfsnoop_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	clock_gettime(CLOCK_MONOTONIC, &start_time);
	err = bpfsnoop_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}
	/* print headers */
	if (env.time) {
		printf("%-9s", "TIME");
	}
	if (env.timestamp) {
		printf("%-8s ", "TIME(s)");
	}
	if (env.print_uid) {
		printf("%-6s ", "UID");
	}

	printf("%-16s %-6s %-6s %-16s\n", "PCOMM", "PID", "PPID", "PROG");

	/* setup event callbacks */
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

	/* main: poll */
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
	bpfsnoop_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
