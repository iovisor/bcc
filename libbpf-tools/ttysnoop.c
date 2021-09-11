/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * ttysnoop     Watch live output from a tty or pts device.
 *
 * Copyright (c) 2021 Hengqi Chen
 *
 * Based on ttysnoop(8) from BCC by Brendan Gregg
 * 11-Sep-2021   Hengqi Chen   Created this.
 */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "ttysnoop.h"
#include "ttysnoop.skel.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	64
#define PERF_POLL_TIMEOUT_MS	100
#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;

static bool clear_screen = true;
static __u64 pts = -1;
static int read_bytes = 256;
static int read_count = 16;

const char *argp_program_version = "ttysnoop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Watch live output from a tty or pts device.\n"
"\n"
"USAGE: ttysnoop [-h] [-C] [-s SIZE] [-c COUNT] DEVICE\n"
"\n"
"EXAMPLES:\n"
"    ttysnoop /dev/pts/2    # snoop output from /dev/pts/2\n"
"    ttysnoop 2             # snoop output from /dev/pts/2 (shortcut)\n"
"    ttysnoop /dev/console  # snoop output from the system console\n"
"    ttysnoop /dev/tty0     # snoop output from /dev/tty0\n"
"    ttysnoop 2 -s 1024     # snoop output from /dev/pts/2 with data size 1024\n"
"    ttysnoop 2 -c 2        # snoop output from /dev/pts/2 with 2 checks for 256"
" bytes of data in buffer (potentially retrieving 512 bytes)\n";

static const struct argp_option opts[] = {
	{ "noclear", 'C', NULL, 0, "Don't clear the screen" },
	{ "datasize", 's', "SIZE", 0, "size of the transmitting buffer (default 256)" },
	{ "datacount", 'c', "COUNT", 0, "number of times we check for 'data-size' data (default 16)" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct stat statbuf;
	char path[PATH_MAX];
	long num;

	switch (key) {
	case 'C':
		clear_screen = false;
		break;
	case 's':
		errno = 0;
		num = strtol(arg, NULL, 10);
		if (errno || num <= 0) {
			warn("Invalid data size: %s\n", arg);
			argp_usage(state);
		}
		read_bytes = num;
		break;
	case 'c':
		errno = 0;
		num = strtol(arg, NULL, 10);
		if (errno || num <= 0) {
			warn("Invalid data count: %s\n", arg);
			argp_usage(state);
		}
		read_count = num;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case ARGP_KEY_ARG:
		if (pts != -1) {
			warn("Too many devices\n");
			argp_usage(state);
		}
		if (arg[0] != '/')
			snprintf(path, sizeof(path), "/dev/pts/%s", arg);
		else
			strcpy(path, arg);
		if (stat(path, &statbuf) < 0) {
			warn("Wrong device\n");
			argp_usage(state);
		}
		pts = statbuf.st_ino;
		break;
	case ARGP_KEY_END:
		if (pts == -1) {
			warn("Device required\n");
			argp_usage(state);
		}
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

	printf("%s", e->buf);
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
	struct ttysnoop_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	err = bump_memlock_rlimit();
	if (err) {
		warn("failed to increase rlimit: %d\n", err);
		return 1;
	}

	obj = ttysnoop_bpf__open();
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->pts = pts;
	obj->rodata->read_bytes = read_bytes >= BUF_SIZE ? (BUF_SIZE - 1) : read_bytes;
	obj->rodata->read_count = read_count;

	if (fentry_exists("tty_write", NULL))
		bpf_program__set_autoload(obj->progs.tty_write_entry, false);
	else
		bpf_program__set_autoload(obj->progs.tty_write_fentry, false);

	err = ttysnoop_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = ttysnoop_bpf__attach(obj);
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
		warn("can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	if (clear_screen) {
		err = system("clear");
		if (err)
			goto cleanup;
	}

	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && errno != EINTR) {
			warn("error polling perf buffer: %s\n", strerror(errno));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	ttysnoop_bpf__destroy(obj);

	return err != 0;
}
