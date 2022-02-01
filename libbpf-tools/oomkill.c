/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * Copyright (c) 2022 The Inspektor Gadget authors
 *
 * Based on oomkill(8) from BCC by Brendan Gregg.
 * 01-February-2022 Francis Laniel created this.
 */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "oomkill.h"
#include "oomkill.skel.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100
#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;
static volatile int proc_loadavg_fd;

const char *argp_program_version = "oomkill 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Monitor when OOM killer is triggered and kills a process.\n"
"\n"
"USAGE: oomkill\n"
"\n";

static void sig_int(int signo)
{
	exiting = 1;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	char time_string[9];
	struct event *event;
	char avgline[64];
	struct tm *tm;
	time_t tloc;

	event = data;

	time(&tloc);
	tm = localtime(&tloc);
	strftime(time_string, sizeof(time_string), "%H:%M:%S", tm);

	if (read(proc_loadavg_fd, avgline, sizeof(avgline)) == -1) {
		perror("Problem reading /proc/loadvg:");

		return;
	}

	printf("%s Triggered by PID %d (\"%s\"), OOM kill of PID %d (\"%s\"), %llu pages, loadavg: %s\n",
		time_string, event->tpid, event->tcomm, event->kpid,
		event->kcomm, event->pages, avgline);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	struct oomkill_bpf *obj;
	struct perf_buffer *pb;
	int ret;
	int err;

	ret = EXIT_SUCCESS;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	proc_loadavg_fd = open("/proc/loadavg", O_RDONLY);
	if (proc_loadavg_fd == -1) {
		perror("Problem opening /proc/loadavg:");

		return EXIT_FAILURE;
	}

	obj = oomkill_bpf__open();
	if (!obj) {
		warn("Failed to open BPF object\n");

		return EXIT_FAILURE;
	}

	err = oomkill_bpf__load(obj);
	if (err) {
		warn("Failed to load BPF object: %d\n", err);

		ret = EXIT_FAILURE;

		goto cleanup;
	}

	err = oomkill_bpf__attach(obj);
	if (err) {
		warn("Failed to attach BPF programs: %d\n", err);

		ret = EXIT_FAILURE;

		goto cleanup;
	}

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		warn("Failed to open perf buffer: %d\n", err);

		ret = EXIT_FAILURE;

		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		perror("Cannot set signal handler:");

		ret = EXIT_FAILURE;

		goto cleanup_everything;
	}

	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && errno != EINTR) {
			perror("Error polling perf buffer:");

			ret = EXIT_FAILURE;

			goto cleanup_everything;
		}

		ret = EXIT_SUCCESS;
	}
cleanup_everything:
	perf_buffer__free(pb);
cleanup:
	close(proc_loadavg_fd);
	oomkill_bpf__destroy(obj);

	return ret;
}
