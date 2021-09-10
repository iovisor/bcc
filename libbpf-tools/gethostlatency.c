/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * gethostlatency  Show latency for getaddrinfo/gethostbyname[2] calls.
 *
 * Copyright (c) 2021 Hengqi Chen
 *
 * Based on gethostlatency(8) from BCC by Brendan Gregg.
 * 24-Mar-2021   Hengqi Chen   Created this.
 */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <time.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "gethostlatency.h"
#include "gethostlatency.skel.h"
#include "trace_helpers.h"
#include "uprobe_helpers.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100
#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;
static pid_t target_pid = 0;
static const char *libc_path = NULL;

const char *argp_program_version = "gethostlatency 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Show latency for getaddrinfo/gethostbyname[2] calls.\n"
"\n"
"USAGE: gethostlatency [-h] [-p PID] [-l LIBC]\n"
"\n"
"EXAMPLES:\n"
"    gethostlatency             # time getaddrinfo/gethostbyname[2] calls\n"
"    gethostlatency -p 1216     # only trace PID 1216\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "libc", 'l', "LIBC", 0, "Specify which libc.so to use" },
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
	case 'l':
		libc_path = strdup(arg);
		if (access(libc_path, F_OK)) {
			warn("Invalid libc: %s\n", arg);
			argp_usage(state);
		}
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
	const struct event *e = data;
	struct tm *tm;
	char ts[16];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	printf("%-8s %-7d %-16s %-10.3f %-s\n",
	       ts, e->pid, e->comm, (double)e->time/1000000, e->host);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

static int get_libc_path(char *path)
{
	FILE *f;
	char buf[PATH_MAX] = {};
	char *filename;
	float version;

	if (libc_path) {
		memcpy(path, libc_path, strlen(libc_path));
		return 0;
	}

	f = fopen("/proc/self/maps", "r");
	if (!f)
		return -errno;

	while (fscanf(f, "%*x-%*x %*s %*s %*s %*s %[^\n]\n", buf) != EOF) {
		if (strchr(buf, '/') != buf)
			continue;
		filename = strrchr(buf, '/') + 1;
		if (sscanf(filename, "libc-%f.so", &version) == 1) {
			memcpy(path, buf, strlen(buf));
			fclose(f);
			return 0;
		}
	}

	fclose(f);
	return -1;
}

static int attach_uprobes(struct gethostlatency_bpf *obj)
{
	int err;
	char libc_path[PATH_MAX] = {};
	off_t func_off;

	err = get_libc_path(libc_path);
	if (err) {
		warn("could not find libc.so\n");
		return -1;
	}

	func_off = get_elf_func_offset(libc_path, "getaddrinfo");
	if (func_off < 0) {
		warn("could not find getaddrinfo in %s\n", libc_path);
		return -1;
	}
	obj->links.handle_entry =
		bpf_program__attach_uprobe(obj->progs.handle_entry, false,
					   target_pid ?: -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.handle_entry);
	if (err) {
		warn("failed to attach getaddrinfo: %d\n", err);
		return -1;
	}
	obj->links.handle_return =
		bpf_program__attach_uprobe(obj->progs.handle_return, true,
					   target_pid ?: -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.handle_return);
	if (err) {
		warn("failed to attach getaddrinfo: %d\n", err);
		return -1;
	}

	func_off = get_elf_func_offset(libc_path, "gethostbyname");
	if (func_off < 0) {
		warn("could not find gethostbyname in %s\n", libc_path);
		return -1;
	}
	obj->links.handle_entry =
		bpf_program__attach_uprobe(obj->progs.handle_entry, false,
					   target_pid ?: -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.handle_entry);
	if (err) {
		warn("failed to attach gethostbyname: %d\n", err);
		return -1;
	}
	obj->links.handle_return =
		bpf_program__attach_uprobe(obj->progs.handle_return, true,
					   target_pid ?: -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.handle_return);
	if (err) {
		warn("failed to attach gethostbyname: %d\n", err);
		return -1;
	}

	func_off = get_elf_func_offset(libc_path, "gethostbyname2");
	if (func_off < 0) {
		warn("could not find gethostbyname2 in %s\n", libc_path);
		return -1;
	}
	obj->links.handle_entry =
		bpf_program__attach_uprobe(obj->progs.handle_entry, false,
					   target_pid ?: -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.handle_entry);
	if (err) {
		warn("failed to attach gethostbyname2: %d\n", err);
		return -1;
	}
	obj->links.handle_return =
		bpf_program__attach_uprobe(obj->progs.handle_return, true,
					   target_pid ?: -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.handle_return);
	if (err) {
		warn("failed to attach gethostbyname2: %d\n", err);
		return -1;
	}

	return 0;
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
	struct gethostlatency_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	err = bump_memlock_rlimit();
	if (err) {
		warn("failed to increase rlimit: %d\n", err);
		return 1;
	}

	obj = gethostlatency_bpf__open();
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->target_pid = target_pid;

	err = gethostlatency_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = attach_uprobes(obj);
	if (err)
		goto cleanup;

	pb_opts.sample_cb = handle_event;
	pb_opts.lost_cb = handle_lost_events;
	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			&pb_opts);
	err = libbpf_get_error(pb);
	if (err) {
		warn("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(-errno));
		goto cleanup;
	}

	printf("%-8s %-7s %-16s %-10s %-s\n",
	       "TIME", "PID", "COMM", "LATms", "HOST");

	while (1) {
		if ((err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS)) < 0)
			break;
		if (exiting)
			goto cleanup;
	}
	warn("error polling perf buffer: %d\n", err);

cleanup:
	perf_buffer__free(pb);
	gethostlatency_bpf__destroy(obj);

	return err != 0;
}
