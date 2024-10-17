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
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "gethostlatency.h"
#include "gethostlatency.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "uprobe_helpers.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100
#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;

static pid_t target_pid = 0;
static const char *libc_path = NULL;
static bool verbose = false;

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
	{ "pid", 'p', "PID", 0, "Process ID to trace", 0 },
	{ "libc", 'l', "LIBC", 0, "Specify which libc.so to use", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
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
	struct event e;
	struct tm *tm;
	char ts[16];
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
	printf("%-8s %-7d %-16s %-10.3f %-s\n",
	       ts, e.pid, e.comm, (double)e.time/1000000, e.host);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

static int get_libc_path(char *path)
{
	char proc_path[PATH_MAX + 32] = {};
	char buf[PATH_MAX] = {};
	char *filename;
	float version;
	FILE *f;

	if (libc_path) {
		memcpy(path, libc_path, strlen(libc_path));
		return 0;
	}

	if (target_pid == 0) {
		f = fopen("/proc/self/maps", "r");
	} else {
		snprintf(buf, sizeof(buf), "/proc/%d/maps", target_pid);
		f = fopen(buf, "r");
	}
	if (!f)
		return -errno;

	while (fscanf(f, "%*x-%*x %*s %*s %*s %*s %[^\n]\n", buf) != EOF) {
		if (strchr(buf, '/') != buf)
			continue;
		filename = strrchr(buf, '/') + 1;
		if (sscanf(filename, "libc-%f.so", &version) == 1 ||
		    sscanf(filename, "libc.so.%f", &version) == 1) {
			if (target_pid == 0) {
				memcpy(path, buf, strlen(buf));
			} else {
				snprintf(proc_path, sizeof(proc_path), "/proc/%d/root%s", target_pid, buf);
				memcpy(path, proc_path, strlen(proc_path));
			}
			fclose(f);
			return 0;
		}
	}

	fclose(f);
	return -1;
}

static int attach_uprobes(struct gethostlatency_bpf *obj, struct bpf_link *links[])
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
	links[0] = bpf_program__attach_uprobe(obj->progs.handle_entry, false,
					      target_pid ?: -1, libc_path, func_off);
	if (!links[0]) {
		warn("failed to attach getaddrinfo: %d\n", -errno);
		return -1;
	}
	links[1] = bpf_program__attach_uprobe(obj->progs.handle_return, true,
					      target_pid ?: -1, libc_path, func_off);
	if (!links[1]) {
		warn("failed to attach getaddrinfo: %d\n", -errno);
		return -1;
	}

	func_off = get_elf_func_offset(libc_path, "gethostbyname");
	if (func_off < 0) {
		warn("could not find gethostbyname in %s\n", libc_path);
		return -1;
	}
	links[2] = bpf_program__attach_uprobe(obj->progs.handle_entry, false,
					      target_pid ?: -1, libc_path, func_off);
	if (!links[2]) {
		warn("failed to attach gethostbyname: %d\n", -errno);
		return -1;
	}
	links[3] = bpf_program__attach_uprobe(obj->progs.handle_return, true,
					      target_pid ?: -1, libc_path, func_off);
	if (!links[3]) {
		warn("failed to attach gethostbyname: %d\n", -errno);
		return -1;
	}

	func_off = get_elf_func_offset(libc_path, "gethostbyname2");
	if (func_off < 0) {
		warn("could not find gethostbyname2 in %s\n", libc_path);
		return -1;
	}
	links[4] = bpf_program__attach_uprobe(obj->progs.handle_entry, false,
					      target_pid ?: -1, libc_path, func_off);
	if (!links[4]) {
		warn("failed to attach gethostbyname2: %d\n", -errno);
		return -1;
	}
	links[5] = bpf_program__attach_uprobe(obj->progs.handle_return, true,
					      target_pid ?: -1, libc_path, func_off);
	if (!links[5]) {
		warn("failed to attach gethostbyname2: %d\n", -errno);
		return -1;
	}

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
	struct perf_buffer *pb = NULL;
	struct bpf_link *links[6] = {};
	struct gethostlatency_bpf *obj;
	int i, err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	obj = gethostlatency_bpf__open_opts(&open_opts);
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

	err = attach_uprobes(obj, links);
	if (err)
		goto cleanup;

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		warn("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	printf("%-8s %-7s %-16s %-10s %-s\n",
	       "TIME", "PID", "COMM", "LATms", "HOST");

	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warn("error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	for (i = 0; i < 6; i++)
		bpf_link__destroy(links[i]);
	gethostlatency_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
