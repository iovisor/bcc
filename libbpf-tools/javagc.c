/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * Copyright (c) 2022 Chen Tao
 * Based on ugc from BCC by Sasha Goldshtein
 * Create: Wed Jun 29 16:00:19 2022
 */
#include <stdio.h>
#include <ctype.h>
#include <argp.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include "javagc.skel.h"
#include "javagc.h"

#define BINARY_PATH_SIZE (256)
#define PERF_BUFFER_PAGES (32)
#define PERF_POLL_TIMEOUT_MS (200)

static struct env {
	pid_t pid;
	int time;
	bool exiting;
	bool verbose;
} env = {
	.pid = -1,
	.time = 1000,
	.exiting = false,
	.verbose = false,
};

const char *argp_program_version = "javagc 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";

const char argp_program_doc[] =
"Monitor javagc time cost.\n"
"\n"
"USAGE: javagc [--help] [-p PID] [-t GC time]\n"
"\n"
"EXAMPLES:\n"
"javagc -p 185         # trace PID 185 only\n"
"javagc -p 185 -t 100  # trace PID 185 java gc time beyond 100us\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Trace this PID only", 0 },
	{ "time", 't', "TIME", 0, "Java gc time", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	int err = 0;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'p':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno) {
			err = errno;
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 't':
		errno = 0;
		env.time = strtol(arg, NULL, 10);
		if (errno) {
			err = errno;
			fprintf(stderr, "invalid time: %s\n", arg);
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return err;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && ! env.verbose)
		return 0;

	return vfprintf(stderr, format, args);
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct data_t *e = (struct data_t *)data;
	struct tm *tm = NULL;
	char ts[16];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	printf("%-8s %-7d %-7d %-7lld\n", ts, e->cpu, e->pid, e->ts/1000);
}

static void handle_lost_events(void *ctx, int cpu, __u64 data_sz)
{
	printf("lost data\n");
}

static void sig_handler(int sig)
{
	env.exiting = true;
}

static int get_jvmso_path(char *path)
{
	char mode[16], line[128], buf[64];
	size_t seg_start, seg_end, seg_off;
	FILE *f;
	int i = 0;
	bool found = false;

	if (env.pid == -1) {
		fprintf(stderr, "not specify pid, see --pid.\n");
		return -1;
	}

	sprintf(buf, "/proc/%d/maps", env.pid);
	f = fopen(buf, "r");
	if (!f) {
		fprintf(stderr, "open %s failed: %m\n", buf);
		return -1;
	}

	while (fscanf(f, "%zx-%zx %s %zx %*s %*d%[^\n]\n",
			&seg_start, &seg_end, mode, &seg_off, line) == 5) {
		i = 0;
		while (isblank(line[i]))
			i++;
		if (strstr(line + i, "libjvm.so")) {
			found = true;
			strcpy(path, line + i);
			break;
		}
	}

	fclose(f);

	if (!found) {
		fprintf(stderr, "Not found libjvm.so.\n");
		return -ENOENT;
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
	char binary_path[BINARY_PATH_SIZE] = {0};
	struct javagc_bpf *skel = NULL;
	int err;
	struct perf_buffer *pb = NULL;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/*
	* libbpf will auto load the so if it in /usr/lib64 /usr/lib etc,
	* but the jvmso not there.
	*/
	err = get_jvmso_path(binary_path);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	skel = javagc_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}
	skel->bss->time = env.time * 1000;

	err = javagc_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	skel->links.handle_mem_pool_gc_start = bpf_program__attach_usdt(skel->progs.handle_gc_start, env.pid,
									binary_path, "hotspot", "mem__pool__gc__begin", NULL);
	if (!skel->links.handle_mem_pool_gc_start) {
		err = errno;
		fprintf(stderr, "attach usdt mem__pool__gc__begin failed: %s\n", strerror(err));
		goto cleanup;
	}

	skel->links.handle_mem_pool_gc_end = bpf_program__attach_usdt(skel->progs.handle_gc_end, env.pid,
								binary_path, "hotspot", "mem__pool__gc__end", NULL);
	if (!skel->links.handle_mem_pool_gc_end) {
		err = errno;
		fprintf(stderr, "attach usdt mem__pool__gc__end failed: %s\n", strerror(err));
		goto cleanup;
	}

	skel->links.handle_gc_start = bpf_program__attach_usdt(skel->progs.handle_gc_start, env.pid,
									binary_path, "hotspot", "gc__begin", NULL);
	if (!skel->links.handle_gc_start) {
		err = errno;
		fprintf(stderr, "attach usdt gc__begin failed: %s\n", strerror(err));
		goto cleanup;
	}

	skel->links.handle_gc_end = bpf_program__attach_usdt(skel->progs.handle_gc_end, env.pid,
				binary_path, "hotspot", "gc__end", NULL);
	if (!skel->links.handle_gc_end) {
		err = errno;
		fprintf(stderr, "attach usdt gc__end failed: %s\n", strerror(err));
		goto cleanup;
	}

	signal(SIGINT, sig_handler);
	printf("Tracing javagc time... Hit Ctrl-C to end.\n");
	printf("%-8s %-7s %-7s %-7s\n",
	       "TIME", "CPU", "PID", "GC TIME");

	pb = perf_buffer__new(bpf_map__fd(skel->maps.perf_map), PERF_BUFFER_PAGES,
			handle_event, handle_lost_events, NULL, NULL);
	while (!env.exiting) {
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
	javagc_bpf__destroy(skel);

	return err != 0;
}
