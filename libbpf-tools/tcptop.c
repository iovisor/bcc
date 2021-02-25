// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Daniel Castro
 * 
 * Based on tcptop from BCC by Brendan Gregg
 * 
 * 22-Feb-2021   Daniel Castro   Converted this from BCC */

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "tcptop.h"
#include "tcptop.skel.h"

#include <arpa/inet.h>

#define warn(...) fprintf(stderr, __VA_ARGS__)

const char *argp_program_version = "tcptop 0.1";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
	"\ntcptop: Summarize TCP send/recv throughput by host.\n"
	"\n"
	"EXAMPLES:\n"
    "	 ./tcptop           # trace TCP send/recv by host\n"
    "	 ./tcptop -t        # include timestamps\n"
    "	 ./tcptop -p 181    # only trace PID 181\n"
	;

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "pid", 'p', "PID", 0, "Process PID to trace" },
	{ "timestamp", 't', NULL, 0, "Include timestamp on output"},
	{},
};

static struct env {
	bool verbose;
	pid_t pid;
	bool print_timestamp;
} env;

static int get_int(const char *arg, int *ret, int min, int max)
{
	char *end;
	long val;

	errno = 0;
	val = strtol(arg, &end, 10);
	if (errno) {
		warn("strtol: %s: %s\n", arg, strerror(errno));
		return -1;
	} else if (end == arg || val < min || val > max) {
		return -1;
	}
	if (ret)
		*ret = val;
	return 0;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	int err;
	//int npids;

	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'p':
		err = get_int(arg, &env.pid, 1, INT_MAX);
		if (err) {
			warn("invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 't':
		env.print_timestamp = true;
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static void print_events_header()
{
	if (env.print_timestamp)
		printf("%-8s ", "TIME");
	printf("%-6s %-16s %-4s %-21s %-21s %-5s %-2s\n",
		   "PID", "COMM", "TYPE", "S_ADDR", "D_ADDR", "MSG_KB", "AF");
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;

	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];
	union {
		struct in_addr  x4;
		struct in6_addr x6;
	} s, d;

	if(env.print_timestamp){
		struct tm *tm;
		char ts[32];
		time_t t;

		time(&t);
		tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		printf("%-8s ", ts);
	}

	if (e->family == AF_INET) {
		s.x4.s_addr = e->saddr_v4;
		d.x4.s_addr = e->daddr_v4;
	} else if (e->family == AF_INET6) {
		memcpy(&s.x6.s6_addr, &e->saddr_v6, sizeof(s.x6.s6_addr));
		memcpy(&d.x6.s6_addr, &e->daddr_v6, sizeof(d.x6.s6_addr));
	} else {
		warn("broken event: e->family=%d", e->family);
		return 0;
	}

	int size = (int)e->send_size;
	
	char s_addr[80];
	char sport[10];
	strcpy(s_addr, inet_ntop(e->family, &s, src, sizeof(src)));
	strcat(s_addr, ":");
	sprintf(sport, "%u", ntohs(e->sport));
	strcat(s_addr, sport);

	char d_addr[80];
	char dport[10];
	strcpy(d_addr, inet_ntop(e->family, &d, dst, sizeof(dst)));
	strcat(d_addr, ":");
	sprintf(dport, "%u", ntohs(e->dport));
	strcat(d_addr, dport);

	printf("%-6d %-16s %-4s %-21s %-21s %-6d %-2d\n",
	 	   e->pid, e->comm, e->is_send ? "SND":"RCV",
	       s_addr, d_addr, size, e->family);

	return 0;
}

static void print_events(int ring_map_fd)
{
	struct ring_buffer *rb = NULL;
	int err;

	/* Set up ring buffer polling */
	rb = ring_buffer__new(ring_map_fd, handle_event, NULL, NULL);
	if (!rb) {
		rb = NULL;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Process events */
	print_events_header();
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			goto cleanup;
		}
		if (err < 0) {
			warn("Error polling ring buffer: %d\n", err);
			goto cleanup;
		}
	}

cleanup:
	ring_buffer__free(rb);
}

int main(int argc, char **argv)
{
	struct tcptop_bpf *skel;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to create BPF maps */
	bump_memlock_rlimit();

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = tcptop_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Parameterize BPF code with minimum duration parameter */
	skel->rodata->filter_pid = env.pid;

	/* Load & verify BPF programs */
	err = tcptop_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = tcptop_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
	
	print_events(bpf_map__fd(skel->maps.rb));


cleanup:
	/* Clean up */
	tcptop_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
