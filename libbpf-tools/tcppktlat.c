// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2023 Wenbo Zhang
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/resource.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "tcppktlat.h"
#include "tcppktlat.skel.h"
#include "compat.h"
#include "trace_helpers.h"

static struct env {
	pid_t pid;
	pid_t tid;
	__u64 min_us;
	__u16 lport;
	__u16 rport;
	bool timestamp;
	bool verbose;
} env = {};

static volatile sig_atomic_t exiting = 0;
static int column_width = 15;

const char *argp_program_version = "tcppktlat 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace latency between TCP received pkt and picked up by userspace thread.\n"
"\n"
"USAGE: tcppktlat [--help] [-T] [-p PID] [-t TID] [-l LPORT] [-r RPORT] [-w] [-v]\n"
"\n"
"EXAMPLES:\n"
"    tcppktlat             # Trace all TCP packet picked up latency\n"
"    tcppktlat -T          # summarize with timestamps\n"
"    tcppktlat -p          # filter for pid\n"
"    tcppktlat -t          # filter for tid\n"
"    tcppktlat -l          # filter for local port\n"
"    tcppktlat -r          # filter for remote port\n"
"    tcppktlat 1000        # filter for latency higher than 1000us";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process PID to trace", 0 },
	{ "tid", 't', "TID", 0, "Thread TID to trace", 0 },
	{ "timestamp", 'T', NULL, 0, "include timestamp on output", 0 },
	{ "lport", 'l', "LPORT", 0, "filter for local port", 0 },
	{ "rport", 'r', "RPORT", 0, "filter for remote port", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "wide", 'w', NULL, 0, "Wide column output (fits IPv6 addresses)", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;
	long long min_us;
	int pid;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			fprintf(stderr, "Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		env.pid = pid;
		break;
	case 't':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			fprintf(stderr, "Invalid TID: %s\n", arg);
			argp_usage(state);
		}
		env.tid = pid;
		break;
	case 'l':
		errno = 0;
		env.lport = strtoul(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid lport: %s\n", arg);
			argp_usage(state);
		}
		env.lport = htons(env.lport);
		break;
	case 'r':
		errno = 0;
		env.rport = strtoul(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid rport: %s\n", arg);
			argp_usage(state);
		}
		env.rport = htons(env.rport);
		break;
	case 'w':
		column_width = 26;
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			fprintf(stderr,
				"Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		min_us = strtoll(arg, NULL, 10);
		if (errno || min_us <= 0) {
			fprintf(stderr, "Invalid delay (in us): %s\n", arg);
			argp_usage(state);
		}
		env.min_us = min_us;
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

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	char saddr[48], daddr[48];
	struct tm *tm;
	char ts[32];
	time_t t;

	if (env.timestamp) {
		time(&t);
		tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		printf("%-8s ", ts);
	}
	inet_ntop(e->family, &e->saddr, saddr, sizeof(saddr));
	inet_ntop(e->family, &e->daddr, daddr, sizeof(daddr));

	printf("%-7d %-7d %-16s %-*s %-5d %-*s %-5d %-.2f\n",
		e->pid, e->tid, e->comm, column_width, saddr, ntohs(e->sport), column_width, daddr,
		ntohs(e->dport), e->delta_us / 1000.0);

	return 0;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
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
	struct bpf_buffer *buf = NULL;
	struct tcppktlat_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = tcppktlat_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	obj->rodata->targ_pid = env.pid;
	obj->rodata->targ_tid = env.tid;
	obj->rodata->targ_sport = env.lport;
	obj->rodata->targ_dport = env.rport;
	obj->rodata->targ_min_us = env.min_us;

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		err = -errno;
		fprintf(stderr, "failed to create ring/perf buffer: %d\n", err);
		goto cleanup;
	}

	if (probe_tp_btf("tcp_probe")) {
		bpf_program__set_autoload(obj->progs.tcp_probe, false);
		bpf_program__set_autoload(obj->progs.tcp_rcv_space_adjust, false);
		bpf_program__set_autoload(obj->progs.tcp_destroy_sock, false);
	} else {
		bpf_program__set_autoload(obj->progs.tcp_probe_btf, false);
		bpf_program__set_autoload(obj->progs.tcp_rcv_space_adjust_btf, false);
		bpf_program__set_autoload(obj->progs.tcp_destroy_sock_btf, false);
	}

	err = tcppktlat_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d, maybe your kernel doesn't support `bpf_get_socket_cookie`\n", err);
		goto cleanup;
	}

	err = tcppktlat_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF object: %d\n", err);
		goto cleanup;
	}

	err = bpf_buffer__open(buf, handle_event, handle_lost_events, NULL);
	if (err) {
		fprintf(stderr, "failed to open ring/perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	if (env.timestamp)
		printf("%-8s ", "TIME(s)");
	printf("%-7s %-7s %-16s %-*s %-5s %-*s %-5s %-s\n",
		"PID", "TID", "COMM", column_width, "LADDR", "LPORT", column_width, "RADDR", "RPORT", "MS");

	while (!exiting) {
		err = bpf_buffer__poll(buf, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling ring/perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}
cleanup:
	bpf_buffer__free(buf);
	tcppktlat_bpf__destroy(obj);

	return err != 0;
}
