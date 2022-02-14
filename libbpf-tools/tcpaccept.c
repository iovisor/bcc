// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

/*
 * tcpaccept	Trace TCP accept.
 *
 * Copyright (c) 2022 Hengqi Chen
 *
 * Based on tcpaccept(8) from BCC by Brendan Gregg.
 * 16-Feb-2022   Hengqi Chen   Created this.
 */
#include <argp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>

#include <bpf/bpf.h>
#include "btf_helpers.h"
#include "tcpaccept.h"
#include "tcpaccept.skel.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100
#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;

static bool emit_timestamp = false;
static pid_t target_pid = -1;
static int target_family = -1;
static char *target_ports = NULL;
static bool verbose = false;

const char *argp_program_version = "tcpaccept 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace TCP accept.\n"
"\n"
"USAGE: tcpaccept [-h] [-t] [-x] [-p PID] [-P ports]\n"
"\n"
"EXAMPLES:\n"
"    tcpaccept                  # trace all TCP accept\n"
"    tcpaccept -t               # include timestamps\n"
"    tcpaccept -4               # trace IPv4 family\n"
"    tcpaccept -6               # trace IPv6 family\n"
"    tcpaccept -p 1215          # only trace PID 1215\n"
"    tcpaccept -P 80,81         # only trace port 80 and 81\n";

static const struct argp_option opts[] = {
	{ "timestamp", 't', NULL, 0, "Include timestamp on output" },
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "ports", 'P', "PORTS", 0, "Comma-separated list of ports to trace." },
	{ "ipv4", '4', NULL, 0, "Trace IPv4 family" },
	{ "ipv6", '6', NULL, 0, "Trace IPv4 family" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long pid, port_num;
	char *port;

	switch (key) {
	case '4':
		target_family = AF_INET;
		break;
	case '6':
		target_family = AF_INET6;
		break;
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			warn("Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		target_pid = pid;
		break;
	case 'P':
		if (!arg) {
			warn("No ports specified\n");
			argp_usage(state);
		}
		target_ports = strdup(arg);
		port = strtok(arg, ",");
		while (port) {
			port_num = strtol(port, NULL, 10);
			if (errno || port_num <= 0 || port_num > 65536) {
				warn("Invalid ports: %s\n", arg);
				argp_usage(state);
			}
			port = strtok(NULL, ",");
		}
		break;
	case 't':
		emit_timestamp = true;
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
	char ts[32], saddr[48], daddr[48];
	struct tm *tm;
	time_t t;

	if (emit_timestamp) {
		time(&t);
		tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		printf("%8s ", ts);
	}
	if (e->family == 4) {
		inet_ntop(AF_INET, &e->saddr, saddr, sizeof(saddr));
		inet_ntop(AF_INET, &e->daddr, daddr, sizeof(daddr));
	} else {
		inet_ntop(AF_INET6, &e->saddr, saddr, sizeof(saddr));
		inet_ntop(AF_INET6, &e->daddr, daddr, sizeof(daddr));
	}
	printf("%-7d %-16s %-2d %-16s %-5d %-16s %-5d\n",
	       e->pid, e->task, e->family, daddr, e->dport, saddr, e->lport);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
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
	struct tcpaccept_bpf *obj;
	int err, port_map_fd;
	short port_num;
	char *port;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		warn("failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	obj = tcpaccept_bpf__open_opts(&open_opts);
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->target_pid = target_pid;
	obj->rodata->target_family = target_family;
	obj->rodata->filter_by_port = target_ports != NULL;

	err = tcpaccept_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	if (target_ports) {
		port_map_fd = bpf_map__fd(obj->maps.ports);
		port = strtok(target_ports, ",");
		while (port) {
			port_num = strtol(port, NULL, 10);
			bpf_map_update_elem(port_map_fd, &port_num, &port_num, BPF_ANY);
			port = strtok(NULL, ",");
		}
	}

	err = tcpaccept_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

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

	if (emit_timestamp)
		printf("%-8s ", "TIME(s)");
	printf("%-7s %-16s %-2s %-16s %-5s %-16s %-5s\n",
	       "PID", "COMM", "IP", "RADDR", "RPORT", "LADDR", "LPORT");

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
	tcpaccept_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
