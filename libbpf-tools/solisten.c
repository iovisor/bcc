/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * solisten  Trace IPv4 and IPv6 listen syscalls
 *
 * Copyright (c) 2021 Hengqi Chen
 *
 * Based on solisten(8) from BCC by Jean-Tiare Le Bigot
 * 31-May-2021   Hengqi Chen   Created this.
 */
#include <argp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <time.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "solisten.h"
#include "solisten.skel.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES       16
#define PERF_POLL_TIMEOUT_MS    100
#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;

static pid_t target_pid = 0;
static bool emit_timestamp = false;

const char *argp_program_version = "solisten 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace IPv4 and IPv6 listen syscalls.\n"
"\n"
"USAGE: solisten [-h] [-t] [-p PID]\n"
"\n"
"EXAMPLES:\n"
"    solisten           # trace listen syscalls\n"
"    solisten -t        # output with timestamp\n"
"    solisten -p 1216   # only trace PID 1216\n";

static const struct argp_option opts[] = {
	{"pid", 'p', "PID", 0, "Process ID to trace"},
	{"timestamp", 't', NULL, 0, "Include timestamp on output"},
	{NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
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
	case 't':
		emit_timestamp = true;
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
	time_t t;
	struct tm *tm;
	char ts[32], proto[16], addr[48] = {};
	__u16 family = e->proto >> 16;
	__u16 type = (__u16)e->proto;
	const char *prot;

	if (emit_timestamp) {
		time(&t);
		tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		printf("%8s ", ts);
	}

	if (type == SOCK_STREAM)
		prot = "TCP";
	else if (type == SOCK_DGRAM)
		prot = "UDP";
	else
		prot = "UNK";
	if (family == AF_INET)
		snprintf(proto, sizeof(proto), "%sv4", prot);
	else /* family == AF_INET6 */
		snprintf(proto, sizeof(proto), "%sv6", prot);
	inet_ntop(family, e->addr, addr, sizeof(addr));
	printf("%-7d %-16s %-3d %-7d %-5s %-5d %-32s\n",
	       e->pid, e->task, e->ret, e->backlog, proto, e->port, addr);
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
	struct solisten_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	err = bump_memlock_rlimit();
	if (err) {
		warn("failed to increase rlimit: %d\n", err);
		return 1;
	}

	obj = solisten_bpf__open();
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->target_pid = target_pid;

	if (fentry_exists("inet_listen", NULL)) {
		bpf_program__set_autoload(obj->progs.inet_listen_entry, false);
		bpf_program__set_autoload(obj->progs.inet_listen_exit, false);
	} else {
		bpf_program__set_autoload(obj->progs.inet_listen_fexit, false);
	}

	err = solisten_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = solisten_bpf__attach(obj);
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
		warn("can't set signal handler: %s\n", strerror(-errno));
		goto cleanup;
	}

	if (emit_timestamp)
		printf("%-8s ", "TIME(s)");
	printf("%-7s %-16s %-3s %-7s %-5s %-5s %-32s\n",
	       "PID", "COMM", "RET", "BACKLOG", "PROTO", "PORT", "ADDR");

	while (1) {
		if ((err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS)) < 0)
			break;
		if (exiting)
			goto cleanup;
	}
	warn("error polling perf buffer: %d\n", err);

cleanup:
	perf_buffer__free(pb);
	solisten_bpf__destroy(obj);

	return err != 0;
}
