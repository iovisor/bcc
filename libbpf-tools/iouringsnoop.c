// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024
//
// iouringsnoop - trace io_uring request submission-to-completion latency.
//
// USAGE:
//   iouringsnoop [options]
//
// Kernel requirements:
//   CONFIG_IO_URING=y  (Linux 5.1+)
//   CONFIG_DEBUG_INFO_BTF=y (for CO-RE / tp_btf; falls back to raw_tp)
//   Tracepoints: io_uring:io_uring_submit_req  (Linux 5.17+)
//                io_uring:io_uring_complete     (Linux 5.10+)
//
// Author: see https://github.com/iovisor/bcc

#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "iouringsnoop.h"
#include "iouringsnoop.skel.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100

static volatile sig_atomic_t exiting = 0;

/* ---------- CLI state ------------------------------------------------------ */

static struct env {
	pid_t   pid;          /* -p: filter by PID                   */
	char   *comm;         /* -c: filter by process name          */
	__u64   min_us;       /* -m: minimum latency threshold (µs)  */
	__u64   targ_ctx;     /* -r: filter by ring ctx pointer      */
	bool    errors_only;  /* -e: show only failed requests       */
	bool    timestamp;    /* -T: include wall-clock timestamp    */
	bool    verbose;      /* -v: verbose libbpf output           */
	int     duration;     /* positional: run for N seconds       */
} env = {};

/* ---------- argp ----------------------------------------------------------- */

const char *argp_program_version = "iouringsnoop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";

const char argp_program_doc[] =
"Trace io_uring request submission-to-completion latency.\n"
"\n"
"USAGE: iouringsnoop [--help] [-p PID] [-c COMM] [-m MIN_US]\n"
"                    [-r CTX] [-e] [-T] [-d DURATION]\n"
"\n"
"EXAMPLES:\n"
"    iouringsnoop              # trace all io_uring requests\n"
"    iouringsnoop -p 1234      # trace PID 1234 only\n"
"    iouringsnoop -c fio       # trace process named 'fio'\n"
"    iouringsnoop -m 1000      # show requests > 1000 µs (1 ms)\n"
"    iouringsnoop -e           # show only failed requests (res < 0)\n"
"    iouringsnoop -T           # include timestamp column\n"
"    iouringsnoop 10           # trace for 10 seconds then exit\n";

static const struct argp_option opts[] = {
	{ "pid",      'p', "PID",    0, "Trace this PID only", 0 },
	{ "comm",     'c', "COMM",   0, "Trace this process name only", 0 },
	{ "min-us",   'm', "MIN_US", 0,
	  "Minimum latency to report, in microseconds", 0 },
	{ "ring",     'r', "CTX",    0,
	  "Trace this io_ring_ctx pointer (hex) only", 0 },
	{ "errors",   'e', NULL,     0, "Show only failed requests", 0 },
	{ "timestamp",'T', NULL,     0, "Include timestamp column", 0 },
	{ "verbose",  'v', NULL,     0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

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
		if (errno || env.pid <= 0) {
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'c':
		env.comm = arg;
		break;
	case 'm':
		errno = 0;
		env.min_us = strtoull(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid MIN_US: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'r':
		errno = 0;
		env.targ_ctx = strtoull(arg, NULL, 16);
		if (errno) {
			fprintf(stderr, "invalid ring ctx (hex): %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'e':
		env.errors_only = true;
		break;
	case 'T':
		env.timestamp = true;
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			fprintf(stderr,
				"unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		env.duration = strtol(arg, NULL, 10);
		if (errno || env.duration <= 0) {
			fprintf(stderr, "invalid duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

/* ---------- libbpf / signal helpers --------------------------------------- */

static int libbpf_print_fn(enum libbpf_print_level level,
			    const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

/* ---------- opcode name table --------------------------------------------- */

static const char * const opcode_names[] = {
	[0]  = "NOP",
	[1]  = "READV",
	[2]  = "WRITEV",
	[3]  = "FSYNC",
	[4]  = "READ_FIXED",
	[5]  = "WRITE_FIXED",
	[6]  = "POLL_ADD",
	[7]  = "POLL_REMOVE",
	[8]  = "SYNC_FILE_RANGE",
	[9]  = "SENDMSG",
	[10] = "RECVMSG",
	[11] = "TIMEOUT",
	[12] = "TIMEOUT_REMOVE",
	[13] = "ACCEPT",
	[14] = "ASYNC_CANCEL",
	[15] = "LINK_TIMEOUT",
	[16] = "CONNECT",
	[17] = "FALLOCATE",
	[18] = "OPENAT",
	[19] = "CLOSE",
	[20] = "FILES_UPDATE",
	[21] = "STATX",
	[22] = "READ",
	[23] = "WRITE",
	[24] = "FADVISE",
	[25] = "MADVISE",
	[26] = "SEND",
	[27] = "RECV",
	[28] = "OPENAT2",
	[29] = "EPOLL_CTL",
	[30] = "SPLICE",
	[31] = "PROVIDE_BUFFERS",
	[32] = "REMOVE_BUFFERS",
	[33] = "TEE",
	[34] = "SHUTDOWN",
	[35] = "RENAMEAT",
	[36] = "UNLINKAT",
	[37] = "MKDIRAT",
	[38] = "SYMLINKAT",
	[39] = "LINKAT",
	[40] = "MSG_RING",
	[41] = "FSETXATTR",
	[42] = "SETXATTR",
	[43] = "FGETXATTR",
	[44] = "GETXATTR",
	[45] = "SOCKET",
	[46] = "URING_CMD",
	[47] = "SEND_ZC",
	[48] = "SENDMSG_ZC",
	[49] = "READ_MULTISHOT",
	[50] = "WAITID",
	[51] = "FUTEX_WAIT",
	[52] = "FUTEX_WAKE",
	[53] = "FUTEX_WAITV",
	[54] = "FIXED_FD_INSTALL",
	[55] = "FTRUNCATE",
	[56] = "BIND",
	[57] = "LISTEN",
};

#define OPCODE_MAX ((int)(sizeof(opcode_names) / sizeof(opcode_names[0])))

static const char *opcode_str(__u8 op)
{
	if (op < OPCODE_MAX && opcode_names[op])
		return opcode_names[op];
	return "UNKNOWN";
}

/* ---------- event handler ------------------------------------------------- */

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct event e;
	char ts[32];

	if (data_sz < sizeof(e)) {
		fprintf(stderr, "iouringsnoop: short event (%u bytes)\n",
			data_sz);
		return;
	}
	/* Alignment in perf buffer is not guaranteed; copy first. */
	memcpy(&e, data, sizeof(e));

	if (env.timestamp) {
		str_timestamp("%H:%M:%S", ts, sizeof(ts));
		printf("%-9s ", ts);
	}

	printf("%-16s %-7u %-20s %8llu %6d\n",
	       e.comm,
	       e.pid,
	       opcode_str(e.opcode),
	       (unsigned long long)e.delta_us,
	       e.res);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "iouringsnoop: lost %llu events on CPU #%d\n",
		lost_cnt, cpu);
}

/* ---------- main ---------------------------------------------------------- */

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser  = parse_arg,
		.doc     = argp_program_doc,
	};
	struct perf_buffer       *pb  = NULL;
	struct iouringsnoop_bpf  *obj = NULL;
	__u64 time_end = 0;
	int   err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = iouringsnoop_bpf__open();
	if (!obj) {
		fprintf(stderr, "iouringsnoop: failed to open BPF object\n");
		return 1;
	}

	/* ---- set rodata (filtering) before load ---- */
	obj->rodata->targ_pid    = env.pid;
	obj->rodata->min_us      = env.min_us;
	obj->rodata->targ_ctx    = env.targ_ctx;
	obj->rodata->errors_only = env.errors_only;

	if (env.comm) {
		obj->rodata->filter_comm = true;
		strncpy((char *)obj->rodata->targ_comm, env.comm,
			TASK_COMM_LEN - 1);
	}

	/*
	 * Select BTF vs raw_tp depending on kernel support.
	 * probe_tp_btf() returns true when the kernel exposes the named
	 * tracepoint with full BTF type information.
	 *
	 * io_uring_submit_req tp_btf is available from Linux 5.17.
	 * io_uring_complete   tp_btf is available from Linux 5.10.
	 *
	 * If BTF is present we use tp_btf programs (preferred); otherwise
	 * we fall back to raw_tp programs.
	 */
	if (probe_tp_btf("io_uring_submit_req")) {
		bpf_program__set_autoload(
			obj->progs.io_uring_submit_req_raw, false);
		bpf_program__set_autoload(
			obj->progs.io_uring_complete_raw, false);
	} else {
		bpf_program__set_autoload(
			obj->progs.io_uring_submit_req_btf, false);
		bpf_program__set_autoload(
			obj->progs.io_uring_complete_btf, false);
	}

	err = iouringsnoop_bpf__load(obj);
	if (err) {
		fprintf(stderr, "iouringsnoop: failed to load BPF object: %d\n",
			err);
		goto cleanup;
	}

	/* Verify that io_uring tracepoints are available on this kernel */
	if (!tracepoint_exists("io_uring", "io_uring_submit_req") ||
	    !tracepoint_exists("io_uring", "io_uring_complete")) {
		fprintf(stderr,
			"iouringsnoop: io_uring tracepoints not available.\n"
			"  Requires Linux >= 5.17 with CONFIG_IO_URING=y.\n");
		err = 1;
		goto cleanup;
	}

	err = iouringsnoop_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "iouringsnoop: failed to attach BPF: %d\n",
			err);
		goto cleanup;
	}

	/* ---- print header ---- */
	if (env.timestamp)
		printf("%-9s ", "TIME");
	printf("%-16s %-7s %-20s %8s %6s\n",
	       "COMM", "PID", "OPCODE", "LAT(us)", "RET");

	if (env.duration)
		printf("Tracing io_uring requests for %d seconds...\n",
		       env.duration);
	else
		printf("Tracing io_uring requests... Hit Ctrl-C to end.\n");

	/* ---- set up perf buffer ---- */
	pb = perf_buffer__new(bpf_map__fd(obj->maps.events),
			      PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events,
			      NULL, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "iouringsnoop: failed to open perf buffer: "
			"%d\n", err);
		goto cleanup;
	}

	if (env.duration)
		time_end = get_ktime_ns() + env.duration * NSEC_PER_SEC;

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "iouringsnoop: can't set signal handler: %s\n",
			strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* ---- poll loop ---- */
	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr,
				"iouringsnoop: error polling perf buffer: "
				"%s\n", strerror(-err));
			goto cleanup;
		}
		err = 0;
		if (env.duration && get_ktime_ns() > time_end)
			break;
	}

cleanup:
	perf_buffer__free(pb);
	iouringsnoop_bpf__destroy(obj);
	return err != 0;
}
