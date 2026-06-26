// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2023 Wenbo Zhang
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
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
#include "map_helpers.h"

#define DEFAULT_INTERVAL 99999999 /* Only print on Ctrl-C by default */

static struct env {
	pid_t pid;
	pid_t tid;
	__u64 min_us;
	__u16 lport;
	__u16 rport;
	bool timestamp;
	bool verbose;
	bool histogram;
	bool per_thread;
	__u32 interval;
	int times;
} env = {
	.interval = DEFAULT_INTERVAL,
	.times = DEFAULT_INTERVAL,
};

static volatile sig_atomic_t exiting = 0;
static int column_width = 15;

const char *argp_program_version = "tcppktlat 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
	"Trace latency between TCP received pkt and picked up by userspace thread.\n"
	"\n"
	"USAGE: tcppktlat [--help] [-T] [-H] [-L] [-p PID] [-t TID] [-l LPORT] [-r RPORT] [-w] [-v]\n"
	"                [min_us | interval [count]]\n"
	"\n"
	"Positional args:\n"
	"    min_us             Minimum latency filter (microseconds) when not using -H\n"
	"    interval [count]   With -H, interval is the histogram print interval (seconds)\n"
	"                       and count limits how many times histograms are printed\n"
	"\n"
	"EXAMPLES:\n"
	"    tcppktlat             # Trace all TCP packet picked up latency\n"
	"    tcppktlat -T          # summarize with timestamps\n"
	"    tcppktlat -H          # show latency histogram\n"
	"    tcppktlat -H 5        # show latency histogram, print every 5 seconds\n"
	"    tcppktlat -H 1 5      # show latency histogram, print every 1 second, 5 times\n"
	"    tcppktlat -H -L       # show latency histogram per thread\n"
	"    tcppktlat -p          # filter for pid\n"
	"    tcppktlat -t          # filter for tid\n"
	"    tcppktlat -l          # filter for local port\n"
	"    tcppktlat -r          # filter for remote port\n"
	"    tcppktlat 1000        # filter for latency higher than 1000us";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process PID to trace", 0 },
	{ "tid", 't', "TID", 0, "Thread TID to trace", 0 },
	{ "timestamp", 'T', NULL, 0, "include timestamp on output", 0 },
	{ "histogram", 'H', NULL, 0,
	  "Show latency histogram. Positional args become interval/count", 0 },
	{ "threads", 'L', NULL, 0, "Print a histogram per thread ID", 0 },
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
	case 'H':
		env.histogram = true;
		/* Interval/count, if any, are parsed from positional args */
		break;
	case 'L':
		env.per_thread = true;
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
		if (env.histogram) {
			/* For histogram mode, positional args are interval and count */
			errno = 0;
			if (pos_args == 0) {
				env.interval = strtoul(arg, NULL, 10);
				if (errno || env.interval == 0) {
					fprintf(stderr,
						"Invalid interval: %s\n", arg);
					argp_usage(state);
				}
			} else if (pos_args == 1) {
				env.times = strtol(arg, NULL, 10);
				if (errno || env.times <= 0) {
					fprintf(stderr, "Invalid count: %s\n",
						arg);
					argp_usage(state);
				}
			} else {
				fprintf(stderr,
					"Unrecognized positional argument: %s\n",
					arg);
				argp_usage(state);
			}
			pos_args++;
		} else {
			/* For non-histogram mode, positional arg is min_us */
			if (pos_args++) {
				fprintf(stderr,
					"Unrecognized positional argument: %s\n",
					arg);
				argp_usage(state);
			}
			errno = 0;
			min_us = strtoll(arg, NULL, 10);
			if (errno || min_us <= 0) {
				fprintf(stderr, "Invalid delay (in us): %s\n",
					arg);
				argp_usage(state);
			}
			env.min_us = min_us;
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
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
	char ts[32];

	if (env.timestamp) {
		str_timestamp("%H:%M:%S", ts, sizeof(ts));
		printf("%-8s ", ts);
	}
	inet_ntop(e->family, &e->saddr, saddr, sizeof(saddr));
	inet_ntop(e->family, &e->daddr, daddr, sizeof(daddr));

	printf("%-7d %-7d %-16s %-*s %-5d %-*s %-5d %-.2f\n", e->pid, e->tid,
	       e->comm, column_width, saddr, ntohs(e->sport), column_width,
	       daddr, ntohs(e->dport), e->delta_us / 1000.0);

	return 0;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

static int calc_hist_stats(__u32 *slots, int slots_size, double *min,
			   double *max, double *avg, double *mean, double *p95,
			   double *p99)
{
	unsigned long long total = 0;
	unsigned long long sum = 0;
	int i, min_slot = -1, max_slot = -1;
	unsigned long long low, high, mid;

	/* Calculate total count and find min/max slots */
	for (i = 0; i < slots_size; i++) {
		if (slots[i] > 0) {
			if (min_slot < 0)
				min_slot = i;
			max_slot = i;
			total += slots[i];
		}
	}

	if (min_slot < 0) {
		/* No data available */
		return -1;
	}

	/* Calculate min (low bound of first slot) */
	low = (1ULL << (min_slot + 1)) >> 1;
	if (low == (1ULL << (min_slot + 1)) - 1)
		low -= 1;
	*min = low;

	/* Calculate max (high bound of last slot) */
	high = (1ULL << (max_slot + 1)) - 1;
	*max = high;

	/* Calculate avg (average) */
	for (i = 0; i < slots_size; i++) {
		if (slots[i] > 0) {
			low = (1ULL << (i + 1)) >> 1;
			high = (1ULL << (i + 1)) - 1;
			if (low == high)
				low -= 1;
			/* Use midpoint of the range as representative value */
			mid = (low + high) / 2;
			sum += mid * slots[i];
		}
	}
	*avg = total > 0 ? (double)sum / total : 0;

	/* Calculate mean (p50, median) and percentiles */
	unsigned long long p50_count = total * 50 / 100;
	unsigned long long p95_count = total * 95 / 100;
	unsigned long long p99_count = total * 99 / 100;
	unsigned long long cumsum = 0;

	*mean = *p95 = *p99 = 0;
	for (i = 0; i < slots_size; i++) {
		if (slots[i] > 0) {
			cumsum += slots[i];
			low = (1ULL << (i + 1)) >> 1;
			high = (1ULL << (i + 1)) - 1;
			if (low == high)
				low -= 1;

			if (*mean == 0 && cumsum >= p50_count) {
				*mean = high; /* Use high bound for median */
			}
			if (*p95 == 0 && cumsum >= p95_count) {
				*p95 = high; /* Use high bound for percentile */
			}
			if (*p99 == 0 && cumsum >= p99_count) {
				*p99 = high; /* Use high bound for percentile */
			}
		}
	}
	return 0;
}

static int print_hist(struct bpf_map *hists_map)
{
	const char *units = "usecs";
	int err, fd = bpf_map__fd(hists_map);
	__u32 keys[MAX_ENTRIES];
	struct hist values[MAX_ENTRIES];
	__u32 count = MAX_ENTRIES;
	__u32 invalid_key = -1;
	double min, max, avg, mean, p95, p99;
	char ts[32];
	static time_t start_time = 0;
	time_t now = time(NULL);
	int i;

	/* Print timestamp header for interval-based output */
	if (env.interval < DEFAULT_INTERVAL) {
		if (start_time == 0) {
			start_time = now;
		}
		str_timestamp("%Y-%m-%d %H:%M:%S", ts, sizeof(ts));
		printf("[%s] (elapsed: %ld seconds)\n", ts, now - start_time);
	}

	/* Use atomic lookup_and_delete to avoid race conditions */
	err = dump_hash(fd, keys, sizeof(__u32), values, sizeof(struct hist),
			&count, &invalid_key, true);
	if (err) {
		fprintf(stderr, "failed to dump hist map: %d\n", err);
		return -1;
	}

	/* Print all histograms */
	for (i = 0; i < count; i++) {
		if (env.timestamp) {
			str_timestamp("%H:%M:%S", ts, sizeof(ts));
			printf("%-8s ", ts);
		}

		if (env.per_thread)
			printf("\ntid = %d %s\n", keys[i], values[i].comm);
		else
			printf("\npid = %d %s\n", keys[i], values[i].comm);
		print_log2_hist(values[i].slots, MAX_SLOTS, units);

		/* Calculate and print statistics */
		err = calc_hist_stats(values[i].slots, MAX_SLOTS, &min, &max,
				      &avg, &mean, &p95, &p99);
		if (err == 0) {
			printf("    min = %.2f %s, max = %.2f %s, mean = %.2f %s, "
			       "avg = %.2f %s, p95 = %.2f %s, p99 = %.2f %s\n",
			       min, units, max, units, mean, units, avg, units,
			       p95, units, p99, units);
		}
	}

	return 0;
}

static void run_histogram_mode(struct tcppktlat_bpf *obj)
{
	bool is_interval_mode = (env.interval < DEFAULT_INTERVAL);

	while (!exiting && env.times > 0) {
		if (is_interval_mode) {
			sleep(env.interval);
			if (!exiting) {
				printf("\n");
				print_hist(obj->maps.hists);
				env.times--;
			}
		} else {
			/* Default: wait for Ctrl-C */
			sleep(1);
		}
	}

	/* Print histogram on exit only for default mode (no interval specified) */
	if (!is_interval_mode) {
		printf("\n");
		print_hist(obj->maps.hists);
	}
}

static int run_event_mode(struct bpf_buffer *buf)
{
	int err = 0;

	while (!exiting) {
		err = bpf_buffer__poll(buf, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling ring/perf buffer: %s\n",
				strerror(-err));
			return err;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

	return err;
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

	if (env.per_thread && !env.histogram) {
		fprintf(stderr,
			"Error: -L option requires -H (histogram mode)\n");
		return 1;
	}

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
	obj->rodata->targ_hist = env.histogram;
	obj->rodata->targ_per_thread = env.per_thread;

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		err = -errno;
		fprintf(stderr, "failed to create ring/perf buffer: %d\n", err);
		goto cleanup;
	}

	if (probe_tp_btf("tcp_probe")) {
		bpf_program__set_autoload(obj->progs.tcp_probe, false);
		bpf_program__set_autoload(obj->progs.tcp_rcv_space_adjust,
					  false);
		bpf_program__set_autoload(obj->progs.tcp_destroy_sock, false);
	} else {
		bpf_program__set_autoload(obj->progs.tcp_probe_btf, false);
		bpf_program__set_autoload(obj->progs.tcp_rcv_space_adjust_btf,
					  false);
		bpf_program__set_autoload(obj->progs.tcp_destroy_sock_btf,
					  false);
	}

	err = tcppktlat_bpf__load(obj);
	if (err) {
		fprintf(stderr,
			"failed to load BPF object: %d, maybe your kernel doesn't support `bpf_get_socket_cookie`\n",
			err);
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
		fprintf(stderr, "can't set signal handler: %s\n",
			strerror(errno));
		err = 1;
		goto cleanup;
	}

	if (env.histogram) {
		printf("Summarize TCP packet latency as a histogram. Hit Ctrl-C to end.\n");
	} else {
		if (env.timestamp)
			printf("%-8s ", "TIME(s)");
		printf("%-7s %-7s %-16s %-*s %-5s %-*s %-5s %-s\n", "PID",
		       "TID", "COMM", column_width, "LADDR", "LPORT",
		       column_width, "RADDR", "RPORT", "MS");
	}

	if (env.histogram) {
		run_histogram_mode(obj);
	} else {
		err = run_event_mode(buf);
		if (err)
			goto cleanup;
	}
cleanup:
	bpf_buffer__free(buf);
	tcppktlat_bpf__destroy(obj);

	return err != 0;
}
