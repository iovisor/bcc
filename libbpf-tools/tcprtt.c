// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2021 Wenbo Zhang
//
// Based on tcprtt(8) from BCC by zhenwei pi.
// 06-Aug-2021   Wenbo Zhang   Created this.
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <argp.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tcprtt.h"
#include "tcprtt.skel.h"
#include "trace_helpers.h"

static struct env {
	__u16 lport;
	__u16 rport;
	__u32 laddr;
	__u32 raddr;
	__u8 laddr_v6[IPV6_LEN];
	__u8 raddr_v6[IPV6_LEN];
	bool milliseconds;
	time_t duration;
	time_t interval;
	bool timestamp;
	bool laddr_hist;
	bool raddr_hist;
	bool extended;
	bool verbose;
} env = {
	.interval = 99999999,
};

static volatile bool exiting;

const char *argp_program_version = "tcprtt 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Summarize TCP RTT as a histogram.\n"
"\n"
"USAGE: \n"
"\n"
"EXAMPLES:\n"
"    tcprtt            # summarize TCP RTT\n"
"    tcprtt -i 1 -d 10 # print 1 second summaries, 10 times\n"
"    tcprtt -m -T      # summarize in millisecond, and timestamps\n"
"    tcprtt -p         # filter for local port\n"
"    tcprtt -P         # filter for remote port\n"
"    tcprtt -a         # filter for local address\n"
"    tcprtt -A         # filter for remote address\n"
"    tcprtt -b         # show sockets histogram by local address\n"
"    tcprtt -B         # show sockets histogram by remote address\n"
"    tcprtt -e         # show extension summary(average)\n";

static const struct argp_option opts[] = {
	{ "interval", 'i', "INTERVAL", 0, "summary interval, seconds", 0 },
	{ "duration", 'd', "DURATION", 0, "total duration of trace, seconds", 0 },
	{ "timestamp", 'T', NULL, 0, "include timestamp on output", 0 },
	{ "millisecond", 'm', NULL, 0, "millisecond histogram", 0 },
	{ "lport", 'p', "LPORT", 0, "filter for local port", 0 },
	{ "rport", 'P', "RPORT", 0, "filter for remote port", 0 },
	{ "laddr", 'a', "LADDR", 0, "filter for local address", 0 },
	{ "raddr", 'A', "RADDR", 0, "filter for remote address", 0 },
	{ "byladdr", 'b', NULL, 0,
	  "show sockets histogram by local address", 0 },
	{ "byraddr", 'B', NULL, 0,
	  "show sockets histogram by remote address", 0 },
	{ "extension", 'e', NULL, 0, "show extension summary(average)", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct in_addr addr;
	struct in6_addr addr_v6;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'i':
		errno = 0;
		env.interval = strtol(arg, NULL, 10);
		if (errno || env.interval <= 0) {
			fprintf(stderr, "invalid interval: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'd':
		errno = 0;
		env.duration = strtol(arg, NULL, 10);
		if (errno || env.duration <= 0) {
			fprintf(stderr, "invalid duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'm':
		env.milliseconds = true;
		break;
	case 'p':
		errno = 0;
		env.lport = strtoul(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid lport: %s\n", arg);
			argp_usage(state);
		}
		env.lport = htons(env.lport);
		break;
	case 'P':
		errno = 0;
		env.rport = strtoul(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid rport: %s\n", arg);
			argp_usage(state);
		}
		env.rport = htons(env.rport);
		break;
	case 'a':
                if (strchr(arg, ':')) {
                        if (inet_pton(AF_INET6, arg, &addr_v6) < 1) {
                                fprintf(stderr, "invalid local IPv6 address: %s\n", arg);
                                argp_usage(state);
                        }
                        memcpy(env.laddr_v6, &addr_v6, sizeof(env.laddr_v6));
                } else {
                        if (inet_pton(AF_INET, arg, &addr) < 0) {
                                fprintf(stderr, "invalid local address: %s\n", arg);
                                argp_usage(state);
                        }
                        env.laddr = addr.s_addr;
                }
		break;
	case 'A':
                if (strchr(arg, ':')) {
                        if (inet_pton(AF_INET6, arg, &addr_v6) < 1) {
                                fprintf(stderr, "invalid remote address: %s\n", arg);
                                argp_usage(state);
                        }
                        memcpy(env.raddr_v6, &addr_v6, sizeof(env.raddr_v6));
                } else {
                        if (inet_pton(AF_INET, arg, &addr) < 0) {
                                fprintf(stderr, "invalid remote address: %s\n", arg);
                                argp_usage(state);
                        }
                        env.raddr = addr.s_addr;
                }
		break;
	case 'b':
		env.laddr_hist = true;
		break;
	case 'B':
		env.raddr_hist = true;
		break;
	case 'e':
		env.extended = true;
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

static void sig_handler(int sig)
{
	exiting = true;
}

static int print_map(struct bpf_map *map)
{
	const char *units = env.milliseconds ? "msecs" : "usecs";
	struct hist_key *lookup_key = NULL, next_key;
	int err, fd = bpf_map__fd(map);
	struct hist hist;

	while (!bpf_map_get_next_key(fd, lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &hist);
		if (err < 0) {
			fprintf(stderr, "failed to lookup infos: %d\n", err);
			return -1;
		}


		if (env.laddr_hist)
			printf("Local Address = ");
		else if (env.raddr_hist)
			printf("Remote Address = ");
		else
			printf("All Addresses = ****** ");

		if (env.laddr_hist || env.raddr_hist) {
			__u16 family = next_key.family;
			char str[INET6_ADDRSTRLEN];

			if (!inet_ntop(family, next_key.addr, str, sizeof(str))) {
				perror("converting IP to string:");
				return -1;
			}

			printf("%s ", str);
		}

		if (env.extended)
			printf("[AVG %llu]", hist.latency / hist.cnt);
		printf("\n");
		print_log2_hist(hist.slots, MAX_SLOTS, units);
		lookup_key = &next_key;
	}

	lookup_key = NULL;
	while (!bpf_map_get_next_key(fd, lookup_key, &next_key)) {
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0) {
			fprintf(stderr, "failed to cleanup infos: %d\n", err);
			return -1;
		}
		lookup_key = &next_key;
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
	__u8 zero_addr_v6[IPV6_LEN] = {};
	struct tcprtt_bpf *obj;
	__u64 time_end = 0;
	struct tm *tm;
	char ts[32];
	time_t t;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if ((env.laddr || env.raddr)
		&& (memcmp(env.laddr_v6, zero_addr_v6, sizeof(env.laddr_v6)) || memcmp(env.raddr_v6, zero_addr_v6, sizeof(env.raddr_v6)))) {
		fprintf(stderr, "It is not permitted to filter by both IPv4 and IPv6\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	obj = tcprtt_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	obj->rodata->targ_laddr_hist = env.laddr_hist;
	obj->rodata->targ_raddr_hist = env.raddr_hist;
	obj->rodata->targ_show_ext = env.extended;
	obj->rodata->targ_sport = env.lport;
	obj->rodata->targ_dport = env.rport;
	obj->rodata->targ_saddr = env.laddr;
	obj->rodata->targ_daddr = env.raddr;
	memcpy(obj->rodata->targ_saddr_v6, env.laddr_v6, sizeof(obj->rodata->targ_saddr_v6));
	memcpy(obj->rodata->targ_daddr_v6, env.raddr_v6, sizeof(obj->rodata->targ_daddr_v6));
	obj->rodata->targ_ms = env.milliseconds;

	if (fentry_can_attach("tcp_rcv_established", NULL))
		bpf_program__set_autoload(obj->progs.tcp_rcv_kprobe, false);
	else
		bpf_program__set_autoload(obj->progs.tcp_rcv, false);

	err = tcprtt_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = tcprtt_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	printf("Tracing TCP RTT");
	if (env.duration)
		printf(" for %ld secs.\n", env.duration);
	else
		printf("... Hit Ctrl-C to end.\n");

	/* setup duration */
	if (env.duration)
		time_end = get_ktime_ns() + env.duration * NSEC_PER_SEC;

	/* main: poll */
	while (1) {
		sleep(env.interval);
		printf("\n");

		if (env.timestamp) {
			time(&t);
			tm = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);
			printf("%-8s\n", ts);
		}

		err = print_map(obj->maps.hists);
		if (err)
			break;

		if (env.duration && get_ktime_ns() > time_end)
			goto cleanup;

		if (exiting)
			break;
	}

cleanup:
	tcprtt_bpf__destroy(obj);
	return err != 0;
}
