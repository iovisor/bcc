// SPDX-License-Identifier: GPL-2.0

/*
 * tcpretrans  Trace IPv4 and IPv6 tcp retransmit events
 *
 * Copyright (c) 2020 Anton Protopopov
 * Copyright (c) 2021 Red Hat, Inc.
 *
 * Based on tcpconnect.c by Anton Protopopov and
 * tcpretrans(8) from BCC by Brendan Gregg
 * 15-Jul-2021   Michael Gugino   Created this.
 */
#include <sys/resource.h>
#include <arpa/inet.h>
#include <argp.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>
#include <bpf/bpf.h>
#include "tcpretrans.h"
#include "tcpretrans.skel.h"
#include "trace_helpers.h"
#include "map_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

const char *argp_program_version = "tcpretrans 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
static const char argp_program_doc[] =
	"\ntcpretrans: Trace TCP retransmits\n"
	"\n"
	"EXAMPLES:\n"
	"    tcpretrans		# display all TCP retransmissions\n"
	"    tcpretrans -c	# count occurred retransmits per flow\n"
	"    tcpretrans -l	# include tail loss probe attempts\n"
	;

static const char *tppath = "/sys/kernel/debug/tracing/events/tcp/tcp_retransmit_skb/id";

static const char *TCPSTATE[] = {
	"",
	"ESTABLISHED",
	"SYN_SENT",
	"SYN_RECV",
	"FIN_WAIT1",
	"FIN_WAIT2",
	"TIME_WAIT",
	"CLOSE",
	"CLOSE_WAIT",
	"LAST_ACK",
	"LISTEN",
	"CLOSING",
	"NEW_SYN_RECV"
};

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
	exiting = true;
}

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "count", 'c', NULL, 0, "Count connects per src ip and dst ip/port" },
	{ "lossprobe", 'l', NULL, 0, "include tail loss probe attempts" },
	{ "kprobe", 'k', NULL, 0, "force kprobe instead of tracepoint" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static struct env {
	bool verbose;
	bool count;
	bool lossprobe;
	bool kprobe;
} env = {};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'c':
		env.count = true;
		break;
	case 'l':
		env.lossprobe = true;
		break;
	case 'k':
		env.kprobe = true;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level,
		const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void print_count_ipv4(int map_fd)
{
	static struct ipv4_flow_key keys[MAX_ENTRIES];
	static struct ipv4_flow_key zero;
	static __u64 counts[MAX_ENTRIES];
	struct in_addr src;
	struct in_addr dst;
	const char *ep_fmt = "[%s]#%d";
	__u32 i, n = MAX_ENTRIES;
	__u32 value_size = sizeof(__u64);
	__u32 key_size = sizeof(keys[0]);
	__u16 dport;
	char s[INET_ADDRSTRLEN];
	char d[INET_ADDRSTRLEN];
	char remote[INET_ADDRSTRLEN + 8];
	char local[INET_ADDRSTRLEN + 8];

	if (dump_hash(map_fd, keys, key_size, counts, value_size, &n, &zero)) {
		warn("dump_hash: %s", strerror(errno));
		return;
	}

	for (i = 0; i < n; i++) {
		src.s_addr = keys[i].saddr;
		dst.s_addr = keys[i].daddr;
		dport = ntohs(keys[i].dport);
		sprintf(local, ep_fmt, inet_ntop(AF_INET, &src, s, sizeof(s)), keys[i].sport);
		sprintf(remote, ep_fmt, inet_ntop(AF_INET, &dst, d, sizeof(d)), dport);
		printf("%-20s <-> %-20s %10llu\n", local, remote, counts[i]);
	}
}

static void print_count_ipv6(int map_fd)
{
	static struct ipv6_flow_key keys[MAX_ENTRIES];
	static struct ipv6_flow_key zero;
	static __u64 counts[MAX_ENTRIES];
	struct in6_addr src;
	struct in6_addr dst;
	__u32 i, n = MAX_ENTRIES;
	__u32 value_size = sizeof(__u64);
	__u32 key_size = sizeof(keys[0]);
	__u16 dport;
	char *ep_fmt = "[%s]#%d";
	char s[INET6_ADDRSTRLEN];
	char d[INET6_ADDRSTRLEN];
	char remote[INET6_ADDRSTRLEN + 8];
	char local[INET6_ADDRSTRLEN + 8];

	if (dump_hash(map_fd, keys, key_size, counts, value_size, &n, &zero)) {
		warn("dump_hash: %s", strerror(errno));
		return;
	}

	for (i = 0; i < n; i++) {
		memcpy(src.s6_addr, keys[i].saddr, sizeof(src.s6_addr));
		memcpy(dst.s6_addr, keys[i].daddr, sizeof(src.s6_addr));
		dport = ntohs(keys[i].dport);
		sprintf(local, ep_fmt, inet_ntop(AF_INET6, &src, s, sizeof(s)), keys[i].sport);
		sprintf(remote, ep_fmt, inet_ntop(AF_INET6, &dst, d, sizeof(d)), dport);
		printf("%-20s <-> %-20s %10llu\n", local, remote, counts[i]);
	}
}

static void print_count(int map_fd_ipv4, int map_fd_ipv6)
{
	while (!exiting)
		pause();

	printf("\n%-25s %-25s %-10s\n", "LADDR:LPORT", "RADDR:RPORT", "RETRANSMITS");
	print_count_ipv4(map_fd_ipv4);
	print_count_ipv6(map_fd_ipv6);
}

static void print_events_header()
{
	printf("%-8s %-6s %-2s %-20s %1s> %-20s %-4s\n", "TIME", "PID", "IP",
		"LADDR:LPORT", "T", "RADDR:RPORT", "STATE");
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;
	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];
	char remote[INET6_ADDRSTRLEN + 6];
	char local[INET6_ADDRSTRLEN + 6];
	union {
		struct in_addr  x4;
		struct in6_addr x6;
	} s, d;
	__u16 dport;

	if (e->af == AF_INET) {
		memcpy(&s.x4.s_addr, e->saddr, sizeof(s.x4.s_addr));
		memcpy(&d.x4.s_addr, e->daddr, sizeof(d.x4.s_addr));
	} else if (e->af == AF_INET6) {
		memcpy(&s.x6.s6_addr, e->saddr, sizeof(s.x6.s6_addr));
		memcpy(&d.x6.s6_addr, e->daddr, sizeof(d.x6.s6_addr));
	} else {
		warn("broken event: event->af=%d", e->af);
		return;
	}

	time(&t);
	tm = localtime(&t);
	dport = ntohs(e->dport);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	sprintf(local, "%s:%d", inet_ntop(e->af, &s, src, sizeof(src)), e->sport);
	sprintf(remote, "%s:%d", inet_ntop(e->af, &d, dst, sizeof(dst)), dport);

	printf("%-8s %-6d %-2d %-20s %1s> %-20s %s\n",
		   ts,
		   e->pid,
		   e->af == AF_INET ? 4 : 6,
		   local,
		   e->type == RETRANSMIT ? "R" : "L",
		   remote,
		   TCPSTATE[e->state]);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warn("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static void print_events(int perf_map_fd)
{
	struct perf_buffer_opts pb_opts = {
		.sample_cb = handle_event,
		.lost_cb = handle_lost_events,
	};
	struct perf_buffer *pb = NULL;
	int err;

	pb = perf_buffer__new(perf_map_fd, 128, &pb_opts);
	err = libbpf_get_error(pb);
	if (err) {
		pb = NULL;
		warn("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	print_events_header();
	while (!exiting) {
		err = perf_buffer__poll(pb, 100);
		if (err < 0 && errno != EINTR) {
			warn("Error polling perf buffer: %d\n", err);
			goto cleanup;
		}
	}

cleanup:
	perf_buffer__free(pb);
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
		.args_doc = NULL,
	};

	struct tcpretrans_bpf *obj;
	int err, tpmissing;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	err = bump_memlock_rlimit();
	if (err) {
		warn("failed to increase rlimit: %s\n", strerror(errno));
		return 1;
	}

	obj = tcpretrans_bpf__open();
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	/*
	 * bpf will load non-existant trace points but fail at the attach stage, so
	 * check to ensure our tp exists before we load it.
	 */
	tpmissing = access(tppath, F_OK);

	if (tpmissing || env.kprobe) {
		if (!env.kprobe)
			warn("tcp_retransmit_skb tracepoint not found, falling back to kprobe");
		err = bpf_program__set_autoload(obj->progs.tp_tcp_retransmit_skb, false);
		if (err) {
			warn("Unable to set autoload for tp_tcp_retransmit_skb\n");
			return err;
		}
	} else {
		err = bpf_program__set_autoload(obj->progs.tcp_retransmit_skb, false);
		if (err) {
			warn("Unable to set autoload for tcp_retransmit_skb\n");
			return err;
		}
	}

	if (!env.lossprobe) {
		err = bpf_program__set_autoload(obj->progs.tcp_send_loss_probe, false);
		if (err) {
			warn("Unable to set autoload for tcp_send_loss_probe\n");
			return err;
		}
	}

	if (env.count)
		obj->rodata->do_count = true;

	err = tcpretrans_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = tcpretrans_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF programs: %s\n", strerror(-err));
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR || signal(SIGTERM, sig_handler) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}
	printf("Tracing retransmits ... Hit Ctrl-C to end\n");
	if (env.count) {
		print_count(bpf_map__fd(obj->maps.ipv4_count),
			bpf_map__fd(obj->maps.ipv6_count));
	} else {
		print_events(bpf_map__fd(obj->maps.events));
	}

cleanup:
	tcpretrans_bpf__destroy(obj);

	return err != 0;
}
