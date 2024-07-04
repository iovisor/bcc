// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Anton Protopopov
//
// Based on tcpconnect(8) from BCC by Brendan Gregg
#include <sys/resource.h>
#include <arpa/inet.h>
#include <argp.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>
#include <bpf/bpf.h>
#include "tcpconnect.h"
#include "tcpconnect.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "map_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;

const char *argp_program_version = "tcpconnect 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
static const char argp_program_doc[] =
	"\ntcpconnect: Count/Trace active tcp connections\n"
	"\n"
	"EXAMPLES:\n"
	"    tcpconnect             # trace all TCP connect()s\n"
	"    tcpconnect -t          # include timestamps\n"
	"    tcpconnect -p 181      # only trace PID 181\n"
	"    tcpconnect -P 80       # only trace port 80\n"
	"    tcpconnect -P 80,81    # only trace port 80 and 81\n"
	"    tcpconnect -U          # include UID\n"
	"    tcpconnect -u 1000     # only trace UID 1000\n"
	"    tcpconnect -c          # count connects per src, dest, port\n"
	"    tcpconnect --C mappath # only trace cgroups in the map\n"
	"    tcpconnect --M mappath # only trace mount namespaces in the map\n"
	;

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

static int get_ints(const char *arg, int *size, int *ret, int min, int max)
{
	const char *argp = arg;
	int max_size = *size;
	int sz = 0;
	char *end;
	long val;

	while (sz < max_size) {
		errno = 0;
		val = strtol(argp, &end, 10);
		if (errno) {
			warn("strtol: %s: %s\n", arg, strerror(errno));
			return -1;
		} else if (end == arg || val < min || val > max) {
			return -1;
		}
		ret[sz++] = val;
		if (*end == 0)
			break;
		argp = end + 1;
	}

	*size = sz;
	return 0;
}

static int get_uint(const char *arg, unsigned int *ret,
		    unsigned int min, unsigned int max)
{
	char *end;
	long val;

	errno = 0;
	val = strtoul(arg, &end, 10);
	if (errno) {
		warn("strtoul: %s: %s\n", arg, strerror(errno));
		return -1;
	} else if (end == arg || val < min || val > max) {
		return -1;
	}
	if (ret)
		*ret = val;
	return 0;
}

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "timestamp", 't', NULL, 0, "Include timestamp on output", 0 },
	{ "count", 'c', NULL, 0, "Count connects per src ip and dst ip/port", 0 },
	{ "print-uid", 'U', NULL, 0, "Include UID on output", 0 },
	{ "pid", 'p', "PID", 0, "Process PID to trace", 0 },
	{ "uid", 'u', "UID", 0, "Process UID to trace", 0 },
	{ "source-port", 's', NULL, 0, "Consider source port when counting", 0 },
	{ "port", 'P', "PORTS", 0,
	  "Comma-separated list of destination ports to trace", 0 },
	{ "cgroupmap", 'C', "PATH", 0, "trace cgroups in this map", 0 },
	{ "mntnsmap", 'M', "PATH", 0, "trace mount namespaces in this map", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static struct env {
	bool verbose;
	bool count;
	bool print_timestamp;
	bool print_uid;
	pid_t pid;
	uid_t uid;
	int nports;
	int ports[MAX_PORTS];
	bool source_port;
} env = {
	.uid = (uid_t) -1,
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	int err;
	int nports;

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
	case 's':
		env.source_port = true;
		break;
	case 't':
		env.print_timestamp = true;
		break;
	case 'U':
		env.print_uid = true;
		break;
	case 'p':
		err = get_int(arg, &env.pid, 1, INT_MAX);
		if (err) {
			warn("invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'u':
		err = get_uint(arg, &env.uid, 0, (uid_t) -2);
		if (err) {
			warn("invalid UID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'P':
		nports = MAX_PORTS;
		err = get_ints(arg, &nports, env.ports, 1, 65535);
		if (err) {
			warn("invalid PORT_LIST: %s\n", arg);
			argp_usage(state);
		}
		env.nports = nports;
		break;
	case 'C':
		warn("not implemented: --cgroupmap");
		break;
	case 'M':
		warn("not implemented: --mntnsmap");
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

static void print_count_ipv4(int map_fd)
{
	static struct ipv4_flow_key keys[MAX_ENTRIES];
	__u32 value_size = sizeof(__u64);
	__u32 key_size = sizeof(keys[0]);
	static struct ipv4_flow_key zero;
	static __u64 counts[MAX_ENTRIES];
	char s[INET_ADDRSTRLEN];
	char d[INET_ADDRSTRLEN];
	__u32 i, n = MAX_ENTRIES;
	struct in_addr src;
	struct in_addr dst;

	if (dump_hash(map_fd, keys, key_size, counts, value_size, &n, &zero)) {
		warn("dump_hash: %s", strerror(errno));
		return;
	}

	for (i = 0; i < n; i++) {
		src.s_addr = keys[i].saddr;
		dst.s_addr = keys[i].daddr;

		printf("%-25s %-25s",
		       inet_ntop(AF_INET, &src, s, sizeof(s)),
		       inet_ntop(AF_INET, &dst, d, sizeof(d)));
		if (env.source_port)
			printf(" %-20d", keys[i].sport);
		printf(" %-20d", ntohs(keys[i].dport));
		printf(" %-10llu", counts[i]);
		printf("\n");
	}
}

static void print_count_ipv6(int map_fd)
{
	static struct ipv6_flow_key keys[MAX_ENTRIES];
	__u32 value_size = sizeof(__u64);
	__u32 key_size = sizeof(keys[0]);
	static struct ipv6_flow_key zero;
	static __u64 counts[MAX_ENTRIES];
	char s[INET6_ADDRSTRLEN];
	char d[INET6_ADDRSTRLEN];
	__u32 i, n = MAX_ENTRIES;
	struct in6_addr src;
	struct in6_addr dst;

	if (dump_hash(map_fd, keys, key_size, counts, value_size, &n, &zero)) {
		warn("dump_hash: %s", strerror(errno));
		return;
	}

	for (i = 0; i < n; i++) {
		memcpy(src.s6_addr, keys[i].saddr, sizeof(src.s6_addr));
		memcpy(dst.s6_addr, keys[i].daddr, sizeof(src.s6_addr));

		printf("%-25s %-25s",
		       inet_ntop(AF_INET6, &src, s, sizeof(s)),
		       inet_ntop(AF_INET6, &dst, d, sizeof(d)));
		if (env.source_port)
			printf(" %-20d", keys[i].sport);
		printf(" %-20d", ntohs(keys[i].dport));
		printf(" %-10llu", counts[i]);
		printf("\n");
	}
}

static void print_count_header()
{
	printf("\n%-25s %-25s", "LADDR", "RADDR");
	if (env.source_port)
		printf(" %-20s", "LPORT");
	printf(" %-20s", "RPORT");
	printf(" %-10s", "CONNECTS");
	printf("\n");
}

static void print_count(int map_fd_ipv4, int map_fd_ipv6)
{
	while (!exiting)
		pause();

	print_count_header();
	print_count_ipv4(map_fd_ipv4);
	print_count_ipv6(map_fd_ipv6);
}

static void print_events_header()
{
	if (env.print_timestamp)
		printf("%-9s", "TIME(s)");
	if (env.print_uid)
		printf("%-6s", "UID");
	printf("%-6s %-16s %-2s %-16s %-16s",
	       "PID", "COMM", "IP", "SADDR", "DADDR");
	if (env.source_port)
		printf(" %-5s", "SPORT");
	printf(" %-5s\n", "DPORT");
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct event event;
	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];
	union {
		struct in_addr  x4;
		struct in6_addr x6;
	} s, d;
	static __u64 start_ts;

	if (data_sz < sizeof(event)) {
		printf("Error: packet too small\n");
		return;
	}
	/* Copy data as alignment in the perf buffer isn't guaranteed. */
	memcpy(&event, data, sizeof(event));

	if (event.af == AF_INET) {
		s.x4.s_addr = event.saddr_v4;
		d.x4.s_addr = event.daddr_v4;
	} else if (event.af == AF_INET6) {
		memcpy(&s.x6.s6_addr, event.saddr_v6, sizeof(s.x6.s6_addr));
		memcpy(&d.x6.s6_addr, event.daddr_v6, sizeof(d.x6.s6_addr));
	} else {
		warn("broken event: event.af=%d", event.af);
		return;
	}

	if (env.print_timestamp) {
		if (start_ts == 0)
			start_ts = event.ts_us;
		printf("%-9.3f", (event.ts_us - start_ts) / 1000000.0);
	}

	if (env.print_uid)
		printf("%-6d", event.uid);

	printf("%-6d %-16.16s %-2d %-16s %-16s",
	       event.pid, event.task,
	       event.af == AF_INET ? 4 : 6,
	       inet_ntop(event.af, &s, src, sizeof(src)),
	       inet_ntop(event.af, &d, dst, sizeof(dst)));

	if (env.source_port)
		printf(" %-5d", event.sport);

	printf(" %-5d", ntohs(event.dport));

	printf("\n");
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warn("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static void print_events(int perf_map_fd)
{
	struct perf_buffer *pb;
	int err;

	pb = perf_buffer__new(perf_map_fd, 128,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		warn("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	print_events_header();
	while (!exiting) {
		err = perf_buffer__poll(pb, 100);
		if (err < 0 && err != -EINTR) {
			warn("error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
		.args_doc = NULL,
	};
	struct tcpconnect_bpf *obj;
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

	obj = tcpconnect_bpf__open_opts(&open_opts);
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	if (env.count)
		obj->rodata->do_count = true;
	if (env.pid)
		obj->rodata->filter_pid = env.pid;
	if (env.uid != (uid_t) -1)
		obj->rodata->filter_uid = env.uid;
	if (env.nports > 0) {
		obj->rodata->filter_ports_len = env.nports;
		for (i = 0; i < env.nports; i++) {
			obj->rodata->filter_ports[i] = htons(env.ports[i]);
		}
	}
	if (env.source_port)
		obj->rodata->source_port = true;

	err = tcpconnect_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = tcpconnect_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF programs: %s\n", strerror(-err));
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	if (env.count) {
		print_count(bpf_map__fd(obj->maps.ipv4_count),
			    bpf_map__fd(obj->maps.ipv6_count));
	} else {
		print_events(bpf_map__fd(obj->maps.events));
	}

cleanup:
	tcpconnect_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
