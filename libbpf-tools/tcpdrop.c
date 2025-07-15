/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * tcpdrop: Trace TCP kernel-dropped packets/segments using eBPF
 * Copyright (c) 2025 Zi Li <zi.li@linux.dev>
 *
 * Based on tcptop(8) from BCC by Brendan Gregg.
 *
 * 01-May-2025   Lance Yang    Created initial demo.
 * 10-Jun-2025   Zi Li         Created this.
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <argp.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/types.h>

#include "tcpdrop.h"
#include "tcpdrop.skel.h"
#include "trace_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define REASON_MAX_LEN 64
#define MAX_DROP_REASONS 128
#define MAX_STACK_DEPTH 15
#define NANOSECONDS_IN_SECOND 1000000000

static volatile sig_atomic_t exiting = 0;
static struct tcpdrop_bpf *skel = NULL;
static char drop_reasons[MAX_DROP_REASONS][REASON_MAX_LEN];
static int drop_reason_max = 0;
static bool drop_reason_inited = false;

const char *argp_program_version = "tcpdrop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
	"Trace TCP kernel-dropped packets/segments using eBPF.\n"
	"\n"
	"USAGE: tcpdrop [-h] [-4] [-6] [--netns-id ID] [--pid-netns PID]\n"
	"\n"
	"EXAMPLES:\n"
	"    tcpdrop            # trace all TCP drops\n"
	"    tcpdrop -4         # trace IPv4 family only\n"
	"    tcpdrop -6         # trace IPv6 family only\n"
	"    tcpdrop --netns-id 12345  # filter by network namespace ID\n"
	"    tcpdrop --pid-netns 123   # filter by network namespace of PID\n";

static const struct argp_option opts[] = {
	{ "ipv4", '4', NULL, 0, "trace IPv4 family only", 0 },
	{ "ipv6", '6', NULL, 0, "trace IPv6 family only", 0 },
	{ "netns-id", 'n', "ID", 0, "filter by network namespace ID", 0 },
	{ "pid-netns", 'p', "PID", 0, "filter by network namespace of PID", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "show the full help", 0 },
	{},
};

struct args {
	bool ipv4_only;
	bool ipv6_only;
	__u32 netns_id;
	__u32 pid_netns;
};
static struct args arguments = { 0 };

static const char *tcp_states[] = {
	[0] = "CLOSED",	   [1] = "LISTEN",	[2] = "SYN_SENT",
	[3] = "SYN_RECV",  [4] = "ESTABLISHED", [5] = "FIN_WAIT1",
	[6] = "FIN_WAIT2", [7] = "CLOSE_WAIT",	[8] = "CLOSING",
	[9] = "LAST_ACK",  [10] = "TIME_WAIT",	[11] = "DELETE_TCB",
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct args *args = state->input;

	switch (key) {
	case '4':
		if (args->ipv6_only) {
			warn("Cannot specify both -4 and -6\n");
			argp_usage(state);
		}
		args->ipv4_only = true;
		break;
	case '6':
		if (args->ipv4_only) {
			warn("Cannot specify both -4 and -6\n");
			argp_usage(state);
		}
		args->ipv6_only = true;
		break;
	case 'n': /* --netns-id */
		errno = 0;
		args->netns_id = strtoul(arg, NULL, 10);
		if (errno || args->netns_id == 0) {
			warn("Invalid netns-id: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'p': /* --pid-netns */
		errno = 0;
		args->pid_netns = strtoul(arg, NULL, 10);
		if (errno || args->pid_netns == 0) {
			warn("Invalid pid-netns: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_END:
		if (args->pid_netns && args->netns_id) {
			warn("Cannot specify both --netns-id and "
			     "--pid-netns\n");
			argp_usage(state);
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
	if (level == LIBBPF_DEBUG)
		return 0; /* Only print debug messages in verbose mode */
	return vfprintf(stderr, format, args);
}

static void sig_handler(int signo)
{
	exiting = 1;
}

static bool fsearch(FILE *f, const char *target)
{
	char tmp[128];

	while (fscanf(f, "%s", tmp) == 1) {
		if (strstr(tmp, target))
			return true;
	}
	return false;
}

static int parse_reason_enum(void)
{
	char name[REASON_MAX_LEN];
	int index = 0;
	FILE *f;

	f = fopen("/sys/kernel/debug/tracing/events/skb/kfree_skb/format", "r");
	if (!f || !fsearch(f, "__print_symbolic")) {
		if (f) {
			warn("Failed to parse drop reasons: %s\n",
			     strerror(errno));
			fclose(f);
		}
		return -1;
	}

	while (fsearch(f, "{") &&
	       fscanf(f, "%d, \"%31[A-Z_0-9]\"", &index, name) == 2) {
		snprintf(drop_reasons[index], REASON_MAX_LEN, "%s", name);
	}
	drop_reason_max = index;
	drop_reason_inited = true;

	fclose(f);
	return 0;
}

static const char *get_drop_reason_name(int reason)
{
	if (reason >= 0 && reason <= drop_reason_max && drop_reason_inited)
		return drop_reasons[reason];
	return "UNKNOWN";
}

static char *tcp_flags_to_str(__u8 flags, char *buf, size_t buf_size)
{
	size_t pos = 0;

	if (flags & 0x01)
		pos += snprintf(buf + pos, buf_size - pos, "FIN|");
	if (flags & 0x02)
		pos += snprintf(buf + pos, buf_size - pos, "SYN|");
	if (flags & 0x04)
		pos += snprintf(buf + pos, buf_size - pos, "RST|");
	if (flags & 0x08)
		pos += snprintf(buf + pos, buf_size - pos, "PSH|");
	if (flags & 0x10)
		pos += snprintf(buf + pos, buf_size - pos, "ACK|");
	if (flags & 0x20)
		pos += snprintf(buf + pos, buf_size - pos, "URG|");
	if (flags & 0x40)
		pos += snprintf(buf + pos, buf_size - pos, "ECE|");
	if (flags & 0x80)
		pos += snprintf(buf + pos, buf_size - pos, "CWR|");
	if (pos > 0)
		buf[pos - 1] = '\0';
	else
		snprintf(buf, buf_size, "NONE");
	return buf;
}

static time_t get_boot_time(void)
{
	FILE *fp = fopen("/proc/stat", "r");
	char line[256];
	time_t boot_time = 0;

	if (!fp) {
		warn("Failed to open /proc/stat: %s\n", strerror(errno));
		return 0;
	}

	while (fgets(line, sizeof(line), fp)) {
		if (sscanf(line, "btime %ld", &boot_time) == 1) {
			fclose(fp);
			return boot_time;
		}
	}
	warn("Failed to find btime in /proc/stat\n");
	fclose(fp);
	return 0;
}

static void print_stack_trace(struct ksyms *ksyms, int stack_map_fd,
			      __u32 stack_id)
{
	__u64 ips[MAX_STACK_DEPTH] = { 0 };

	if (stack_id == 0) {
		printf("  [Invalid stack ID 0]\n");
		return;
	}

	if (bpf_map_lookup_elem(stack_map_fd, &stack_id, ips) < 0) {
		warn("Failed to lookup stack trace (id: %u): %s\n", stack_id,
		     strerror(errno));
		return;
	}

	printf("Stack trace (id: %u):\n", stack_id);
	for (int i = 0; i < MAX_STACK_DEPTH && ips[i]; i++) {
		const struct ksym *ksym = ksyms__map_addr(ksyms, ips[i]);
		printf("  #%-2d 0x%016llx [%s]\n", i, ips[i],
		       ksym ? ksym->name : "UNKNOWN");
	}
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct ksyms *ksyms = ctx;

	if (data_sz != sizeof(struct event)) {
		warn("Invalid event size: %zu, expected %zu\n", data_sz,
		     sizeof(struct event));
		return 0;
	}
	if (e->ip_version != 4 && e->ip_version != 6) {
		warn("Invalid ip_version: %u\n", e->ip_version);
		return 0;
	}

	time_t boot_time = get_boot_time();
	if (boot_time == 0)
		return 0;

	__u64 elapsed_seconds = e->timestamp / NANOSECONDS_IN_SECOND;
	time_t event_time = boot_time + elapsed_seconds;
	struct tm tm;
	localtime_r(&event_time, &tm);
	char time_buf[16];
	strftime(time_buf, sizeof(time_buf), "%H:%M:%S", &tm);

	char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
	if (e->ip_version == 4) {
		inet_ntop(AF_INET, &e->saddr_v4, src_ip, sizeof(src_ip));
		inet_ntop(AF_INET, &e->daddr_v4, dst_ip, sizeof(dst_ip));
	} else {
		struct in6_addr saddr, daddr;
		memcpy(saddr.s6_addr32, e->saddr_v6, sizeof(e->saddr_v6));
		memcpy(daddr.s6_addr32, e->daddr_v6, sizeof(e->daddr_v6));
		inet_ntop(AF_INET6, &saddr, src_ip, sizeof(src_ip));
		inet_ntop(AF_INET6, &daddr, dst_ip, sizeof(dst_ip));
	}

	const char *tcp_state = e->state < ARRAY_SIZE(tcp_states) ?
					tcp_states[e->state] :
					"UNKNOWN";
	char tcp_flags_buf[64];
	tcp_flags_to_str(e->tcpflags, tcp_flags_buf, sizeof(tcp_flags_buf));
	const char *drop_reason = get_drop_reason_name(e->drop_reason);

	char src_buf[INET6_ADDRSTRLEN + 6], dst_buf[INET6_ADDRSTRLEN + 6],
		state_buf[128];
	snprintf(src_buf, sizeof(src_buf), "%s:%u", src_ip, e->sport);
	snprintf(dst_buf, sizeof(dst_buf), "%s:%u", dst_ip, e->dport);
	snprintf(state_buf, sizeof(state_buf), "%s (%s)", tcp_state,
		 tcp_flags_buf);

	printf("%-8s %-7u %-2u %-20s > %-20s %-20s %s (%d)\n", time_buf, e->pid,
	       e->ip_version, src_buf, dst_buf, state_buf, drop_reason,
	       e->drop_reason);

	int stack_map_fd = bpf_map__fd(skel->maps.stack_traces);
	if (stack_map_fd >= 0 && e->stack_id != 0)
		print_stack_trace(ksyms, stack_map_fd, e->stack_id);

	printf("\n");
	return 0;
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct ring_buffer *rb = NULL;
	struct ksyms *ksyms = NULL;
	int err = 0;

	err = argp_parse(&argp, argc, argv, 0, NULL, &arguments);
	if (err)
		return err;

	if (arguments.pid_netns) {
		char path[64];
		struct stat st;

		snprintf(path, sizeof(path), "/proc/%u/ns/net",
			 arguments.pid_netns);
		if (stat(path, &st) < 0) {
			warn("Failed to get netns for PID %u: %s\n",
			     arguments.pid_netns, strerror(errno));
			return 1;
		}
		arguments.netns_id = st.st_ino;
	}

	libbpf_set_print(libbpf_print_fn);

	ksyms = ksyms__load();
	if (!ksyms) {
		warn("Failed to load kernel symbols\n");
		return 1;
	}

	LIBBPF_OPTS(bpf_object_open_opts, opts);
	skel = tcpdrop_bpf__open_opts(&opts);
	if (!skel) {
		warn("Failed to open BPF skeleton\n");
		err = 1;
		goto cleanup;
	}

	skel->bss->ipv4_only = arguments.ipv4_only;
	skel->bss->ipv6_only = arguments.ipv6_only;
	skel->bss->netns_id = arguments.netns_id;

	err = tcpdrop_bpf__load(skel);
	if (err) {
		warn("Failed to load BPF skeleton: %d\n", err);
		goto cleanup;
	}

	err = tcpdrop_bpf__attach(skel);
	if (err) {
		warn("Failed to attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	parse_reason_enum();
	if (!drop_reason_inited) {
		warn("Failed to parse drop reasons, some reasons may show as UNKNOWN.\n");
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event,
			      ksyms, NULL);
	if (!rb) {
		warn("Failed to create ring buffer: %s\n", strerror(errno));
		err = -1;
		goto cleanup;
	}

	printf("%-8s %-7s %-2s %-20s > %-20s %-20s %s\n", "TIME", "PID", "IP",
	       "SADDR:SPORT", "DADDR:DPORT", "STATE (FLAGS)", "REASON (CODE)");

	if (signal(SIGINT, sig_handler) == SIG_ERR ||
	    signal(SIGTERM, sig_handler) == SIG_ERR) {
		warn("Failed to set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	printf("Monitoring skb:kfree_skb events...\n");
	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			warn("Error polling ring buffer: %d\n", err);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	tcpdrop_bpf__destroy(skel);
	ksyms__free(ksyms);
	return err != 0;
}