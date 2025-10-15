// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Ism Hong.
 *
 * Based on funcslower from BCC by Sasha Goldshtein and others
 * 2025-10-05   Ism Hong   Created this.
 *
 * TODO:
 * - support uprobes on libraries without -p PID. (parse ld.so.cache)
 * - support fentry/fexit probe
 */

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "funcslower.h"
#include "funcslower.skel.h"
#include "trace_helpers.h"
#include "btf_helpers.h"
#include "uprobe_helpers.h"

#define PERF_BUFFER_PAGES	64
#define PERF_POLL_TIMEOUT_MS	100
#define NSEC_PER_SEC 1000000000ULL
#define PERF_MAX_STACK_DEPTH 127

static volatile sig_atomic_t exiting = 0;

static pid_t target_pid = 0;
static float min_ms = 0;
static float min_us = 0;
static int args_count = 0;
static bool timestamp = false;
static bool time_sec = false;
static bool verbose = false;
static bool folded = false;
static bool user_stack = false;
static bool kernel_stack = false;
static char **functions = NULL;
static int functions_count = 0;
static struct syms_cache *syms_cache = NULL;
static struct ksyms *ksyms = NULL;
static __u64 earliest_ts = 0;

const char *argp_program_version = "funcslower 0.1"; const char
*argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace slow kernel or user function calls.\n"
"\n"
"USAGE: funcslower [-h] [-p PID] [-m MIN_MS] [-u MIN_US] [-a ARGUMENTS]\n"
"                  [-T] [-t] [-v] [-f] [-U] [-K] function [function ...]\n"
"\n"
"EXAMPLES:\n"
"  ./funcslower vfs_write              # trace vfs_write calls slower than 1ms\n"
"  ./funcslower -m 10 vfs_write        # same, but slower than 10ms\n"
"  ./funcslower -u 10 c:open           # trace open calls slower than 10us\n"
"  ./funcslower -p 135 c:open          # trace pid 135 only\n"
"  ./funcslower c:malloc c:free        # trace both malloc and free slower than 1ms\n"
"  ./funcslower -a 2 c:open            # show first two arguments to open\n"
"  ./funcslower -UK -m 10 c:open       # Show user and kernel stack frame of open calls slower than 10ms\n"
"  ./funcslower -f -UK c:open          # Output in folded format for flame graphs\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Trace this PID only", 0 },
	{ "min-ms", 'm', "MIN_MS", 0, "Minimum duration to trace (ms)", 0 },
	{ "min-us", 'u', "MIN_US", 0, "Minimum duration to trace (us)", 0 },
	{ "arguments", 'a', "ARGUMENTS", 0, "Print this many entry arguments, as hex", 0 },
	{ "time", 'T', NULL, 0, "Show HH:MM:SS timestamp", 0 },
	{ "timestamp", 't', NULL, 0, "Show timestamp in seconds at us resolution", 0 },
	{ "verbose", 'v', NULL, 0, "Print BPF program debug output", 0 },
	{ "folded", 'f', NULL, 0, "Output folded format, one line per stack (for flame graphs)", 0 },
	{ "user-stack", 'U', NULL, 0, "Output user stack trace", 0 },
	{ "kernel-stack", 'K', NULL, 0, "Output kernel stack trace", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'p':
		target_pid = strtol(arg, NULL, 10);
		break;
	case 'm':
		min_ms = strtof(arg, NULL);
		break;
	case 'u':
		min_us = strtof(arg, NULL);
		break;
	case 'a':
		args_count = strtol(arg, NULL, 10);
		if (args_count > MAX_ARGS) {
			fprintf(stderr, "Max arguments supported is %d\n", MAX_ARGS);
			return ARGP_ERR_UNKNOWN;
		}
		break;
	case 'T':
		timestamp = true;
		break;
	case 't':
		time_sec = true;
		break;
	case 'v':
		verbose = true;
		break;
	case 'f':
		folded = true;
		break;
	case 'U':
		user_stack = true;
		break;
	case 'K':
		kernel_stack = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case ARGP_KEY_ARG:
		if (functions_count == 0)
			functions = &state->argv[state->next - 1];
		functions_count++;
		break;
	case ARGP_KEY_END:
		if (functions_count == 0) {
			fprintf(stderr, "No function to trace, provide at least one.\n");
			argp_usage(state);
		}
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

static void print_stack(int map_fd, int stack_id, int pid)
{
	__u64 ip[PERF_MAX_STACK_DEPTH];
	int i;

	if (bpf_map_lookup_elem(map_fd, &stack_id, ip) != 0) {
		return;
	}

	for (i = 0; i < PERF_MAX_STACK_DEPTH; i++) {
		if (!ip[i])
			break;
		if (pid) {
			const struct syms *syms = syms_cache__get_syms(syms_cache, pid);
			const struct sym *sym = syms__map_addr(syms, ip[i]);
			printf("    %s\n", sym ? sym->name : "[unknown]");
		} else {
			const struct ksym *sym = ksyms__map_addr(ksyms, ip[i]);
			printf("    %s\n", sym ? sym->name : "[unknown]");
		}
	}
}

static void print_folded(struct funcslower_bpf *skel, const struct event *e)
{
	const struct syms *syms = NULL;
	const struct sym *sym;
	__u64 *ip;
	int i;

	ip = calloc(PERF_MAX_STACK_DEPTH, sizeof(*ip));
	if (!ip) {
		fprintf(stderr, "failed to alloc ip, out of memory\n");
		return;
	}

	printf("%s;", e->comm);

	if (user_stack && e->user_stack_id >= 0) {
		if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.stacks), &e->user_stack_id, ip) == 0) {
			syms = syms_cache__get_syms(syms_cache, e->tgid_pid >> 32);
			for (i = 0; i < PERF_MAX_STACK_DEPTH; i++) {
				if (!ip[i])
					break;
				if (!syms)
					printf("[unknown];");
				else {
					sym = syms__map_addr(syms, ip[i]);
					printf("%s;", sym ? sym->name : "[unknown]");
				}
			}
		}
	}

	if (user_stack && kernel_stack && e->user_stack_id >= 0 && e->kernel_stack_id >= 0)
		printf("-;");

	if (kernel_stack && e->kernel_stack_id >= 0) {
		if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.stacks), &e->kernel_stack_id, ip) == 0) {
			for (i = 0; i < PERF_MAX_STACK_DEPTH; i++) {
				if (!ip[i])
					break;
				const struct ksym *ks = ksyms__map_addr(ksyms, ip[i]);
				printf("%s;", ks ? ks->name : "[unknown]");
			}
		}
	}

	printf(" 1\n");
	free(ip);
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct funcslower_bpf *skel = ctx;
	const struct event *e = data;
	char ts_str[32];
	struct tm *tm;
	time_t t;

	if (folded) {
		print_folded(skel, e);
		return;
	}

	if (timestamp) {
		t = time(NULL);
		tm = localtime(&t);
		strftime(ts_str, sizeof(ts_str), "%H:%M:%S", tm);
		printf("%-10s ", ts_str);
	} else if (time_sec) {
		if (earliest_ts == 0)
			earliest_ts = e->start_ns;
		printf("% -10.6f ", (e->start_ns - earliest_ts) / 1000000000.0);
	}

	double lat = (double)e->duration_ns / (min_us > 0 ? 1000 : 1000000);

	printf("%-14.14s %-6d %7.2f %16llx %s",
			e->comm, (__u32)(e->tgid_pid >> 32), lat, e->retval, functions[e->id]);

	if (args_count > 0) {
		printf(" ");
		for (int i = 0; i < args_count; i++) {
			printf("0x%llx%s", e->args[i], i == args_count - 1 ? "" : " ");
		}
	}
	printf("\n");

	if (user_stack && e->user_stack_id >= 0)
		print_stack(bpf_map__fd(skel->maps.stacks), e->user_stack_id, e->tgid_pid >> 32);
	if (kernel_stack && e->kernel_stack_id >= 0)
		print_stack(bpf_map__fd(skel->maps.stacks), e->kernel_stack_id, 0);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

struct bpf_link *bpf_program__attach_kretprobe(const struct bpf_program *prog, const char *func_name)
{
	return bpf_program__attach_kprobe(prog, true, func_name);
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct funcslower_bpf *skel = NULL;
	struct perf_buffer *pb = NULL;
	struct bpf_link *links[MAX_FUNCS * 2];
	int links_cnt = 0;
	int err, i;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return 1;

	if (functions_count == 0) {
		fprintf(stderr, "No function to trace, provide at least one.\n");
		return 1;
	}

	if (functions_count > MAX_FUNCS) {
		fprintf(stderr, "Too many functions to trace, max is %d\n", MAX_FUNCS);
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(NULL);
	if (err) {
		fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	if (user_stack || kernel_stack || folded) {
		syms_cache = syms_cache__new(0);
		if (!syms_cache) {
			fprintf(stderr, "failed to create syms_cache\n");
			return 1;
		}
		ksyms = ksyms__load();
		if (!ksyms) {
			fprintf(stderr, "failed to load ksyms\n");
			goto cleanup;
		}
	}

	skel = funcslower_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	skel->rodata->tgid = target_pid;
	if (min_ms > 0)
		skel->rodata->min_lat_ns = min_ms * 1000000;
	else if (min_us > 0)
		skel->rodata->min_lat_ns = min_us * 1000;
	else
		skel->rodata->min_lat_ns = 1000000; /* default 1ms */

	skel->rodata->need_args = args_count > 0;
	skel->rodata->args_count = args_count;
	skel->rodata->need_user_stack = user_stack || folded;
	skel->rodata->need_kernel_stack = kernel_stack || folded;

	err = funcslower_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	for (i = 0; i < functions_count; i++) {
		char *func_spec = functions[i];
		char *lib, *func;
		char prog_name[64];
		struct bpf_program *prog;

		func = strdup(func_spec);
		lib = strchr(func, ':');
		if (lib) {
			*lib = '\0';
			lib++;
			char *tmp = func;
			func = lib;
			lib = tmp;
		} else {
			lib = NULL;
		}

		snprintf(prog_name, sizeof(prog_name), "funcslower_entry_%d", i);
		prog = bpf_object__find_program_by_name(skel->obj, prog_name);
		if (!prog) {
			fprintf(stderr, "Failed to find program %s\n", prog_name);
			err = -1;
			goto cleanup;
		}

		if (lib) { /* uprobe */
			char binary_path[PATH_MAX];
			off_t func_offset;

			if (resolve_binary_path(lib, target_pid, binary_path, sizeof(binary_path))) {
				fprintf(stderr, "could not find library %s\n", lib);
				err = -1;
				goto cleanup;
			}

			func_offset = get_elf_func_offset(binary_path, func);
			if (func_offset < 0) {
				fprintf(stderr, "could not find function %s in %s\n", func, binary_path);
				err = -1;
				goto cleanup;
			}

			links[links_cnt++] = bpf_program__attach_uprobe(prog, false,
					target_pid ?: -1, binary_path, func_offset);
			if (!links[links_cnt - 1]) {
				err = -errno;
				fprintf(stderr, "Failed to attach uprobe to %s:%s: %d\n",
						binary_path, func, err);
				goto cleanup;
			}

			links[links_cnt++] = bpf_program__attach_uprobe(skel->progs.funcslower_return,
					true, target_pid ?: -1, binary_path, func_offset);
			if (!links[links_cnt - 1]) {
				err = -errno;
				fprintf(stderr, "Failed to attach uretprobe to %s:%s: %d\n", binary_path, func, err);
				goto cleanup;
			}
		} else { /* kprobe */
			links[links_cnt++] = bpf_program__attach_kprobe(prog, false, func);
			if (!links[links_cnt - 1]) {
				err = -errno;
				fprintf(stderr, "Failed to attach kprobe to %s: %d\n", func, err);
				goto cleanup;
			}

			links[links_cnt++] = bpf_program__attach_kretprobe(skel->progs.funcslower_return, func);
			if (!links[links_cnt - 1]) {
				err = -errno;
				fprintf(stderr, "Failed to attach kretprobe to %s: %d\n", func, err);
				goto cleanup;
			}
		}
		free(lib ? lib : func);
	}

	pb = perf_buffer__new(bpf_map__fd(skel->maps.events), PERF_BUFFER_PAGES,
			handle_event, handle_lost_events, skel, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	const char *time_designator = min_us > 0 ? "us" : "ms";
	float time_value = min_us > 0 ? min_us : (min_ms > 0 ? min_ms : 1);
	if (!folded) {
		printf("Tracing function calls slower than %g %s... Ctrl+C to quit.\n",
				time_value, time_designator);
		char lat_str[16];
		snprintf(lat_str, sizeof(lat_str), "LAT(%s)", time_designator);
		if (timestamp || time_sec)
			printf("%-10s %-14s %-6s %7s %16s %s%s\n", "TIME", "COMM", "PID",
					lat_str, "RVAL", "FUNC", args_count > 0 ? " ARGS" : "");
		else
			printf("%-14s %-6s %7s %16s %s%s\n", "COMM", "PID", lat_str,
					"RVAL", "FUNC", args_count > 0 ? " ARGS" : ""); }

	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	for (i = 0; i < links_cnt; i++)
		bpf_link__destroy(links[i]);
	funcslower_bpf__destroy(skel);
	syms_cache__free(syms_cache);
	ksyms__free(ksyms);
	return -err;
}
