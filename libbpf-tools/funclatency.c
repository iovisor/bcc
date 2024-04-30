// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Google LLC.
 *
 * Based on funclatency from BCC by Brendan Gregg and others
 * 2021-02-26   Barret Rhoden   Created this.
 *
 * TODO:
 * - support uprobes on libraries without -p PID. (parse ld.so.cache)
 * - support regexp pattern matching and per-function histograms
 */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "funclatency.h"
#include "funclatency.skel.h"
#include "trace_helpers.h"
#include "map_helpers.h"
#include "btf_helpers.h"
#include "uprobe_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

static struct prog_env {
	int units;
	pid_t pid;
	unsigned int duration;
	unsigned int interval;
	unsigned int iterations;
	bool timestamp;
	char *funcname;
	bool verbose;
	bool kprobes;
	char *cgroupspath;
	bool cg;
	bool is_kernel_func;
} env = {
	.interval = 99999999,
	.iterations = 99999999,
};

const char *argp_program_version = "funclatency 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
static const char args_doc[] = "FUNCTION";
static const char program_doc[] =
"Time functions and print latency as a histogram\n"
"\n"
"Usage: funclatency [-h] [-m|-u] [-p PID] [-d DURATION] [ -i INTERVAL ] [-c CG]\n"
"                   [-T] FUNCTION\n"
"       Choices for FUNCTION: FUNCTION         (kprobe)\n"
"                             LIBRARY:FUNCTION (uprobe a library in -p PID)\n"
"                             :FUNCTION        (uprobe the binary of -p PID)\n"
"                             PROGRAM:FUNCTION (uprobe the binary PROGRAM)\n"
"\v"
"Examples:\n"
"  ./funclatency do_sys_open         # time the do_sys_open() kernel function\n"
"  ./funclatency -m do_nanosleep     # time do_nanosleep(), in milliseconds\n"
"  ./funclatency -c CG               # Trace process under cgroupsPath CG\n"
"  ./funclatency -u vfs_read         # time vfs_read(), in microseconds\n"
"  ./funclatency -p 181 vfs_read     # time process 181 only\n"
"  ./funclatency -p 181 c:read       # time the read() C library function\n"
"  ./funclatency -p 181 :foo         # time foo() from pid 181's userspace\n"
"  ./funclatency -i 2 -d 10 vfs_read # output every 2 seconds, for 10s\n"
"  ./funclatency -mTi 5 vfs_read     # output every 5 seconds, with timestamps\n"
;

static const struct argp_option opts[] = {
	{ "milliseconds", 'm', NULL, 0, "Output in milliseconds", 0 },
	{ "microseconds", 'u', NULL, 0, "Output in microseconds", 0 },
	{0, 0, 0, 0, "", 0 },
	{ "pid", 'p', "PID", 0, "Process ID to trace", 0 },
	{0, 0, 0, 0, "", 0 },
	{ "interval", 'i', "INTERVAL", 0, "Summary interval in seconds", 0 },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path", 0 },
	{ "duration", 'd', "DURATION", 0, "Duration to trace", 0 },
	{ "timestamp", 'T', NULL, 0, "Print timestamp", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "kprobes", 'k', NULL, 0, "Use kprobes instead of fentry", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct prog_env *env = state->input;
	long duration, interval, pid;

	switch (key) {
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			warn("Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		env->pid = pid;
		break;
	case 'm':
		if (env->units != NSEC) {
			warn("only set one of -m or -u\n");
			argp_usage(state);
		}
		env->units = MSEC;
		break;
	case 'c':
		env->cgroupspath = arg;
		env->cg = true;
		break;
	case 'u':
		if (env->units != NSEC) {
			warn("only set one of -m or -u\n");
			argp_usage(state);
		}
		env->units = USEC;
		break;
	case 'd':
		errno = 0;
		duration = strtol(arg, NULL, 10);
		if (errno || duration <= 0) {
			warn("Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		env->duration = duration;
		break;
	case 'i':
		errno = 0;
		interval = strtol(arg, NULL, 10);
		if (errno || interval <= 0) {
			warn("Invalid interval: %s\n", arg);
			argp_usage(state);
		}
		env->interval = interval;
		break;
	case 'T':
		env->timestamp = true;
		break;
	case 'k':
		env->kprobes = true;
		break;
	case 'v':
		env->verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case ARGP_KEY_ARG:
		if (env->funcname) {
			warn("Too many function names: %s\n", arg);
			argp_usage(state);
		}
		env->funcname = arg;
		break;
	case ARGP_KEY_END:
		if (!env->funcname) {
			warn("Need a function to trace\n");
			argp_usage(state);
		}
		if (env->duration) {
			if (env->interval > env->duration)
				env->interval = env->duration;
			env->iterations = env->duration / env->interval;
		}
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

static const char *unit_str(void)
{
	switch (env.units) {
	case NSEC:
		return "nsec";
	case USEC:
		return "usec";
	case MSEC:
		return "msec";
	};

	return "bad units";
}

static bool try_fentry(struct funclatency_bpf *obj)
{
	long err;

	if (env.kprobes || !env.is_kernel_func ||
	    !fentry_can_attach(env.funcname, NULL)) {
		goto out_no_fentry;
	}

	err = bpf_program__set_attach_target(obj->progs.dummy_fentry, 0,
					     env.funcname);
	if (err) {
		warn("failed to set attach fentry: %s\n", strerror(-err));
		goto out_no_fentry;
	}

	err = bpf_program__set_attach_target(obj->progs.dummy_fexit, 0,
					     env.funcname);
	if (err) {
		warn("failed to set attach fexit: %s\n", strerror(-err));
		goto out_no_fentry;
	}

	bpf_program__set_autoload(obj->progs.dummy_kprobe, false);
	bpf_program__set_autoload(obj->progs.dummy_kretprobe, false);

	return true;

out_no_fentry:
	bpf_program__set_autoload(obj->progs.dummy_fentry, false);
	bpf_program__set_autoload(obj->progs.dummy_fexit, false);

	return false;
}

static int attach_kprobes(struct funclatency_bpf *obj)
{
	obj->links.dummy_kprobe =
		bpf_program__attach_kprobe(obj->progs.dummy_kprobe, false,
					   env.funcname);
	if (!obj->links.dummy_kprobe) {
		warn("failed to attach kprobe: %d\n", -errno);
		return -1;
	}

	obj->links.dummy_kretprobe =
		bpf_program__attach_kprobe(obj->progs.dummy_kretprobe, true,
					   env.funcname);
	if (!obj->links.dummy_kretprobe) {
		warn("failed to attach kretprobe: %d\n", -errno);
		return -1;
	}

	return 0;
}

static int attach_uprobes(struct funclatency_bpf *obj)
{
	char *binary, *function;
	char bin_path[PATH_MAX];
	off_t func_off;
	int ret = -1;
	long err;

	binary = strdup(env.funcname);
	if (!binary) {
		warn("strdup failed");
		return -1;
	}
	function = strchr(binary, ':');
	if (!function) {
		warn("Binary should have contained ':' (internal bug!)\n");
		return -1;
	}
	*function = '\0';
	function++;

	if (resolve_binary_path(binary, env.pid, bin_path, sizeof(bin_path)))
		goto out_binary;

	func_off = get_elf_func_offset(bin_path, function);
	if (func_off < 0) {
		warn("Could not find %s in %s\n", function, bin_path);
		goto out_binary;
	}

	obj->links.dummy_kprobe =
		bpf_program__attach_uprobe(obj->progs.dummy_kprobe, false,
					   env.pid ?: -1, bin_path, func_off);
	if (!obj->links.dummy_kprobe) {
		err = -errno;
		warn("Failed to attach uprobe: %ld\n", err);
		goto out_binary;
	}

	obj->links.dummy_kretprobe =
		bpf_program__attach_uprobe(obj->progs.dummy_kretprobe, true,
					   env.pid ?: -1, bin_path, func_off);
	if (!obj->links.dummy_kretprobe) {
		err = -errno;
		warn("Failed to attach uretprobe: %ld\n", err);
		goto out_binary;
	}

	ret = 0;

out_binary:
	free(binary);

	return ret;
}

static volatile bool exiting;

static void sig_hand(int signr)
{
	exiting = true;
}

static struct sigaction sigact = {.sa_handler = sig_hand};

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.args_doc = args_doc,
		.doc = program_doc,
	};
	struct funclatency_bpf *obj;
	int i, err;
	struct tm *tm;
	char ts[32];
	time_t t;
	int idx, cg_map_fd;
	int cgfd = -1;
	bool used_fentry = false;

	err = argp_parse(&argp, argc, argv, 0, NULL, &env);
	if (err)
		return err;

	env.is_kernel_func = !strchr(env.funcname, ':');

	sigaction(SIGINT, &sigact, 0);

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	obj = funclatency_bpf__open_opts(&open_opts);
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->units = env.units;
	obj->rodata->targ_tgid = env.pid;
	obj->rodata->filter_cg = env.cg;

	used_fentry = try_fentry(obj);

	err = funclatency_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object\n");
		return 1;
	}

/* update cgroup path fd to map */
	if (env.cg) {
		idx = 0;
		cg_map_fd = bpf_map__fd(obj->maps.cgroup_map);
		cgfd = open(env.cgroupspath, O_RDONLY);
		if (cgfd < 0) {
			fprintf(stderr, "Failed opening Cgroup path: %s", env.cgroupspath);
			goto cleanup;
		}
		if (bpf_map_update_elem(cg_map_fd, &idx, &cgfd, BPF_ANY)) {
			fprintf(stderr, "Failed adding target cgroup to map");
			goto cleanup;
		}
	}

	if (!obj->bss) {
		warn("Memory-mapping BPF maps is supported starting from Linux 5.7, please upgrade.\n");
		goto cleanup;
	}

	if (!used_fentry) {
		if (env.is_kernel_func)
			err = attach_kprobes(obj);
		else
			err = attach_uprobes(obj);
		if (err)
			goto cleanup;
	}

	err = funclatency_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs: %s\n",
			strerror(-err));
		goto cleanup;
	}

	printf("Tracing %s.  Hit Ctrl-C to exit\n", env.funcname);

	for (i = 0; i < env.iterations && !exiting; i++) {
		sleep(env.interval);

		printf("\n");
		if (env.timestamp) {
			time(&t);
			tm = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);
			printf("%-8s\n", ts);
		}

		print_log2_hist(obj->bss->hist, MAX_SLOTS, unit_str());

		/* Cleanup histograms for interval output */
		memset(obj->bss->hist, 0, sizeof(obj->bss->hist));
	}

	printf("Exiting trace of %s\n", env.funcname);

cleanup:
	funclatency_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);
	if (cgfd > 0)
		close(cgfd);

	return err != 0;
}
