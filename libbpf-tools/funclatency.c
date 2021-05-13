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

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "funclatency.h"
#include "funclatency.skel.h"
#include "trace_helpers.h"
#include "map_helpers.h"
#include "uprobe_helpers.h"
#include "kprobe_helpers.h"
#include "string_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

static struct prog_env {
	int units;
	pid_t pid;
	unsigned int duration;
	unsigned int interval;
	unsigned int iterations;
	bool timestamp;
	char *funcname;
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
"Usage: funclatency [-h] [-m|-u] [-p PID] [-d DURATION] [ -i INTERVAL ]\n"
"                   [-T] FUNCTION\n"
"       Choices for FUNCTION: FUNCTION/PATTERN (kprobe or kprobe pattern)\n"
"                             LIBRARY:FUNCTION (uprobe a library in -p PID)\n"
"                             :FUNCTION        (uprobe the binary of -p PID)\n"
"                             PROGRAM:FUNCTION (uprobe the binary PROGRAM)\n"
"\v"
"Examples:\n"
"  ./funclatency -m 'vfs_*'          # show one histogram per matched function\n"
"  ./funclatency -u vfs_read         # time vfs_read(), in microseconds\n"
"  ./funclatency do_sys_open         # time the do_sys_open() kernel function\n"
"  ./funclatency -m do_nanosleep     # time do_nanosleep(), in milliseconds\n"
"  ./funclatency -u vfs_read         # time vfs_read(), in microseconds\n"
"  ./funclatency -p 181 vfs_read     # time process 181 only\n"
"  ./funclatency -p 181 c:read       # time the read() C library function\n"
"  ./funclatency -p 181 :foo         # time foo() from pid 181's userspace\n"
"  ./funclatency -i 2 -d 10 vfs_read # output every 2 seconds, for 10s\n"
"  ./funclatency -mTi 5 vfs_read     # output every 5 seconds, with timestamps\n"
;

static const struct argp_option opts[] = {
	{ "milliseconds", 'm', NULL, 0, "Output in milliseconds"},
	{ "microseconds", 'u', NULL, 0, "Output in microseconds"},
	{0, 0, 0, 0, ""},
	{ "pid", 'p', "PID", 0, "Process ID to trace"},
	{0, 0, 0, 0, ""},
	{ "interval", 'i', "INTERVAL", 0, "Summary interval in seconds"},
	{ "duration", 'd', "DURATION", 0, "Duration to trace"},
	{ "timestamp", 'T', NULL, 0, "Print timestamp"},
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
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

static int attach_kprobes(struct funclatency_bpf *obj, char *funcname)
{
	long err;

	obj->links.dummy_kprobe =
		bpf_program__attach_kprobe(obj->progs.dummy_kprobe, false,
					   funcname);
	err = libbpf_get_error(obj->links.dummy_kprobe);
	if (err) {
		warn("failed to attach kprobe: %ld\n", err);
		return -1;
	}

	obj->links.dummy_kretprobe =
		bpf_program__attach_kprobe(obj->progs.dummy_kretprobe, true,
					   funcname);
	err = libbpf_get_error(obj->links.dummy_kretprobe);
	if (err) {
		warn("failed to attach kretprobe: %ld\n", err);
		return -1;
	}

	return 0;
}

static int attach_uprobes(struct funclatency_bpf *obj, char *funcname)
{
	char *binary, *function;
	char bin_path[PATH_MAX];
	off_t func_off;
	int ret = -1;
	long err;

	binary = strdup(funcname);
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
	err = libbpf_get_error(obj->links.dummy_kprobe);
	if (err) {
		warn("Failed to attach uprobe: %ld\n", err);
		goto out_binary;
	}

	obj->links.dummy_kretprobe =
		bpf_program__attach_uprobe(obj->progs.dummy_kretprobe, true,
					   env.pid ?: -1, bin_path, func_off);
	err = libbpf_get_error(obj->links.dummy_kretprobe);
	if (err) {
		warn("Failed to attach uretprobe: %ld\n", err);
		goto out_binary;
	}

	ret = 0;

out_binary:
	free(binary);

	return ret;
}

static int attach_probes(struct funclatency_bpf *obj, char *funcname)
{
    if (strchr(funcname, ':'))
        return attach_uprobes(obj, funcname);
    return attach_kprobes(obj, funcname);
}

static volatile bool exiting;

static void sig_hand(int signr)
{
	exiting = true;
}

static struct sigaction sigact = {.sa_handler = sig_hand};

int main(int argc, char **argv)
{
  static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .args_doc = args_doc,
    .doc = program_doc,
  };
  struct funclatency_bpf **obj = malloc(sizeof(struct funclatency_bpf *));
  int i, j, k, err;
  struct tm *tm;
  char ts[32];
  time_t t;
  char **func_list = malloc(sizeof(char *)), *pattern = NULL,
       **label = malloc(sizeof(char *));
  size_t size = 1;
  ssize_t pattern_len = 0;

	err = argp_parse(&argp, argc, argv, 0, NULL, &env);
	if (err)
		return err;

	sigaction(SIGINT, &sigact, 0);

	err = bump_memlock_rlimit();
	if (err) {
		warn("failed to increase rlimit: %d\n", err);
		return 1;
	}

  if (strchr(env.funcname, ':')) {
    func_list[0] = strdup(env.funcname);
  } else {
    if ((err = string_replace(env.funcname, strlen(env.funcname), "*", ".*",
                              &pattern, &pattern_len))) {
      warn("failed to replace '*' to '.*': %s\n", strerror(err));
      return 1;
    }

    if ((err = get_kprobe_functions(pattern, &func_list, &size))) {
      if (err == ERANGE)
        warn("the number of matched functions is large than: %d\n",
             KPROBE_LIMIT);
      else {
        warn("failed to read from /proc/kallsyms: %s\n", strerror(err));
        free(pattern);
        return 1;
      }
    }

    obj = realloc(obj, size * sizeof(struct funclatency_bpf *));
    label = realloc(label, size * sizeof(char *));
  }

  for (i = 0; i < size; i++) {
    obj[i] = funclatency_bpf__open();
    if (!obj[i]) {
      warn("failed to open BPF object\n");
      return 1;
    }

    obj[i]->rodata->units = env.units;
    obj[i]->rodata->targ_tgid = env.pid;

    err = funclatency_bpf__load(obj[i]);
    if (err) {
      warn("failed to load BPF object\n");
      return 1;
    }

    label[i] = malloc(sizeof("\nFunction=") + strlen(func_list[i]));
    sprintf(label[i], "\nFunction=%s", func_list[i]);
    err = attach_probes(obj[i], func_list[i]);
    if (err)
      goto cleanup;
  }

  printf("Tracing %ld functions for '%s'.  Hit Ctrl-C to exit\n", size,
         env.funcname);

  for (j = 0; j < env.iterations && !exiting; j++) {
    sleep(env.interval);
    printf("\n");
    if (env.timestamp) {
      time(&t);
      tm = localtime(&t);
      strftime(ts, sizeof(ts), "%H:%M:%S", tm);
      printf("%-8s\n", ts);
    }

    for (k = 0; k < size; k++) {
      print_log2_hist(obj[k]->bss->hist, MAX_SLOTS, unit_str(), label[k]);
      /* TODO clean old hist (atomic?) */
    }
  }

  printf("\nDetaching...\n");

cleanup:
  for (j = 0; j < i; j++) {
    free(label[j]);
    funclatency_bpf__destroy(obj[j]);
  }

  free(label);
  free(pattern);
  free_kprobe_functions(func_list, size);

  return err != 0;
}
