/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2021 Sony Group Corporation */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "trace_helpers.h"
#include "sysinjector.h"
#include "sysinjector.skel.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

static struct prog_env {
	pid_t pid;
	char *comm;
	int comm_len;
	int retval;
	char *syscall;
} env;

const char *argp_program_version = "sysinjector 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
static const char args_doc[] = "SYSCALL";
static const char program_doc[] =
"Modify a return value of a syscall\n"
"\n"
"Usage: sysinjector [-h] [-p PID] [-c COMM] [-r RETVAL] SYSCALL\n"
"\v"
"Examples:\n"
"  ./sysinjector -r -12 -p 1111 __x64_sys_mknodat            # return ENOMEM\n"
"  ./sysinjector -r -22 -c sleep __x64_sys_clock_nanosleep   # return EINVAL\n"
;

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to modify"},
	{ "comm",  'c', "COMM",  0, "Trace this comm only" },
	{ "retval", 'r', "RETVAL", 0, "Modified return value" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct prog_env *env = state->input;
	long pid;
	int len, retval;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			warn("Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		env->pid = pid;
		break;
	case 'c':
		env->comm = strdup(arg);
		if (!env->comm) {
			warn("strdup: %s\n", strerror(errno));
			argp_usage(state);
		}
		len = strlen(arg) + 1;
		env->comm_len = len > TASK_COMM_LEN ? TASK_COMM_LEN : len;
		break;
	case 'r':
		errno = 0;
		retval = strtol(arg, NULL, 10);
		if (errno) {
			warn("Invalid RETVAL: %s\n", arg);
			argp_usage(state);
		}
		env->retval = retval;
		break;
	case ARGP_KEY_ARG:
		if (env->syscall) {
			warn("Too many syscalls: %s\n", arg);
			argp_usage(state);
		}
		env->syscall = strdup(arg);
		if (!env->syscall) {
			warn("strdup: %s\n", strerror(errno));
			argp_usage(state);
		}
		break;
	case ARGP_KEY_END:
		if (!env->syscall) {
			warn("Need the syscall to modify the return value\n");
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int attach_kprobes(struct sysinjector_bpf *obj)
{
	long err;

	obj->links.handle_retval_at_enter = bpf_program__attach_kprobe(obj->progs.handle_retval_at_enter, false, env.syscall);
	err = libbpf_get_error(obj->links.handle_retval_at_enter);
	if (err) {
		warn("failed to attach kprobe: %ld\n", err);
		return -1;
	}

	return 0;
}

static volatile int exiting = 0;

static void sig_hand(int signr)
{
	exiting = 1;
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
	struct sysinjector_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, &env);
	if (err)
		return err;

	sigaction(SIGINT, &sigact, 0);

	err = bump_memlock_rlimit();
	if (err) {
		warn("failed to increase rlimit: %d\n", err);
		return 1;
	}

	obj = sysinjector_bpf__open();
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->targ_tgid = env.pid;
	obj->rodata->retval = env.retval;
	if (env.comm)
		strncpy((char*)obj->rodata->targ_comm, env.comm, env.comm_len);

	err = sysinjector_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object\n");
		return 1;
	}

	err = attach_kprobes(obj);
	if (err)
		goto cleanup;

	printf("Modifing the return value of %s. Ctrl-C to exit\n", env.syscall);

	while (!exiting)
		pause();

cleanup:
	free(env.syscall);
	free(env.comm);
	sysinjector_bpf__destroy(obj);

	return err != 0;
}
