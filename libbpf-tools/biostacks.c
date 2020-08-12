// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// Based on biostacks(8) from BPF-Perf-Tools-Book by Brendan Gregg.
// 10-Aug-2020   Wenbo Zhang   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "biostacks.h"
#include "biostacks.skel.h"
#include "trace_helpers.h"

static struct env {
	char *disk;
	int disk_len;
	int duration;
	bool milliseconds;
	bool verbose;
} env = {
	.duration = -1,
};

const char *argp_program_version = "biostacks 0.1";
const char *argp_program_bug_address = "<ethercflow@gmail.com>";
const char argp_program_doc[] =
"Tracing block I/O with init stacks.\n"
"\n"
"USAGE: biostacks [-h]\n"
"\n"
"EXAMPLES:\n"
"    biostacks              # trace block I/O with init stacks.\n"
"    biolatency -d sdc      # trace sdc only\n";

static const struct argp_option opts[] = {
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{ "disk",  'd', "DISK",  0, "Trace this disk only" },
	{ "milliseconds", 'm', NULL, 0, "Millisecond histogram" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'h':
		argp_usage(state);
		break;
	case 'd':
		env.disk = arg;
		env.disk_len = strlen(arg) + 1;
		if (env.disk_len > DISK_NAME_LEN) {
			fprintf(stderr, "invaild disk name: too long\n");
			argp_usage(state);
		}
		break;
	case 'm':
		env.milliseconds = true;
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			fprintf(stderr,
				"unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		env.duration = strtoll(arg, NULL, 10);
		if (errno || env.duration <= 0) {
			fprintf(stderr, "invalid delay (in us): %s\n", arg);
			argp_usage(state);
		}
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

int libbpf_print_fn(enum libbpf_print_level level,
		const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
}

static int print_map(struct ksyms *ksyms, int fd)
{
	char *units = env.milliseconds ? "msecs" : "usecs";
	__u64 lookup_key = -1, next_key;
	const struct ksym *ksym;
	int num_stack, i, err;
	struct rqinfo rqinfo;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &rqinfo);
		if (err < 0) {
			fprintf(stderr, "failed to lookup hist: %d\n", err);
			return -1;
		}
		printf("%-14.14s %-6d %-7s\n",
			rqinfo.comm, rqinfo.pid, rqinfo.disk);
		num_stack = rqinfo.kern_stack_size /
			sizeof(rqinfo.kern_stack[0]);
		for (i = 0; i < num_stack; i++) {
			ksym = ksyms__map_addr(ksyms, rqinfo.kern_stack[i]);
			printf("%s\n", ksym->name);
		}
		print_log2_hist(rqinfo.slots, MAX_SLOTS, units);
		printf("\n");
		lookup_key = next_key;
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
	struct ksyms *ksyms = NULL;
	struct biostacks_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	err = bump_memlock_rlimit();
	if (err) {
		fprintf(stderr, "failed to increase rlimit: %d\n", err);
		return 1;
	}

	obj = biostacks_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF ojbect\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	if (env.disk)
		strncpy((char*)obj->rodata->targ_disk, env.disk, env.disk_len);
	obj->rodata->targ_ms = env.milliseconds;

	err = biostacks_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	obj->links.fentry__blk_account_io_start =
		bpf_program__attach(obj->progs.fentry__blk_account_io_start);
	err = libbpf_get_error(obj->links.fentry__blk_account_io_start);
	if (err) {
		fprintf(stderr, "failed to attach blk_account_io_start: %s\n",
			strerror(err));
		goto cleanup;
	}
	ksyms = ksyms__load();
	if (!ksyms) {
		fprintf(stderr, "failed to load kallsyms\n");
		goto cleanup;
	}
	if (ksyms__get_symbol(ksyms, "blk_account_io_merge_bio")) {
		obj->links.kprobe__blk_account_io_merge_bio =
			bpf_program__attach(obj->
					progs.kprobe__blk_account_io_merge_bio);
		err = libbpf_get_error(obj->
				links.kprobe__blk_account_io_merge_bio);
		if (err) {
			fprintf(stderr, "failed to attach "
				"blk_account_io_merge_bio: %s\n",
				strerror(err));
			goto cleanup;
		}
	}
	obj->links.fentry__blk_account_io_done =
		bpf_program__attach(obj->progs.fentry__blk_account_io_done);
	err = libbpf_get_error(obj->links.fentry__blk_account_io_done);
	if (err) {
		fprintf(stderr, "failed to attach blk_account_io_done: %s\n",
			strerror(err));
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	printf("Tracing block I/O with init stacks. Hit Ctrl-C to end.\n");
	sleep(env.duration);
	print_map(ksyms, bpf_map__fd(obj->maps.rqinfos));

cleanup:
	biostacks_bpf__destroy(obj);
	ksyms__free(ksyms);

	return err != 0;
}
