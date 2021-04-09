// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// Based on readahead(8) from BPF-Perf-Tools-Book by Brendan Gregg.
// 8-Jun-2020   Wenbo Zhang   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "readahead.h"
#include "readahead.skel.h"
#include "trace_helpers.h"

static struct env {
	int duration;
	bool verbose;
} env = {
	.duration = -1
};

static volatile bool exiting;

const char *argp_program_version = "readahead 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Show fs automatic read-ahead usage.\n"
"\n"
"USAGE: readahead [--help] [-d DURATION]\n"
"\n"
"EXAMPLES:\n"
"    readahead              # summarize on-CPU time as a histogram"
"    readahead -d 10        # trace for 10 seconds only\n";

static const struct argp_option opts[] = {
	{ "duration", 'd', "DURATION", 0, "Duration to trace"},
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		errno = 0;
		env.duration = strtol(arg, NULL, 10);
		if (errno || env.duration <= 0) {
			fprintf(stderr, "Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		break;
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
	exiting = true;
}

/*
 * Starting from v5.10-rc1 (8238287), __do_page_cache_readahead has
 * renamed to do_page_cache_ra. So we specify the function dynamically.
 */
static int readahead__set_attach_target(struct bpf_program *prog)
{
	int err;

	err = bpf_program__set_attach_target(prog, 0, "do_page_cache_ra");
	if (!err)
		return 0;

	err = bpf_program__set_attach_target(prog, 0,
					"__do_page_cache_readahead");
	if (!err)
		return 0;

	fprintf(stderr, "failed to set attach target for %s: %s\n",
		bpf_program__name(prog), strerror(-err));
	return err;
}

static long readahead__probe_target(struct bpf_program *prog, bool retprobe)
{
	struct bpf_link *link;

	link = bpf_program__attach_kprobe(prog, retprobe, "do_page_cache_ra");
	if ((long)link != -2 /*ENOENT*/)
		return 0;

	link = bpf_program__attach_kprobe(prog, retprobe, "__do_page_cache_readahead");
	if ((long)link != -2 /*ENOENT*/)
		return 0;

	return (long)link;
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct readahead_bpf *obj;
	struct hist *histp;
	int err;
	struct bpf_link *link;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	err = bump_memlock_rlimit();
	if (err) {
		fprintf(stderr, "failed to increase rlimit: %d\n", err);
		return 1;
	}

	obj = readahead_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}
	err = readahead_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object\n");
		goto cleanup;
	}

	link = bpf_program__attach_trace(obj->progs.fexit_page_cache_alloc_ret);
	if ((long)link == -524 /*ENOTSUPP*/) {
		err = readahead__probe_target(obj->progs.kprobe_do_page_cache_ra, false);
		if (err)
			goto cleanup;
		err = readahead__probe_target(obj->progs.kprobe_do_page_cache_ra, true);
		if (err)
			goto cleanup;
		bpf_program__attach_kprobe(obj->progs.kretprobe_page_cache_alloc_ret,
			true, "__page_cache_alloc");
		bpf_program__attach_kprobe(obj->progs.kprobe_mark_page_accessed,
			false, "mark_page_accessed");
	}
	else {
		err = readahead__set_attach_target(obj->progs.fentry_do_page_cache_ra);
		if (err)
			goto cleanup;
		err = readahead__set_attach_target(obj->progs.fexit_do_page_cache_ra);
		if (err)
			goto cleanup;
		bpf_program__attach_trace(obj->progs.fentry_do_page_cache_ra);
		bpf_program__attach_trace(obj->progs.fexit_do_page_cache_ra);
		bpf_program__attach_trace(obj->progs.fentry_mark_page_accessed);
	}

	signal(SIGINT, sig_handler);

	printf("Tracing fs read-ahead ... Hit Ctrl-C to end.\n");

	sleep(env.duration);
	printf("\n");

	histp = &obj->bss->hist;

	printf("Readahead unused/total pages: %d/%d\n",
		histp->unused, histp->total);
	print_log2_hist(histp->slots, MAX_SLOTS, "msecs");

cleanup:
	readahead_bpf__destroy(obj);
	return err != 0;
}
