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
"    readahead              # summarize on-CPU time as a histogram\n"
"    readahead -d 10        # trace for 10 seconds only\n";

static const struct argp_option opts[] = {
	{ "duration", 'd', "DURATION", 0, "Duration to trace", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
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

static int readahead__set_attach_target(struct bpf_program *prog)
{
	int err;

	/*
	 * 56a4d67c264e ("mm/readahead: Switch to page_cache_ra_order") in v5.18
	 * renamed do_page_cache_ra to page_cache_ra_order
	 */
	err = bpf_program__set_attach_target(prog, 0, "page_cache_ra_order");
	if (!err)
		return 0;

	/*
	 * 8238287eadb2 ("mm/readahead: make do_page_cache_ra take a readahead_control")
	 * in v5.10 renamed __do_page_cache_readahead to do_page_cache_ra
	*/
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

static int attach_access(struct readahead_bpf *obj)
{
	bpf_program__set_autoload(obj->progs.folio_mark_accessed, false);
	bpf_program__set_autoload(obj->progs.mark_page_accessed, false);

	/*
	 * 76580b65 ("mm/swap: Add folio_mark_accessed()") in v5.15
	 * convert mark_page_accessed() to folio_mark_accessed().
	 */
	if (fentry_can_attach("folio_mark_accessed", NULL))
		return bpf_program__set_autoload(obj->progs.folio_mark_accessed, true);

	if (fentry_can_attach("mark_page_accessed", NULL))
		return bpf_program__set_autoload(obj->progs.mark_page_accessed, true);
	
	fprintf(stderr, "failed to attach to access functions\n");
	return -1;
}

static int attach_alloc_ret(struct readahead_bpf *obj)
{
	bpf_program__set_autoload(obj->progs.page_cache_alloc_ret, false);
	bpf_program__set_autoload(obj->progs.filemap_alloc_folio_ret, false);
	bpf_program__set_autoload(obj->progs.filemap_alloc_folio_noprof_ret, false);

	/*
	 * b951aaff5035 ("mm: enable page allocation tagging") in v6.10
	 * renamed filemap_alloc_folio to filemap_alloc_folio_noprof
	 */
	if (fentry_can_attach("filemap_alloc_folio_noprof", NULL))
		return bpf_program__set_autoload(obj->progs.filemap_alloc_folio_noprof_ret, true);

	/*
	 * bb3c579e25e5 ("mm/filemap: Add filemap_alloc_folio") in v5.16
	 * changed __page_cache_alloc to be a wrapper of filemap_alloc_folio
	 */
	if (fentry_can_attach("filemap_alloc_folio", NULL))
		return bpf_program__set_autoload(obj->progs.filemap_alloc_folio_ret, true);

	if (fentry_can_attach("__page_cache_alloc", NULL))
		return bpf_program__set_autoload(obj->progs.page_cache_alloc_ret, true);

	fprintf(stderr, "failed to attach to alloc functions\n");
	return -1;
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

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = readahead_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	err = attach_access(obj);
	if (err)
		goto cleanup;
	err = attach_alloc_ret(obj);
	if (err)
		goto cleanup;
	err = readahead__set_attach_target(obj->progs.do_page_cache_ra);
	if (err)
		goto cleanup;
	err = readahead__set_attach_target(obj->progs.do_page_cache_ra_ret);
	if (err)
		goto cleanup;

	err = readahead_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object\n");
		goto cleanup;
	}

	if (!obj->bss) {
		fprintf(stderr, "Memory-mapping BPF maps is supported starting from Linux 5.7, please upgrade.\n");
		goto cleanup;
	}

	err = readahead_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
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
