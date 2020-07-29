// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// Based on biosnoop(8) from BCC by Brendan Gregg.
// 29-Jun-2020   Wenbo Zhang   Created this.
#include <argp.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include "blk_types.h"
#include "biosnoop.h"
#include "biosnoop.skel.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100

static struct env {
	char *disk;
	int disk_len;
	int duration;
	bool timestamp;
	bool queued;
	bool verbose;
} env = {};

static volatile __u64 start_ts;

const char *argp_program_version = "biosnoop 0.1";
const char *argp_program_bug_address = "<ethercflow@gmail.com>";
const char argp_program_doc[] =
"Summarize block device I/O latency as a histogram.\n"
"\n"
"USAGE: biosnoop [-h] [-T] [-Q]\n"
"\n"
"EXAMPLES:\n"
"    biosnoop              # summarize block I/O latency as a histogram\n"
"    biosnoop -Q           # include OS queued time in I/O time\n"
"    biosnoop 10           # trace for 10 seconds only\n"
"    biosnoop -d sdc       # trace sdc only\n";

static const struct argp_option opts[] = {
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{ "queued", 'Q', NULL, 0, "Include OS queued time in I/O time" },
	{ "disk",  'd', "DISK",  0, "Trace this disk only" },
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
	case 'Q':
		env.queued = true;
		break;
	case 'd':
		env.disk = arg;
		env.disk_len = strlen(arg) + 1;
		if (env.disk_len > DISK_NAME_LEN) {
			fprintf(stderr, "invaild disk name: too long\n");
			argp_usage(state);
		}
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

static void blk_fill_rwbs(char *rwbs, unsigned int op)
{
	int i = 0;

	if (op & REQ_PREFLUSH)
		rwbs[i++] = 'F';

	switch (op & REQ_OP_MASK) {
	case REQ_OP_WRITE:
	case REQ_OP_WRITE_SAME:
		rwbs[i++] = 'W';
		break;
	case REQ_OP_DISCARD:
		rwbs[i++] = 'D';
		break;
	case REQ_OP_SECURE_ERASE:
		rwbs[i++] = 'D';
		rwbs[i++] = 'E';
		break;
	case REQ_OP_FLUSH:
		rwbs[i++] = 'F';
		break;
	case REQ_OP_READ:
		rwbs[i++] = 'R';
		break;
	default:
		rwbs[i++] = 'N';
	}

	if (op & REQ_FUA)
		rwbs[i++] = 'F';
	if (op & REQ_RAHEAD)
		rwbs[i++] = 'A';
	if (op & REQ_SYNC)
		rwbs[i++] = 'S';
	if (op & REQ_META)
		rwbs[i++] = 'M';

	rwbs[i] = '\0';
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;
	char rwbs[RWBS_LEN];

	if (!start_ts)
		start_ts = e->ts;
	blk_fill_rwbs(rwbs, e->cmd_flags);
	printf("%-11.6f %-14.14s %-6d %-7s %-4s %-10lld %-7d ",
		(e->ts - start_ts) / 1000000000.0,
		e->comm, e->pid, e->disk, rwbs, e->sector, e->len);
	if (env.queued)
		printf("%7.3f ", e->qdelta != -1 ?
			e->qdelta / 1000000.0 : -1);
	printf("%7.3f\n", e->delta / 1000000.0);
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct perf_buffer_opts pb_opts;
	struct perf_buffer *pb = NULL;
	struct ksyms *ksyms = NULL;
	struct biosnoop_bpf *obj;
	__u64 time_end = 0;
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

	obj = biosnoop_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF ojbect\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	if (env.disk)
		strncpy((char*)obj->rodata->targ_disk, env.disk, env.disk_len);
	obj->rodata->targ_queued = env.queued;

	err = biosnoop_bpf__load(obj);
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
	if (env.queued) {
		obj->links.tp_btf__block_rq_insert =
			bpf_program__attach(obj->progs.tp_btf__block_rq_insert);
		err = libbpf_get_error(obj->links.tp_btf__block_rq_insert);
		if (err) {
			fprintf(stderr, "failed to attach block_rq_insert: %s\n",
				strerror(err));
			goto cleanup;
		}
	}
	obj->links.tp_btf__block_rq_issue =
		bpf_program__attach(obj->progs.tp_btf__block_rq_issue);
	err = libbpf_get_error(obj->links.tp_btf__block_rq_issue);
	if (err) {
		fprintf(stderr, "failed to attach block_rq_issue: %s\n",
			strerror(err));
		goto cleanup;
	}
	obj->links.tp_btf__block_rq_complete =
		bpf_program__attach(obj->progs.tp_btf__block_rq_complete);
	err = libbpf_get_error(obj->links.tp_btf__block_rq_complete);
	if (err) {
		fprintf(stderr, "failed to attach block_rq_complete: %s\n",
			strerror(err));
		goto cleanup;
	}

	pb_opts.sample_cb = handle_event;
	pb_opts.lost_cb = handle_lost_events;
	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			&pb_opts);
	err = libbpf_get_error(pb);
	if (err) {
		pb = NULL;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	printf("%-11s %-14s %-6s %-7s %-4s %-10s %-7s ",
		"TIME(s)", "COMM", "PID", "DISK", "T", "SECTOR", "BYTES");
	if (env.queued)
		printf("%7s ", "QUE(ms)");
	printf("%7s\n", "LAT(ms)");

	/* setup duration */
	if (env.duration)
		time_end = get_ktime_ns() + env.duration * NSEC_PER_SEC;

	/* main: poll */
	while (1) {
		if ((err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS)) < 0)
			break;
		if (env.duration && get_ktime_ns() > time_end)
			goto cleanup;
	}
	printf("error polling perf buffer: %d\n", err);

cleanup:
	biosnoop_bpf__destroy(obj);
	ksyms__free(ksyms);

	return err != 0;
}
