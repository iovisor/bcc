// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// Based on biolatency(8) from BCC by Brendan Gregg.
// 15-Jun-2020   Wenbo Zhang   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include "blk_types.h"
#include "biolatency.h"
#include "biolatency.skel.h"
#include "trace_helpers.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

static struct env {
	char *disk;
	int disk_len;
	time_t interval;
	int times;
	bool timestamp;
	bool queued;
	bool per_disk;
	bool per_flag;
	bool milliseconds;
	bool verbose;
} env = {
	.interval = 99999999,
	.times = 99999999,
};

static volatile bool exiting;

const char *argp_program_version = "biolatency 0.1";
const char *argp_program_bug_address = "<ethercflow@gmail.com>";
const char argp_program_doc[] =
	"Summarize block device I/O latency as a histogram.\n"
	"\n"
	"USAGE: biolatency [-h] [-T] [-m] [-Q] [-D] [-F] [-d] [interval] [count]\n"
	"\n"
	"EXAMPLES:\n"
	"    biolatency              # summarize block I/O latency as a histogram\n"
	"    biolatency 1 10         # print 1 second summaries, 10 times\n"
	"    biolatency -mT 1        # 1s summaries, milliseconds, and timestamps\n"
	"    biolatency -Q           # include OS queued time in I/O time\n"
	"    biolatency -D           # show each disk device separately\n"
	"    biolatency -F           # show I/O flags separately\n"
	"    biolatency -d sdc       # Trace sdc only\n";

static const struct argp_option opts[] = {
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output" },
	{ "milliseconds", 'm', NULL, 0, "Millisecond histogram" },
	{ "queued", 'Q', NULL, 0, "Include OS queued time in I/O time" },
	{ "disk", 'D', NULL, 0, "Print a histogram per disk device" },
	{ "flag", 'F', NULL, 0, "Print a histogram per set of I/O flags" },
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
	case 'm':
		env.milliseconds = true;
		break;
	case 'Q':
		env.queued = true;
		break;
	case 'D':
		env.per_disk = true;
		break;
	case 'F':
		env.per_flag = true;
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
		errno = 0;
		if (pos_args == 0) {
			env.interval = strtol(arg, NULL, 10);
			if (errno) {
				fprintf(stderr, "invalid internal\n");
				argp_usage(state);
			}
		} else if (pos_args == 1) {
			env.times = strtol(arg, NULL, 10);
			if (errno) {
				fprintf(stderr, "invalid times\n");
				argp_usage(state);
			}
		} else {
			fprintf(stderr,
				"unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		pos_args++;
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

static void print_cmd_flags(int cmd_flags)
{
	static struct { int bit; const char *str; } flags[] = {
		{ REQ_NOWAIT, "NoWait-" },
		{ REQ_BACKGROUND, "Background-" },
		{ REQ_RAHEAD, "ReadAhead-" },
		{ REQ_PREFLUSH, "PreFlush-" },
		{ REQ_FUA, "FUA-" },
		{ REQ_INTEGRITY, "Integrity-" },
		{ REQ_IDLE, "Idle-" },
		{ REQ_NOMERGE, "NoMerge-" },
		{ REQ_PRIO, "Priority-" },
		{ REQ_META, "Metadata-" },
		{ REQ_SYNC, "Sync-" },
	};
	static const char *ops[] = {
		[REQ_OP_READ] = "Read",
		[REQ_OP_WRITE] = "Write",
		[REQ_OP_FLUSH] = "Flush",
		[REQ_OP_DISCARD] = "Discard",
		[REQ_OP_SECURE_ERASE] = "SecureErase",
		[REQ_OP_ZONE_RESET] = "ZoneReset",
		[REQ_OP_WRITE_SAME] = "WriteSame",
		[REQ_OP_ZONE_RESET_ALL] = "ZoneResetAll",
		[REQ_OP_WRITE_ZEROES] = "WriteZeroes",
		[REQ_OP_ZONE_OPEN] = "ZoneOpen",
		[REQ_OP_ZONE_CLOSE] = "ZoneClose",
		[REQ_OP_ZONE_FINISH] = "ZoneFinish",
		[REQ_OP_SCSI_IN] = "SCSIIn",
		[REQ_OP_SCSI_OUT] = "SCSIOut",
		[REQ_OP_DRV_IN] = "DrvIn",
		[REQ_OP_DRV_OUT] = "DrvOut",
	};
	int i;

	printf("flags = ");

	for (i = 0; i < ARRAY_SIZE(flags); i++) {
		if (cmd_flags & flags[i].bit)
			printf("%s", flags[i].str);
	}

	if ((cmd_flags & REQ_OP_MASK) < ARRAY_SIZE(ops))
		printf("%s", ops[cmd_flags & REQ_OP_MASK]);
	else
		printf("Unknown");
}

static int print_log2_hists(int fd)
{
	struct hist_key lookup_key = { .cmd_flags = -1 }, next_key;
	char *units = env.milliseconds ? "msecs" : "usecs";
	struct hist hist;
	int err;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &hist);
		if (err < 0) {
			fprintf(stderr, "failed to lookup hist: %d\n", err);
			return -1;
		}
		if (env.per_disk)
			printf("\ndisk = %s\t", next_key.disk[0] != '\0' ?
				next_key.disk : "unnamed");
		if (env.per_flag)
			print_cmd_flags(next_key.cmd_flags);
		printf("\n");
		print_log2_hist(hist.slots, MAX_SLOTS, units);
		lookup_key = next_key;
	}

	lookup_key.cmd_flags = -1;
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0) {
			fprintf(stderr, "failed to cleanup hist : %d\n", err);
			return -1;
		}
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
	struct biolatency_bpf *obj;
	struct tm *tm;
	char ts[32];
	time_t t;
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

	obj = biolatency_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF ojbect\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	if (env.disk)
		strncpy((char*)obj->rodata->targ_disk, env.disk, env.disk_len);
	obj->rodata->targ_per_disk = env.per_disk;
	obj->rodata->targ_per_flag = env.per_flag;
	obj->rodata->targ_ms = env.milliseconds;
	obj->rodata->targ_queued = env.queued;

	err = biolatency_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	if (env.queued) {
		obj->links.tp_btf__block_rq_insert =
			bpf_program__attach(obj->progs.tp_btf__block_rq_insert);
		err = libbpf_get_error(obj->links.tp_btf__block_rq_insert);
		if (err) {
			fprintf(stderr, "failed to attach: %s\n", strerror(-err));
			goto cleanup;
		}
	}
	obj->links.tp_btf__block_rq_issue =
		bpf_program__attach(obj->progs.tp_btf__block_rq_issue);
	err = libbpf_get_error(obj->links.tp_btf__block_rq_issue);
	if (err) {
		fprintf(stderr, "failed to attach: %s\n", strerror(-err));
		goto cleanup;
	}
	obj->links.tp_btf__block_rq_complete =
		bpf_program__attach(obj->progs.tp_btf__block_rq_complete);
	err = libbpf_get_error(obj->links.tp_btf__block_rq_complete);
	if (err) {
		fprintf(stderr, "failed to attach: %s\n", strerror(-err));
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	printf("Tracing block device I/O... Hit Ctrl-C to end.\n");

	/* main: poll */
	while (1) {
		sleep(env.interval);
		printf("\n");

		if (env.timestamp) {
			time(&t);
			tm = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);
			printf("%-8s\n", ts);
		}

		err = print_log2_hists(bpf_map__fd(obj->maps.hists));
		if (err)
			break;

		if (exiting || --env.times == 0)
			break;
	}

cleanup:
	biolatency_bpf__destroy(obj);

	return err != 0;
}
