/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * fsdist  Summarize file system operations latency.
 *
 * Copyright (c) 2021 Wenbo Zhang
 * Copyright (c) 2021 Hengqi Chen
 *
 * Based on ext4dist(8) from BCC by Brendan Gregg.
 * 9-Feb-2021   Wenbo Zhang   Created this.
 * 20-May-2021   Hengqi Chen  Migrated to fsdist.
 * 27-Oct-2023   Pcheng Cui   Add support for F2FS.
 */
#include <argp.h>
#include <libgen.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "fsdist.h"
#include "fsdist.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

enum fs_type {
	NONE,
	BTRFS,
	EXT4,
	NFS,
	XFS,
	F2FS,
	BCACHEFS,
	ZFS,
};

static struct fs_config {
	const char *fs;
	const char *op_funcs[F_MAX_OP];
} fs_configs[] = {
	[BTRFS] = { "btrfs", {
		[F_READ] = "btrfs_file_read_iter",
		[F_WRITE] = "btrfs_file_write_iter",
		[F_OPEN] = "btrfs_file_open",
		[F_FSYNC] = "btrfs_sync_file",
		[F_GETATTR] = NULL, /* not supported */
	}},
	[EXT4] = { "ext4", {
		[F_READ] = "ext4_file_read_iter",
		[F_WRITE] = "ext4_file_write_iter",
		[F_OPEN] = "ext4_file_open",
		[F_FSYNC] = "ext4_sync_file",
		[F_GETATTR] = "ext4_file_getattr",
	}},
	[NFS] = { "nfs", {
		[F_READ] = "nfs_file_read",
		[F_WRITE] = "nfs_file_write",
		[F_OPEN] = "nfs_file_open",
		[F_FSYNC] = "nfs_file_fsync",
		[F_GETATTR] = "nfs_getattr",
	}},
	[XFS] = { "xfs", {
		[F_READ] = "xfs_file_read_iter",
		[F_WRITE] = "xfs_file_write_iter",
		[F_OPEN] = "xfs_file_open",
		[F_FSYNC] = "xfs_file_fsync",
		[F_GETATTR] = NULL, /* not supported */
	}},
	[F2FS] = { "f2fs", {
		[F_READ] = "f2fs_file_read_iter",
		[F_WRITE] = "f2fs_file_write_iter",
		[F_OPEN] = "f2fs_file_open",
		[F_FSYNC] = "f2fs_sync_file",
		[F_GETATTR] = "f2fs_getattr",
	}},
	[BCACHEFS] = { "bcachefs", {
		[F_READ] = "bch2_read_iter",
		[F_WRITE] = "bch2_write_iter",
		[F_OPEN] = "bch2_open",
		[F_FSYNC] = "bch2_fsync",
		[F_GETATTR] = "bch2_getattr",
	}},
	[ZFS] = { "zfs", {
		[F_READ] = "zpl_iter_read",
		[F_WRITE] = "zpl_iter_write",
		[F_OPEN] = "zpl_open",
		[F_FSYNC] = "zpl_fsync",
		[F_GETATTR] = NULL, /* not supported */
	}},
};

static char *file_op_names[] = {
	[F_READ] = "read",
	[F_WRITE] = "write",
	[F_OPEN] = "open",
	[F_FSYNC] = "fsync",
	[F_GETATTR] = "getattr",
};

static struct hist zero;
static volatile sig_atomic_t exiting;

/* options */
static enum fs_type fs_type = NONE;
static bool emit_timestamp = false;
static bool timestamp_in_ms = false;
static pid_t target_pid = 0;
static int interval = 99999999;
static int count = 99999999;
static bool verbose = false;

const char *argp_program_version = "fsdist 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Summarize file system operations latency.\n"
"\n"
"Usage: fsdist [-h] [-t] [-T] [-m] [-p PID] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    fsdist -t ext4             # show ext4 operations latency as a histogram\n"
"    fsdist -t nfs -p 1216      # trace nfs operations with PID 1216 only\n"
"    fsdist -t xfs 1 10         # trace xfs operations, 1s summaries, 10 times\n"
"    fsdist -t btrfs -m 5       # trace btrfs operation, 5s summaries, in ms\n";

static const struct argp_option opts[] = {
	{ "timestamp", 'T', NULL, 0, "Print timestamp", 0 },
	{ "milliseconds", 'm', NULL, 0, "Millisecond histogram", 0 },
	{ "pid", 'p', "PID", 0, "Process ID to trace", 0 },
	{ "type", 't', "Filesystem", 0, "Which filesystem to trace, [btrfs/ext4/nfs/xfs/f2fs/bcachefs/zfs]", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'v':
		verbose = true;
		break;
	case 'T':
		emit_timestamp = true;
		break;
	case 'm':
		timestamp_in_ms = true;
		break;
	case 't':
		if (!strcmp(arg, "btrfs")) {
			fs_type = BTRFS;
		} else if (!strcmp(arg, "ext4")) {
			fs_type = EXT4;
		} else if (!strcmp(arg, "nfs")) {
			fs_type = NFS;
		} else if (!strcmp(arg, "xfs")) {
			fs_type = XFS;
		} else if (!strcmp(arg, "f2fs")) {
			fs_type = F2FS;
		} else if (!strcmp(arg, "bcachefs")) {
			fs_type = BCACHEFS;
		} else if (!strcmp(arg, "zfs")) {
			fs_type = ZFS;
		} else {
			warn("invalid filesystem\n");
			argp_usage(state);
		}
		break;
	case 'p':
		errno = 0;
		target_pid = strtol(arg, NULL, 10);
		if (errno || target_pid <= 0) {
			warn("invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0) {
			interval = strtol(arg, NULL, 10);
			if (errno) {
				warn("invalid internal\n");
				argp_usage(state);
			}
		} else if (pos_args == 1) {
			count = strtol(arg, NULL, 10);
			if (errno) {
				warn("invalid count\n");
				argp_usage(state);
			}
		} else {
			warn("unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		pos_args++;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static void alias_parse(char *prog)
{
	char *name = basename(prog);

	if (strstr(name, "btrfsdist")) {
		fs_type = BTRFS;
	} else if (strstr(name, "ext4dist")) {
		fs_type = EXT4;
	} else if (strstr(name, "nfsdist")) {
		fs_type = NFS;
	} else if (strstr(name, "xfsdist")) {
		fs_type = XFS;
	} else if (strstr(name, "f2fsdist")){
		fs_type = F2FS;
	} else if (strstr(name, "bcachefsdist")){
		fs_type = BCACHEFS;
	} else if (strstr(name, "zfsdist")) {
		fs_type = ZFS;
	}
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = 1;
}

static int print_hists(struct fsdist_bpf__bss *bss)
{
	const char *units = timestamp_in_ms ? "msecs" : "usecs";
	enum fs_file_op op;

	for (op = F_READ; op < F_MAX_OP; op++) {
		struct hist hist = bss->hists[op];

		bss->hists[op] = zero;
		if (!memcmp(&zero, &hist, sizeof(hist)))
			continue;
		printf("operation = '%s'\n", file_op_names[op]);
		print_log2_hist(hist.slots, MAX_SLOTS, units);
		printf("\n");
	}
	return 0;
}

static bool check_fentry()
{
	int i;
	const char *fn_name, *module;
	bool support_fentry = true;

	for (i = 0; i < F_MAX_OP; i++) {
		fn_name = fs_configs[fs_type].op_funcs[i];
		module = fs_configs[fs_type].fs;
		if (fn_name && !fentry_can_attach(fn_name, module)) {
			support_fentry = false;
			break;
		}
	}
	return support_fentry;
}

static int fentry_set_attach_target(struct fsdist_bpf *obj)
{
	struct fs_config *cfg = &fs_configs[fs_type];
	int err = 0;

	err = err ?: bpf_program__set_attach_target(obj->progs.file_read_fentry, 0, cfg->op_funcs[F_READ]);
	err = err ?: bpf_program__set_attach_target(obj->progs.file_read_fexit, 0, cfg->op_funcs[F_READ]);
	err = err ?: bpf_program__set_attach_target(obj->progs.file_write_fentry, 0, cfg->op_funcs[F_WRITE]);
	err = err ?: bpf_program__set_attach_target(obj->progs.file_write_fexit, 0, cfg->op_funcs[F_WRITE]);
	err = err ?: bpf_program__set_attach_target(obj->progs.file_open_fentry, 0, cfg->op_funcs[F_OPEN]);
	err = err ?: bpf_program__set_attach_target(obj->progs.file_open_fexit, 0, cfg->op_funcs[F_OPEN]);
	err = err ?: bpf_program__set_attach_target(obj->progs.file_sync_fentry, 0, cfg->op_funcs[F_FSYNC]);
	err = err ?: bpf_program__set_attach_target(obj->progs.file_sync_fexit, 0, cfg->op_funcs[F_FSYNC]);
	if (cfg->op_funcs[F_GETATTR]) {
		err = err ?: bpf_program__set_attach_target(obj->progs.getattr_fentry, 0, cfg->op_funcs[F_GETATTR]);
		err = err ?: bpf_program__set_attach_target(obj->progs.getattr_fexit, 0, cfg->op_funcs[F_GETATTR]);
	} else {
		bpf_program__set_autoload(obj->progs.getattr_fentry, false);
		bpf_program__set_autoload(obj->progs.getattr_fexit, false);
	}
	return err;
}

static void disable_fentry(struct fsdist_bpf *obj)
{
	bpf_program__set_autoload(obj->progs.file_read_fentry, false);
	bpf_program__set_autoload(obj->progs.file_read_fexit, false);
	bpf_program__set_autoload(obj->progs.file_write_fentry, false);
	bpf_program__set_autoload(obj->progs.file_write_fexit, false);
	bpf_program__set_autoload(obj->progs.file_open_fentry, false);
	bpf_program__set_autoload(obj->progs.file_open_fexit, false);
	bpf_program__set_autoload(obj->progs.file_sync_fentry, false);
	bpf_program__set_autoload(obj->progs.file_sync_fexit, false);
	bpf_program__set_autoload(obj->progs.getattr_fentry, false);
	bpf_program__set_autoload(obj->progs.getattr_fexit, false);
}

static void disable_kprobes(struct fsdist_bpf *obj)
{
	bpf_program__set_autoload(obj->progs.file_read_entry, false);
	bpf_program__set_autoload(obj->progs.file_read_exit, false);
	bpf_program__set_autoload(obj->progs.file_write_entry, false);
	bpf_program__set_autoload(obj->progs.file_write_exit, false);
	bpf_program__set_autoload(obj->progs.file_open_entry, false);
	bpf_program__set_autoload(obj->progs.file_open_exit, false);
	bpf_program__set_autoload(obj->progs.file_sync_entry, false);
	bpf_program__set_autoload(obj->progs.file_sync_exit, false);
	bpf_program__set_autoload(obj->progs.getattr_entry, false);
	bpf_program__set_autoload(obj->progs.getattr_exit, false);
}

static int attach_kprobes(struct fsdist_bpf *obj)
{
	long err = 0;
	struct fs_config *cfg = &fs_configs[fs_type];

	/* F_READ */
	obj->links.file_read_entry = bpf_program__attach_kprobe(obj->progs.file_read_entry, false, cfg->op_funcs[F_READ]);
	if (!obj->links.file_read_entry)
		goto errout;
	obj->links.file_read_exit = bpf_program__attach_kprobe(obj->progs.file_read_exit, true, cfg->op_funcs[F_READ]);
	if (!obj->links.file_read_exit)
		goto errout;
	/* F_WRITE */
	obj->links.file_write_entry = bpf_program__attach_kprobe(obj->progs.file_write_entry, false, cfg->op_funcs[F_WRITE]);
	if (!obj->links.file_write_entry)
		goto errout;
	obj->links.file_write_exit = bpf_program__attach_kprobe(obj->progs.file_write_exit, true, cfg->op_funcs[F_WRITE]);
	if (!obj->links.file_write_exit)
		goto errout;
	/* F_OPEN */
	obj->links.file_open_entry = bpf_program__attach_kprobe(obj->progs.file_open_entry, false, cfg->op_funcs[F_OPEN]);
	if (!obj->links.file_open_entry)
		goto errout;
	obj->links.file_open_exit = bpf_program__attach_kprobe(obj->progs.file_open_exit, true, cfg->op_funcs[F_OPEN]);
	if (!obj->links.file_open_exit)
		goto errout;
	/* F_FSYNC */
	obj->links.file_sync_entry = bpf_program__attach_kprobe(obj->progs.file_sync_entry, false, cfg->op_funcs[F_FSYNC]);
	if (!obj->links.file_sync_entry)
		goto errout;
	obj->links.file_sync_exit = bpf_program__attach_kprobe(obj->progs.file_sync_exit, true, cfg->op_funcs[F_FSYNC]);
	if (!obj->links.file_sync_exit)
		goto errout;
	/* F_GETATTR */
	if (!cfg->op_funcs[F_GETATTR])
		return 0;
	obj->links.getattr_entry = bpf_program__attach_kprobe(obj->progs.getattr_entry, false, cfg->op_funcs[F_GETATTR]);
	if (!obj->links.getattr_entry)
		goto errout;
	obj->links.getattr_exit = bpf_program__attach_kprobe(obj->progs.getattr_exit, true, cfg->op_funcs[F_GETATTR]);
	if (!obj->links.getattr_exit)
		goto errout;
	return 0;
errout:
	err = -errno;
	warn("failed to attach kprobe: %ld\n", err);
	return err;
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct fsdist_bpf *skel;
	struct tm *tm;
	char ts[32];
	time_t t;
	int err;
	bool support_fentry;

	alias_parse(argv[0]);
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;
	if (fs_type == NONE) {
		warn("filesystem must be specified using -t option.\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	skel = fsdist_bpf__open_opts(&open_opts);
	if (!skel) {
		warn("failed to open BPF object\n");
		return 1;
	}

	skel->rodata->target_pid = target_pid;
	skel->rodata->in_ms = timestamp_in_ms;

	/*
	 * before load
	 * if fentry is supported, we set attach target and disable kprobes
	 * otherwise, we disable fentry and attach kprobes after loading
	 */
	support_fentry = check_fentry();
	if (support_fentry) {
		err = fentry_set_attach_target(skel);
		if (err) {
			warn("failed to set attach target: %d\n", err);
			goto cleanup;
		}
		disable_kprobes(skel);
	} else {
		disable_fentry(skel);
	}

	err = fsdist_bpf__load(skel);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	/*
	 * after load
	 * if fentry is supported, let libbpf do auto load
	 * otherwise, we attach to kprobes manually
	 */
	err = support_fentry ? fsdist_bpf__attach(skel) : attach_kprobes(skel);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	printf("Tracing %s operation latency... Hit Ctrl-C to end.\n",
	       fs_configs[fs_type].fs);

	while (1) {
		sleep(interval);
		printf("\n");

		if (emit_timestamp) {
			time(&t);
			tm = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);
			printf("%-8s\n", ts);
		}

		err = print_hists(skel->bss);
		if (err)
			break;

		if (exiting || --count == 0)
			break;
	}

cleanup:
	fsdist_bpf__destroy(skel);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
