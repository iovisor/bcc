// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

/*
 * biotop Trace block I/O by process.
 * Copyright (c) 2022 Francis Laniel <flaniel@linux.microsoft.com>
 *
 * Based on biotop(8) from BCC by Brendan Gregg.
 * 03-Mar-2022   Francis Laniel   Created this.
 * 23-Nov-2023   Pcheng Cui       Add PID filter support.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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
#include "biotop.h"
#include "biotop.skel.h"
#include "compat.h"
#include "trace_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)
#define OUTPUT_ROWS_LIMIT 10240

enum SORT {
	ALL,
	IO,
	BYTES,
	TIME,
};

struct disk {
	int major;
	int minor;
	char name[256];
};

struct vector {
	size_t nr;
	size_t capacity;
	void **elems;
};

int grow_vector(struct vector *vector) {
	if (vector->nr >= vector->capacity) {
		void **reallocated;

		if (!vector->capacity)
			vector->capacity = 1;
		else
			vector->capacity *= 2;

		reallocated = libbpf_reallocarray(vector->elems, vector->capacity, sizeof(*vector->elems));
		if (!reallocated)
			return -1;

		vector->elems = reallocated;
	}

	return 0;
}

void free_vector(struct vector vector) {
	for (size_t i = 0; i < vector.nr; i++)
		if (vector.elems[i] != NULL)
			free(vector.elems[i]);
	free(vector.elems);
}

struct vector disks = {};

static volatile sig_atomic_t exiting = 0;

static bool clear_screen = true;
static int output_rows = 20;
static int sort_by = ALL;
static int interval = 1;
static int count = 99999999;
static pid_t target_pid = 0;
static bool verbose = false;

const char *argp_program_version = "biotop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace file reads/writes by process.\n"
"\n"
"USAGE: biotop [-h] [interval] [count] [-p PID]\n"
"\n"
"EXAMPLES:\n"
"    biotop            # file I/O top, refresh every 1s\n"
"    biotop 5 10       # 5s summaries, 10 times\n"
"    biotop -p 181     # only trace PID 1216\n";

static const struct argp_option opts[] = {
	{ "noclear", 'C', NULL, 0, "Don't clear the screen", 0 },
	{ "sort", 's', "SORT", 0, "Sort columns, default all [all, io, bytes, time]", 0 },
	{ "rows", 'r', "ROWS", 0, "Maximum rows to print, default 20", 0 },
	{ "pid", 'p', "PID", 0, "Process ID to trace", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long rows, pid;
	static int pos_args;

	switch (key) {
	case 'C':
		clear_screen = false;
		break;
	case 's':
		if (!strcmp(arg, "all")) {
			sort_by = ALL;
		} else if (!strcmp(arg, "io")) {
			sort_by = IO;
		} else if (!strcmp(arg, "bytes")) {
			sort_by = BYTES;
		} else if (!strcmp(arg, "time")) {
			sort_by = TIME;
		} else {
			warn("invalid sort method: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'r':
		errno = 0;
		rows = strtol(arg, NULL, 10);
		if (errno || rows <= 0) {
			warn("invalid rows: %s\n", arg);
			argp_usage(state);
		}
		output_rows = rows;
		if (output_rows > OUTPUT_ROWS_LIMIT)
			output_rows = OUTPUT_ROWS_LIMIT;
		break;
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			warn("Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		target_pid = pid;
		break;
	case 'v':
		verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0) {
			interval = strtol(arg, NULL, 10);
			if (errno || interval <= 0) {
				warn("invalid interval\n");
				argp_usage(state);
			}
		} else if (pos_args == 1) {
			count = strtol(arg, NULL, 10);
			if (errno || count <= 0) {
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

struct data_t {
	struct info_t key;
	struct val_t value;
};

static int sort_column(const void *obj1, const void *obj2)
{
	struct data_t *d1 = (struct data_t *) obj1;
	struct data_t *d2 = (struct data_t *) obj2;

	struct val_t *s1 = &d1->value;
	struct val_t *s2 = &d2->value;

	if (sort_by == IO)
		return s2->io - s1->io;
	else if (sort_by == BYTES)
		return s2->bytes - s1->bytes;
	else if (sort_by == TIME)
		return s2->us - s1->us;
	else
		return (s2->io + s2->bytes + s2->us)
			- (s1->io + s1->bytes + s1->us);
}

static void parse_disk_stat(void)
{
	FILE *fp;
	char *line;
	size_t zero;

	fp = fopen("/proc/diskstats", "r");
	if (!fp)
		return;

	zero = 0;
	while (getline(&line, &zero, fp) != -1) {
		struct disk disk;

		if (sscanf(line, "%d %d %s", &disk.major, &disk.minor, disk.name) != 3)
			continue;

		if (grow_vector(&disks) == -1)
			goto err;

		disks.elems[disks.nr] = malloc(sizeof(disk));
		if (!disks.elems[disks.nr])
			goto err;

		memcpy(disks.elems[disks.nr], &disk, sizeof(disk));

		disks.nr++;
	}

	free(line);
	fclose(fp);

	return;
err:
	fprintf(stderr, "realloc or malloc failed\n");

	free_vector(disks);
}

static char *search_disk_name(int major, int minor)
{
	for (size_t i = 0; i < disks.nr; i++) {
		struct disk *diskp;

		if (!disks.elems[i])
			continue;

		diskp = (struct disk *) disks.elems[i];
		if (diskp->major == major && diskp->minor == minor)
			return diskp->name;
	}

	return "";
}

static int print_stat(struct biotop_bpf *obj)
{
	FILE *f;
	time_t t;
	struct tm *tm;
	char ts[16], buf[256];
	struct info_t *prev_key = NULL;
	static struct data_t datas[OUTPUT_ROWS_LIMIT];
	int n, i, err = 0, rows = 0;
	int fd = bpf_map__fd(obj->maps.counts);

	f = fopen("/proc/loadavg", "r");
	if (f) {
		time(&t);
		tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		memset(buf, 0, sizeof(buf));
		n = fread(buf, 1, sizeof(buf), f);
		if (n)
			printf("%8s loadavg: %s\n", ts, buf);
		fclose(f);
	}
	printf("%-7s %-16s %1s %-3s %-3s %-8s %5s %7s %6s\n",
	       "PID", "COMM", "D", "MAJ", "MIN", "DISK", "I/O", "Kbytes", "AVGms");

	while (1) {
		err = bpf_map_get_next_key(fd, prev_key, &datas[rows].key);
		if (err) {
			if (errno == ENOENT) {
				err = 0;
				break;
			}
			warn("bpf_map_get_next_key failed: %s\n", strerror(errno));
			return err;
		}
		err = bpf_map_lookup_elem(fd, &datas[rows].key, &datas[rows].value);
		if (err) {
			warn("bpf_map_lookup_elem failed: %s\n", strerror(errno));
			return err;
		}
		prev_key = &datas[rows].key;
		rows++;
	}

	qsort(datas, rows, sizeof(struct data_t), sort_column);
	rows = rows < output_rows ? rows : output_rows;
	for (i = 0; i < rows; i++) {
		int major;
		int minor;
		struct info_t *key = &datas[i].key;
		struct val_t *value = &datas[i].value;
		float avg_ms = 0;

		/* To avoid floating point exception. */
		if (value->io)
			avg_ms = ((float) value->us) / 1000 / value->io;

		major = key->major;
		minor = key->minor;

		printf("%-7d %-16s %1s %-3d %-3d %-8s %5d %7lld %6.2f\n",
		       key->pid, key->name, key->rwflag ? "W": "R",
		       major, minor, search_disk_name(major, minor),
		       value->io, value->bytes / 1024, avg_ms);
	}

	printf("\n");
	prev_key = NULL;

	while (1) {
		struct info_t key;

		err = bpf_map_get_next_key(fd, prev_key, &key);
		if (err) {
			if (errno == ENOENT) {
				err = 0;
				break;
			}
			warn("bpf_map_get_next_key failed: %s\n", strerror(errno));
			return err;
		}
		err = bpf_map_delete_elem(fd, &key);
		if (err) {
			warn("bpf_map_delete_elem failed: %s\n", strerror(errno));
			return err;
		}
		prev_key = &key;
	}
	return err;
}

static bool has_block_io_tracepoints(void)
{
	return tracepoint_exists("block", "block_io_start") &&
		tracepoint_exists("block", "block_io_done");
}

static void disable_block_io_tracepoints(struct biotop_bpf *obj)
{
	bpf_program__set_autoload(obj->progs.block_io_start, false);
	bpf_program__set_autoload(obj->progs.block_io_done, false);
}

static void disable_blk_account_io_kprobes(struct biotop_bpf *obj)
{
	bpf_program__set_autoload(obj->progs.blk_account_io_start, false);
	bpf_program__set_autoload(obj->progs.blk_account_io_done, false);
	bpf_program__set_autoload(obj->progs.__blk_account_io_start, false);
	bpf_program__set_autoload(obj->progs.__blk_account_io_done, false);
}

static void blk_account_io_set_autoload(struct biotop_bpf *obj,
					struct ksyms *ksyms)
{
	if (!ksyms__get_symbol(ksyms, "__blk_account_io_start")) {
		bpf_program__set_autoload(obj->progs.__blk_account_io_start, false);
		bpf_program__set_autoload(obj->progs.__blk_account_io_done, false);
	} else {
		bpf_program__set_autoload(obj->progs.blk_account_io_start, false);
		bpf_program__set_autoload(obj->progs.blk_account_io_done, false);
	}
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct biotop_bpf *obj;
	struct ksyms *ksyms;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = biotop_bpf__open();
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->target_pid = target_pid;

	parse_disk_stat();

	ksyms = ksyms__load();
	if (!ksyms) {
		err = -ENOMEM;
		warn("failed to load kallsyms\n");
		goto cleanup;
	}

	if (has_block_io_tracepoints())
		disable_blk_account_io_kprobes(obj);
	else {
		disable_block_io_tracepoints(obj);
		blk_account_io_set_autoload(obj, ksyms);
	}

	err = biotop_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = biotop_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	while (1) {
		sleep(interval);

		if (clear_screen) {
			err = system("clear");
			if (err)
				goto cleanup;
		}

		err = print_stat(obj);
		if (err)
			goto cleanup;

		count--;
		if (exiting || !count)
			goto cleanup;
	}

cleanup:
	ksyms__free(ksyms);
	free_vector(disks);
	biotop_bpf__destroy(obj);

	return err != 0;
}
