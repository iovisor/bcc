// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Anton Protopopov
//
// Based on syscount(8) from BCC by Sasha Goldshtein
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <argp.h>
#include <bpf/bpf.h>
#include "syscount.h"
#include "syscount.skel.h"
#include "errno_helpers.h"
#include "syscall_helpers.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

/* This structure extends data_t by adding a key item which should be sorted
 * together with the count and total_ns fields */
struct data_ext_t {
	__u64 count;
	__u64 total_ns;
	char comm[TASK_COMM_LEN];
	__u32 key;
};


#define warn(...) fprintf(stderr, __VA_ARGS__)

const char *argp_program_version = "syscount 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
static const char argp_program_doc[] =
"\nsyscount: summarize syscall counts and latencies\n"
"\n"
"EXAMPLES:\n"
"    syscount                 # print top 10 syscalls by count every second\n"
"    syscount -p $(pidof dd)  # look only at a particular process\n"
"    syscount -L              # measure and sort output by latency\n"
"    syscount -P              # group statistics by pid, not by syscall\n"
"    syscount -x -i 5         # count only failed syscalls\n"
"    syscount -e ENOENT -i 5  # count only syscalls failed with a given errno\n"
"    syscount -c CG           # Trace process under cgroupsPath CG\n";
;

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "pid", 'p', "PID", 0, "Process PID to trace", 0 },
	{ "interval", 'i', "INTERVAL", 0, "Print summary at this interval"
				" (seconds), 0 for infinite wait (default)", 0 },
	{ "duration", 'd', "DURATION", 0, "Total tracing duration (seconds)", 0 },
	{ "top", 'T', "TOP", 0, "Print only the top syscalls (default 10)", 0 },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified/<CG>", 0, "Trace process in cgroup path", 0 },
	{ "failures", 'x', NULL, 0, "Trace only failed syscalls", 0 },
	{ "latency", 'L', NULL, 0, "Collect syscall latency", 0 },
	{ "milliseconds", 'm', NULL, 0, "Display latency in milliseconds"
					" (default: microseconds)", 0 },
	{ "process", 'P', NULL, 0, "Count by process and not by syscall", 0 },
	{ "errno", 'e', "ERRNO", 0, "Trace only syscalls that return this error"
				 "(numeric or EPERM, etc.)", 0 },
	{ "list", 'l', NULL, 0, "Print list of recognized syscalls and exit", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static struct env {
	bool list_syscalls;
	bool milliseconds;
	bool failures;
	bool verbose;
	bool latency;
	bool process;
	int filter_errno;
	int interval;
	int duration;
	int top;
	pid_t pid;
	char *cgroupspath;
	bool cg;
} env = {
	.top = 10,
};

static int get_int(const char *arg, int *ret, int min, int max)
{
	char *end;
	long val;

	errno = 0;
	val = strtol(arg, &end, 10);
	if (errno) {
		warn("strtol: %s: %s\n", arg, strerror(errno));
		return -1;
	} else if (end == arg || val < min || val > max) {
		return -1;
	}
	if (ret)
		*ret = val;
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;

	return vfprintf(stderr, format, args);
}

static int compar_count(const void *dx, const void *dy)
{
	__u64 x = ((struct data_ext_t *) dx)->count;
	__u64 y = ((struct data_ext_t *) dy)->count;
	return x > y ? -1 : !(x == y);
}

static int compar_latency(const void *dx, const void *dy)
{
	__u64 x = ((struct data_ext_t *) dx)->total_ns;
	__u64 y = ((struct data_ext_t *) dy)->total_ns;
	return x > y ? -1 : !(x == y);
}

static const char *agg_col(struct data_ext_t *val, char *buf, size_t size)
{
	if (env.process) {
		snprintf(buf, size, "%-6u %-15s", val->key, val->comm);
	} else {
		syscall_name(val->key, buf, size);
	}
	return buf;
}

static const char *agg_colname(void)
{
	return (env.process) ? "PID    COMM" : "SYSCALL";
}

static const char *time_colname(void)
{
	return (env.milliseconds) ? "TIME (ms)" : "TIME (us)";
}

static void print_latency_header(void)
{
	printf("%-22s %8s %16s\n", agg_colname(), "COUNT", time_colname());
}

static void print_count_header(void)
{
	printf("%-22s %8s\n", agg_colname(), "COUNT");
}

static void print_latency(struct data_ext_t *vals, size_t count)
{
	double div = env.milliseconds ? 1000000.0 : 1000.0;
	char buf[2 * TASK_COMM_LEN];
	int i;

	print_latency_header();
	for (i = 0; i < count && i < env.top; i++)
		printf("%-22s %8llu %16.3lf\n",
		       agg_col(&vals[i], buf, sizeof(buf)),
		       vals[i].count, vals[i].total_ns / div);
	printf("\n");
}

static void print_count(struct data_ext_t *vals, size_t count)
{
	char buf[2 * TASK_COMM_LEN];
	int i;

	print_count_header();
	for (i = 0; i < count && i < env.top; i++)
		printf("%-22s %8llu\n",
		       agg_col(&vals[i], buf, sizeof(buf)), vals[i].count);
	printf("\n");
}

static void print_timestamp()
{
	time_t now = time(NULL);
	struct tm tm;

	if (localtime_r(&now, &tm))
		printf("[%02d:%02d:%02d]\n", tm.tm_hour, tm.tm_min, tm.tm_sec);
	else
		warn("localtime_r: %s", strerror(errno));
}

static bool batch_map_ops = true; /* hope for the best */

static int read_vals_batch(int fd, struct data_ext_t *vals, __u32 *count)
{
	struct data_t orig_vals[*count];
	void *in = NULL, *out;
	__u32 i, n, n_read = 0;
	__u32 keys[*count];
	int err = 0;

	while (n_read < *count && !err) {
		n = *count - n_read;
		err = bpf_map_lookup_and_delete_batch(fd, &in, &out,
				keys + n_read, orig_vals + n_read, &n, NULL);
		if (err < 0 && err != -ENOENT) {
			/* we want to propagate EINVAL upper, so that
			 * the batch_map_ops flag is set to false */
			if (err != -EINVAL)
				warn("bpf_map_lookup_and_delete_batch: %s\n",
				     strerror(-err));
			return err;
		}
		n_read += n;
		in = out;
	}

	for (i = 0; i < n_read; i++) {
		vals[i].count = orig_vals[i].count;
		vals[i].total_ns = orig_vals[i].total_ns;
		vals[i].key = keys[i];
		strncpy(vals[i].comm, orig_vals[i].comm, TASK_COMM_LEN);
	}

	*count = n_read;
	return 0;
}

static bool read_vals(int fd, struct data_ext_t *vals, __u32 *count)
{
	__u32 keys[MAX_ENTRIES];
	struct data_t val;
	__u32 key = -1;
	__u32 next_key;
	int i = 0, j;
	int err;

	if (batch_map_ops) {
		err = read_vals_batch(fd, vals, count);
		if (err < 0 && err == -EINVAL) {
			/* fall back to a racy variant */
			batch_map_ops = false;
		} else {
			return err >= 0;
		}
	}

	if (!vals || !count || !*count)
		return true;

	for (key = -1; i < *count; ) {
		err = bpf_map_get_next_key(fd, &key, &next_key);
		if (err && errno != ENOENT) {
			warn("failed to get next key: %s\n", strerror(errno));
			return false;
		} else if (err) {
			break;
		}
		key = keys[i++] = next_key;
	}

	for (j = 0; j < i; j++) {
		err = bpf_map_lookup_elem(fd, &keys[j], &val);
		if (err && errno != ENOENT) {
			warn("failed to lookup element: %s\n", strerror(errno));
			return false;
		}
		vals[j].count = val.count;
		vals[j].total_ns = val.total_ns;
		vals[j].key = keys[j];
		memcpy(vals[j].comm, val.comm, TASK_COMM_LEN);
	}

	/* There is a race here: system calls which are represented by keys
	 * above and happened between lookup and delete will be ignored.  This
	 * will be fixed in future by using bpf_map_lookup_and_delete_batch,
	 * but this function is too fresh to use it in bcc. */

	for (j = 0; j < i; j++) {
		err = bpf_map_delete_elem(fd, &keys[j]);
		if (err) {
			warn("failed to delete element: %s\n", strerror(errno));
			return false;
		}
	}

	*count = i;
	return true;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	int number;
	int err;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'x':
		env.failures = true;
		break;
	case 'L':
		env.latency = true;
		break;
	case 'm':
		env.milliseconds = true;
		break;
	case 'P':
		env.process = true;
		break;
	case 'p':
		err = get_int(arg, &env.pid, 1, INT_MAX);
		if (err) {
			warn("invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'i':
		err = get_int(arg, &env.interval, 0, INT_MAX);
		if (err) {
			warn("invalid INTERVAL: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'd':
		err = get_int(arg, &env.duration, 1, INT_MAX);
		if (err) {
			warn("invalid DURATION: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'T':
		err = get_int(arg, &env.top, 1, INT_MAX);
		if (err) {
			warn("invalid TOP: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'c':
		env.cgroupspath = arg;
		env.cg = true;
		break;
	case 'e':
		err = get_int(arg, &number, 1, INT_MAX);
		if (err) {
			number = errno_by_name(arg);
			if (number < 0) {
				warn("invalid errno: %s (bad, or can't "
				     "parse dynamically; consider using "
				     "numeric value and/or installing the "
				     "errno program from moreutils)\n", arg);
				argp_usage(state);
			}
		}
		env.filter_errno = number;
		break;
	case 'l':
		env.list_syscalls = true;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static volatile sig_atomic_t hang_on = 1;

void sig_int(int signo)
{
	hang_on = 0;
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	void (*print)(struct data_ext_t *, size_t);
	int (*compar)(const void *, const void *);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct data_ext_t vals[MAX_ENTRIES];
	struct syscount_bpf *obj;
	int seconds = 0;
	__u32 count;
	int err;
	int idx, cg_map_fd;
	int cgfd = -1;

	init_syscall_names();

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		goto free_names;

	if (env.list_syscalls) {
		list_syscalls();
		goto free_names;
	}

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	obj = syscount_bpf__open_opts(&open_opts);
	if (!obj) {
		warn("failed to open BPF object\n");
		err = 1;
		goto free_names;
	}

	if (env.pid)
		obj->rodata->filter_pid = env.pid;
	if (env.failures)
		obj->rodata->filter_failed = true;
	if (env.latency)
		obj->rodata->measure_latency = true;
	if (env.process)
		obj->rodata->count_by_process = true;
	if (env.filter_errno)
		obj->rodata->filter_errno = env.filter_errno;
	if (env.cg)
		obj->rodata->filter_cg = env.cg;

	err = syscount_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %s\n", strerror(-err));
		goto cleanup_obj;
	}

	/* update cgroup path fd to map */
	if (env.cg) {
		idx = 0;
		cg_map_fd = bpf_map__fd(obj->maps.cgroup_map);
		cgfd = open(env.cgroupspath, O_RDONLY);
		if (cgfd < 0) {
			fprintf(stderr, "Failed opening Cgroup path: %s", env.cgroupspath);
			goto cleanup_obj;
		}
		if (bpf_map_update_elem(cg_map_fd, &idx, &cgfd, BPF_ANY)) {
			fprintf(stderr, "Failed adding target cgroup to map");
			goto cleanup_obj;
		}
	}

	obj->links.sys_exit = bpf_program__attach(obj->progs.sys_exit);
	if (!obj->links.sys_exit) {
		err = -errno;
		warn("failed to attach sys_exit program: %s\n", strerror(-err));
		goto cleanup_obj;
	}
	if (env.latency) {
		obj->links.sys_enter = bpf_program__attach(obj->progs.sys_enter);
		if (!obj->links.sys_enter) {
			err = -errno;
			warn("failed to attach sys_enter programs: %s\n",
			     strerror(-err));
			goto cleanup_obj;
		}
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		goto cleanup_obj;
	}

	compar = env.latency ? compar_latency : compar_count;
	print = env.latency ? print_latency : print_count;

	printf("Tracing syscalls, printing top %d... Ctrl+C to quit.\n", env.top);
	while (hang_on) {
		sleep(env.interval ?: 1);
		if (env.duration) {
			seconds += env.interval ?: 1;
			if (seconds >= env.duration)
				hang_on = 0;
		}
		if (hang_on && !env.interval)
			continue;

		count = MAX_ENTRIES;
		if (!read_vals(bpf_map__fd(obj->maps.data), vals, &count))
			break;
		if (!count)
			continue;

		qsort(vals, count, sizeof(vals[0]), compar);
		print_timestamp();
		print(vals, count);
	}

cleanup_obj:
	syscount_bpf__destroy(obj);
free_names:
	free_syscall_names();
	cleanup_core_btf(&open_opts);
	if (cgfd > 0)
		close(cgfd);

	return err != 0;
}
