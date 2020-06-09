// Based on execsnoop(8) from BCC by Brendan Gregg and others.
//
#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "execsnoop.h"
#include "execsnoop.skel.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES   64
#define NSEC_PRECISION (NSEC_PER_SEC / 1000)
#define MAX_ARGS_KEY 259

static struct env {
	bool time;
	bool timestamp;
	bool fails;
	uid_t uid;
	bool quote;
	const char *name;
	const char *line;
	bool print_uid;
	bool verbose;
	int max_args;
} env = {
	.max_args = DEFAULT_MAXARGS,
	.uid = INVALID_UID
};

static struct timespec start_time;

const char *argp_program_version = "execsnoop 0.1";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
"Trace open family syscalls\n"
"\n"
"USAGE: execsnoop [-h] [-T] [-t] [-x] [-u UID] [-q] [-n NAME] [-l LINE] [-U]\n"
"                 [--max-args MAX_ARGS]\n"
"\n"
"EXAMPLES:\n"
"   ./execsnoop           # trace all exec() syscalls\n"
"   ./execsnoop -x        # include failed exec()s\n"
"   ./execsnoop -T        # include time (HH:MM:SS)\n"
"   ./execsnoop -U        # include UID\n"
"   ./execsnoop -u 1000   # only trace UID 1000\n"
"   ./execsnoop -t        # include timestamps\n"
"   ./execsnoop -q        # add \"quotemarks\" around arguments\n"
"   ./execsnoop -n main   # only print command lines containing \"main\"\n"
"   ./execsnoop -l tpkg   # only print command where arguments contains \"tpkg\"";

static const struct argp_option opts[] = {
	{ "time", 'T', NULL, 0, "include time column on output (HH:MM:SS)"},
	{ "timestamp", 't', NULL, 0, "include timestamp on output"},
	{ "fails", 'x', NULL, 0, "include failed exec()s"},
	{ "uid", 'u', "UID", 0, "trace this UID only"},
	{ "quote", 'q', NULL, 0, "Add quotemarks (\") around arguments"},
	{ "name", 'n', "NAME", 0, "only print commands matching this name, any arg"},
	{ "line", 'l', "LINE", 0, "only print commands where arg contains this line"},
	{ "print-uid", 'U', NULL, 0, "print UID column"},
	{ "max-args", MAX_ARGS_KEY, "MAX_ARGS", 0,
		"maximum number of arguments parsed and displayed, defaults to 20"},
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long int uid, max_args;

	switch (key) {
	case 'h':
		argp_usage(state);
		break;
	case 'T':
		env.time = true;
		break;
	case 't':
		env.timestamp = true;
		break;
	case 'x':
		env.fails = true;
		break;
	case 'u':
		errno = 0;
		uid = strtol(arg, NULL, 10);
		if (errno || uid < 0 || uid >= INVALID_UID) {
			fprintf(stderr, "Invalid UID %s\n", arg);
			argp_usage(state);
		}
		env.uid = uid;
		break;
	case 'q':
		env.quote = true;
		break;
	case 'n':
		env.name = arg;
		break;
	case 'l':
		env.line = arg;
		break;
	case 'U':
		env.print_uid = true;
		break;
	case 'v':
		env.verbose = true;
		break;
	case MAX_ARGS_KEY:
		errno = 0;
		max_args = strtol(arg, NULL, 10);
		if (errno || max_args < 1 || max_args > TOTAL_MAX_ARGS) {
			fprintf(stderr, "Invalid MAX_ARGS %s, should be in [1, %d] range\n",
					arg, TOTAL_MAX_ARGS);

			argp_usage(state);
		}
		env.max_args = max_args;
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

static void time_since_start()
{
	long nsec, sec;
	static struct timespec cur_time;
	double time_diff;

	clock_gettime(CLOCK_MONOTONIC, &cur_time);
	nsec = cur_time.tv_nsec - start_time.tv_nsec;
	sec = cur_time.tv_sec - start_time.tv_sec;
	if (nsec < 0) {
		nsec += NSEC_PER_SEC;
		sec--;
	}
	time_diff = sec + (double)nsec / NSEC_PER_SEC;
	printf("%-8.3f", time_diff);
}

static void inline quoted_symbol(char c) {
	switch(c) {
		case '"':
			putchar('\\');
			putchar('"');
			break;
		case '\t':
			putchar('\\');
			putchar('t');
			break;
		case '\n':
			putchar('\\');
			putchar('n');
			break;
		default:
			putchar(c);
			break;
	}
}

static void print_args(const struct event *e, bool quote)
{
	int args_counter = 0;

	if (env.quote)
		putchar('"');

	for (int i = 0; i < e->args_size && args_counter < e->args_count; i++) {
		char c = e->args[i];
		if (env.quote) {
			if (c == '\0') {
				args_counter++;
				putchar('"');
				putchar(' ');
				if (args_counter < e->args_count) {
					putchar('"');
				}
			} else {
				quoted_symbol(c);
			}
		} else {
			if (c == '\0') {
				args_counter++;
				putchar(' ');
			} else {
				putchar(c);
			}
		}
	}
	if (e->args_count == env.max_args + 1) {
		fputs(" ...", stdout);
	}
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;
	time_t t;
	struct tm *tm;
	char ts[32];

	/* TODO: use pcre lib */
	if (env.name && strstr(e->comm, env.name) == NULL)
		return;

	/* TODO: use pcre lib */
	if (env.line && strstr(e->comm, env.line) == NULL)
		return;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	if (env.time) {
		printf("%-8s ", ts);
	}
	if (env.timestamp) {
		time_since_start();
	}

	if (env.print_uid)
		printf("%-6d", e->uid);

	printf("%-16s %-6d %-6d %3d ", e->comm, e->pid, e->ppid, e->retval);
	print_args(e, env.quote);
	putchar('\n');
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
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
	struct execsnoop_bpf *obj;
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

	obj = execsnoop_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	obj->rodata->ignore_failed = !env.fails;
	obj->rodata->targ_uid = env.uid;
	obj->rodata->max_args = env.max_args;

	err = execsnoop_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	clock_gettime(CLOCK_MONOTONIC, &start_time);
	err = execsnoop_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}
	/* print headers */
	if (env.time) {
		printf("%-9s", "TIME");
	}
	if (env.timestamp) {
		printf("%-8s ", "TIME(s)");
	}
	if (env.print_uid) {
		printf("%-6s ", "UID");
	}

	printf("%-16s %-6s %-6s %3s %s\n", "PCOMM", "PID", "PPID", "RET", "ARGS");

	/* setup event callbacks */
	pb_opts.sample_cb = handle_event;
	pb_opts.lost_cb = handle_lost_events;
	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES, &pb_opts);
	err = libbpf_get_error(pb);
	if (err) {
		pb = NULL;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	/* main: poll */
	while ((err = perf_buffer__poll(pb, 100)) >= 0)
		;
	printf("Error polling perf buffer: %d\n", err);

cleanup:
	perf_buffer__free(pb);
	execsnoop_bpf__destroy(obj);

	return err != 0;
}
