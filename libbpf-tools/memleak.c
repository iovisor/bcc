#include <argp.h>
#include <stdio.h>
#include <sys/types.h>

#include "memleak.skel.h"

#define TASK_COMM_LEN 16

static struct env {
	pid_t pid;
	char command[TASK_COMM_LEN];
	bool kernel_trace;
	bool trace_all;
	//bool show_allocs;
	//bool combined_only;
	int interval;
	int min_age_ns;
	int sample_every_n;
	int sample_rate;
	int num_prints;
	int top_stacks;
	size_t min_size;
	size_t max_size;
	char *object;

	int count;
	bool wa_missing_free;
	bool percpu;
} env;

const char *argp_program_version = "memleak 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";

const char argp_args_doc[] = "trace mem leaks\n"
"\n";

static const struct argp_option argp_options[] = {
	// name/longopt:str, key/shortopt:int, arg:str, flags:int, doc:str
	{"pid", 'p', "PID", 0, "Process ID to trace. if not specified, trace kernel allocs"},
	{"trace", 't', 0, 0, "print trace messages for each alloc/free call" },
	{"interval", 'i', "INTERVAL", 5, "interval in seconds to print outstanding allocs"},
	{"count", 'n', "COUNT", 0, "number of times to print the report before exiting"},
	{"show-allocs", 'a', 0, 0, "show allocation addresses and sizes as well as call stacks"},
	{"older", 'O', "AGE_MS", 0, "prune allocations younger than this age in milliseconds"},
	{"command", 'c', "COMMAND", 0, "execute and trace the specified command"},
	{"combined-only", 'C', 0, 0, "show combined allocation statistics only"},
	{"wa-missing-free", 'F', 0, 0, "Workaround to alleviate misjudgments when free is missing"},
	{"sample-rate", 'r', "SAMPLE_RATE", 0, "sample every N-th allocation to decrease the overhead"},
	{"top", 'T', "TOP_SIZE", 0, "display only this many top allocating stacks (by size)"},
	{"min-size", 'N', "MIN_SIZE", 0, "capture only allocations larger than this size"},
	{"max-size", 'X', "MAX_SIZE", 0, "capture only allocations smaller than this size"},
	{"obj", 'O', "OBJECT", 0, "attach to allocator functions in the specified object"}, // note - default="c" in original bcc
	{"ebpf", 'b', "EBPF", 0, ""}, // note - suppressed in original bcc
	{"percpu", 'x', 0, 0, "trace percpu allocations"},
	{},
};

static long argp_parse_long(int key, const char *arg, struct argp_state *state)
{
	errno = 0;
	const long temp = strtol(arg, NULL, 10);
	if (errno || temp <= 0) {
		fprintf(stderr, "error arg:%c %s\n", (char)key, arg);
		argp_usage(state);
	}

	return temp;
}

static error_t argp_parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'p':
		env.pid = argp_parse_long(key, arg, state);
		break;
	case 't':
		env.trace_all = true;
		break;
	case 'i':
		env.interval = argp_parse_long(key, arg, state);
		break;
	case 'n':
		env.num_prints = arg_parse_long(key, arg, state);
		break;
	case 'a':
		break;
	case 'O':
		env.min_age_ns = 1e6 * argp_parse_long(key, arg, state);
		break;
	case 'c':
		strncpy(env.command, arg, sizeof(env.command));
		break;
	case ARGP_KEY_ARG:
		fprintf(stderr, "Unrecognized positional argument: %s\n", arg);
		argp_usage(state);
	default:
		fprintf(stderr, "unknown arg:%c %s\n", (char)key, arg);
		return ARGP_ERR_UNKNOWN;
	}

	fprintf(stderr, "good arg:%c %s\n", (char)key, arg);

	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static struct ring_buffer *rb;

static int handle_event(void *ctx, void *data, size_t len)
{
	return 0;
}

int main(int argc, char *argv[])
{
	static const struct argp argp = {
		.options = argp_options,
		.parser = argp_parse_arg,
		.doc = argp_args_doc,
	};

	int err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.min_size

	if (strcmp(env.cmd, "\0") != 0)
		printf("running command: %s\n", env.cmd);
	else if (env.pid == -1)
		env.kernel_trace = true;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	struct memleak_bpf *skel = memleak_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open bpf object\n");
		return 1;
	}

	skel->rodata->pid = -1;
	skel->rodata->min_size = 0;
	skel->rodata->max_size = -1;
	skel->rodata->page_size = 0; // todo - default?
	skel->rodata->sample_every_n = 1;
	skel->rodata->trace_all = false;
	skel->rodata->kernel_trace = false;
	skel->rodata->wa_missing_free = false;

	if (memleak_bpf__load(skel)) {
		fprintf(stderr, "failed to load bpf object\n");
		goto cleanup;
	}

	if (memleak_bpf__attach(skel)) {
		fprintf(stderr, "failed to attach bpf program(s)\n");
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "failed to create ring buffer\n");
		goto cleanup;
	}

	const int timeout = 1000; // milliseconds

	printf("begin polling\n");

	for (;;) {
		err = ring_buffer__poll(rb, timeout);
		if (err < 0) {
			if (err == -EINTR) {
				err = 0;
				printf("polling interrupted\n");
			} else {
				fprintf(stderr, "failed to poll ring buffer: %d\n", err);
			}

			break;
		}

		printf("poll ok\n");
	}

	printf("end polling\n");

cleanup:
	memleak_bpf__destroy(skel);
}
