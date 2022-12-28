#include <argp.h>
#include <stdio.h>
#include <sys/types.h>

#include "memleak.skel.h"

static struct env {
	pid_t pid;
	char *command;
	bool kernel_trace;
	bool trace_all;
	//bool show_allocs;
	//bool combined_only;
	int interval;
	int min_age_ns;
	//int older;
	int sample_every_n;
	int sample_rate;
	int num_prints;
	int top_stacks;
	int min_size;
	int max_size;
	char *object;

	int count;
	bool wa_missing_free;
	bool percpu;
} env;

const char *argp_program_version = "memleak 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";

const char args_doc[] = "trace mem leaks\n"
"\n";

static const struct argp_option options[] = {
	// name:str, key:int, arg:str, flags:int, doc:str
	{"pid", 'p', "PID", 0, "Process ID to trace. if not specified, trace kernel allocs"},
	{"trace", 't', "TRACE", 0, "print trace messages for each alloc/free call" },
	{"interval", 'i', "INTERVAL", 5, "interval in seconds to print outstanding allocs"},
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long int temp;

	switch (key) {
	case 'p':
		errno = 0;
		temp = strtol(arg, NULL, 10);
		if (errno || temp <= 0) {
			fprintf(stderr, "error arg:%c %s\n", (char)key, arg);
			argp_usage(state);
		}

		env.pid = temp;

		break;
	case 't':
		env.trace_all = true;
		break;
	case 'i':
		errno = 0;
		temp = strtol(arg, NULL, 10);
		if (errno || temp <= 0) {
			fprintf(stderr, "error arg:%c %s\n", (char)key, arg);
			argp_usage(state);
		}

		env.interval = temp;

		break;
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
		.options = options,
		.parser = parse_arg,
		.doc = args_doc,
	};

	int err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	struct memleak_bpf *skel = memleak_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open bpf object\n");
		return 1;
	}

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
